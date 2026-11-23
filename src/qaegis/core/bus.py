"""Strongly typed asynchronous Event Bus supporting pub/sub, request/reply, and ZeroMQ."""

from __future__ import annotations

import asyncio
import contextlib
import fnmatch
import hashlib
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import orjson
import zmq
import zmq.asyncio
from pydantic import BaseModel, Field, model_validator

from qaegis.core.config import BusConfig
from qaegis.core.telemetry import QAegisMetrics, get_logger

logger = get_logger(__name__)


def canonical_payload_hash(payload: dict[str, Any]) -> str:
    """Compute a deterministic SHA-256 hex digest over a JSON-serializable payload."""
    canonical_bytes = orjson.dumps(payload, option=orjson.OPT_SORT_KEYS)
    return hashlib.sha256(canonical_bytes).hexdigest()


class EventEnvelope(BaseModel):
    """Validated inter-module message contract transmitted across the Q-Aegis Event Bus."""

    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    topic: str = Field(min_length=1, max_length=256)
    source: str = Field(min_length=1, max_length=128)
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    correlation_id: str | None = None
    reply_to: str | None = None
    schema_version: str = "1.0"
    payload: dict[str, Any] = Field(default_factory=dict)
    payload_sha256: str = ""

    @model_validator(mode="after")
    def _ensure_payload_hash(self) -> EventEnvelope:
        expected = canonical_payload_hash(self.payload)
        if not self.payload_sha256:
            self.payload_sha256 = expected
        elif self.payload_sha256 != expected:
            raise ValueError(
                f"EventEnvelope payload integrity check failed for event {self.event_id}"
            )
        return self

    def to_wire_bytes(self) -> bytes:
        """Serialize the envelope deterministically for ZeroMQ or network transport."""
        return orjson.dumps(self.model_dump(mode="json"), option=orjson.OPT_SORT_KEYS)

    @classmethod
    def from_wire_bytes(cls, data: bytes) -> EventEnvelope:
        """Deserialize and validate an envelope from wire bytes."""
        return cls.model_validate(orjson.loads(data))


EventHandler = Callable[[EventEnvelope], Awaitable[None]]
RequestHandler = Callable[[EventEnvelope], Awaitable[dict[str, Any]]]


class BackpressureError(RuntimeError):
    """Raised when a subscriber queue is full and policy is set to `reject`."""


class Subscription:
    """Handle representing an active topic subscription on the EventBus."""

    def __init__(
        self,
        subscription_id: str,
        pattern: str,
        queue: asyncio.Queue[EventEnvelope],
        worker_task: asyncio.Task[None] | None,
    ) -> None:
        self.subscription_id = subscription_id
        self.pattern = pattern
        self.queue = queue
        self.worker_task = worker_task


class EventBus:
    """High-throughput typed async Event Bus with backpressure and optional ZeroMQ bridge."""

    def __init__(
        self,
        config: BusConfig | None = None,
        metrics: QAegisMetrics | None = None,
    ) -> None:
        self._config = config or BusConfig()
        self._metrics = metrics or QAegisMetrics()
        self._subscriptions: dict[str, Subscription] = {}
        self._request_handlers: dict[str, RequestHandler] = {}
        self._pending_replies: dict[str, asyncio.Future[EventEnvelope]] = {}
        self._running = False
        self._zmq_ctx: zmq.asyncio.Context | None = None
        self._zmq_pub: zmq.asyncio.Socket | None = None
        self._zmq_sub: zmq.asyncio.Socket | None = None
        self._zmq_reader_task: asyncio.Task[None] | None = None

    @property
    def is_running(self) -> bool:
        """Return whether the EventBus is started."""
        return self._running

    async def start(self) -> None:
        """Start the event bus and optional ZeroMQ bridge."""
        if self._running:
            return
        self._running = True
        if self._config.transport == "zmq":
            self._zmq_ctx = zmq.asyncio.Context()
            self._zmq_pub = self._zmq_ctx.socket(zmq.PUB)
            self._zmq_pub.bind(self._config.zmq_pub_endpoint)
            self._zmq_sub = self._zmq_ctx.socket(zmq.SUB)
            self._zmq_sub.connect(self._config.zmq_sub_endpoint)
            self._zmq_sub.setsockopt(zmq.SUBSCRIBE, b"")
            self._zmq_reader_task = asyncio.create_task(self._zmq_receive_loop())
        logger.info("event_bus_started", transport=self._config.transport)

    async def stop(self) -> None:
        """Gracefully stop all subscriber workers, pending RPCs, and ZeroMQ sockets."""
        if not self._running:
            return
        self._running = False

        if self._zmq_reader_task is not None:
            self._zmq_reader_task.cancel()
            await asyncio.gather(self._zmq_reader_task, return_exceptions=True)
            self._zmq_reader_task = None

        for sock in (self._zmq_pub, self._zmq_sub):
            if sock is not None:
                sock.close(linger=0)
        self._zmq_pub = None
        self._zmq_sub = None
        if self._zmq_ctx is not None:
            self._zmq_ctx.term()
            self._zmq_ctx = None

        for sub in list(self._subscriptions.values()):
            if sub.worker_task is not None:
                sub.worker_task.cancel()
                await asyncio.gather(sub.worker_task, return_exceptions=True)
        self._subscriptions.clear()

        for future in self._pending_replies.values():
            if not future.done():
                future.cancel()
        self._pending_replies.clear()
        logger.info("event_bus_stopped")

    def subscribe(
        self,
        topic_pattern: str,
        handler: EventHandler | None = None,
        max_queue_size: int | None = None,
    ) -> Subscription:
        """Subscribe to a topic or glob pattern (e.g., `sensor.*`).

        If `handler` is provided, a background coroutine dispatches incoming envelopes
        to `handler`. Otherwise callers can read directly from `subscription.queue`.
        """
        sub_id = uuid.uuid4().hex
        queue: asyncio.Queue[EventEnvelope] = asyncio.Queue(
            maxsize=max_queue_size or self._config.max_queue_size
        )

        worker: asyncio.Task[None] | None = None
        if handler is not None:
            worker = asyncio.create_task(self._dispatch_loop(sub_id, queue, handler))

        sub = Subscription(
            subscription_id=sub_id,
            pattern=topic_pattern,
            queue=queue,
            worker_task=worker,
        )
        self._subscriptions[sub_id] = sub
        return sub

    async def unsubscribe(self, subscription: Subscription) -> None:
        """Cancel and remove an existing subscription."""
        existing = self._subscriptions.pop(subscription.subscription_id, None)
        if existing is not None and existing.worker_task is not None:
            existing.worker_task.cancel()
            await asyncio.gather(existing.worker_task, return_exceptions=True)

    def register_responder(self, topic: str, handler: RequestHandler) -> None:
        """Register an async request/reply responder for an exact topic."""
        self._request_handlers[topic] = handler

    async def publish(
        self,
        topic: str,
        payload: dict[str, Any],
        source: str = "core",
        correlation_id: str | None = None,
        reply_to: str | None = None,
    ) -> EventEnvelope:
        """Construct, validate, and publish a typed event envelope."""
        envelope = EventEnvelope(
            topic=topic,
            source=source,
            payload=payload,
            correlation_id=correlation_id,
            reply_to=reply_to,
        )
        await self.publish_envelope(envelope)
        return envelope

    async def publish_envelope(self, envelope: EventEnvelope) -> None:
        """Deliver an already-constructed envelope to local subscribers and optional ZeroMQ."""
        self._metrics.bus_events_published.labels(
            topic=envelope.topic,
            source=envelope.source,
        ).inc()

        await self._deliver_local(envelope)

        if self._zmq_pub is not None:
            await self._zmq_pub.send_multipart(
                [envelope.topic.encode("utf-8"), envelope.to_wire_bytes()]
            )

    async def request(
        self,
        topic: str,
        payload: dict[str, Any],
        source: str = "core",
        timeout_s: float | None = None,
    ) -> EventEnvelope:
        """Execute a typed request/reply call against a registered responder."""
        correlation_id = uuid.uuid4().hex
        reply_topic = f"_reply.{correlation_id}"
        timeout = timeout_s if timeout_s is not None else self._config.request_timeout_s

        responder = self._request_handlers.get(topic)
        if responder is None:
            raise KeyError(f"No request responder registered for topic '{topic}'")

        req_envelope = EventEnvelope(
            topic=topic,
            source=source,
            payload=payload,
            correlation_id=correlation_id,
            reply_to=reply_topic,
        )
        self._metrics.bus_events_published.labels(topic=topic, source=source).inc()

        loop = asyncio.get_running_loop()
        reply_future: asyncio.Future[EventEnvelope] = loop.create_future()
        self._pending_replies[correlation_id] = reply_future

        async def _invoke_responder() -> None:
            try:
                response_payload = await responder(req_envelope)
                reply_env = EventEnvelope(
                    topic=reply_topic,
                    source=topic,
                    payload=response_payload,
                    correlation_id=correlation_id,
                )
                if not reply_future.done():
                    reply_future.set_result(reply_env)
            except Exception as exc:
                if not reply_future.done():
                    reply_future.set_exception(exc)

        task = asyncio.create_task(_invoke_responder())
        try:
            return await asyncio.wait_for(reply_future, timeout=timeout)
        finally:
            self._pending_replies.pop(correlation_id, None)
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    async def _deliver_local(self, envelope: EventEnvelope) -> None:
        for sub in list(self._subscriptions.values()):
            if not fnmatch.fnmatchcase(envelope.topic, sub.pattern):
                continue
            await self._enqueue_with_backpressure(sub, envelope)

    async def _enqueue_with_backpressure(
        self,
        sub: Subscription,
        envelope: EventEnvelope,
    ) -> None:
        policy = self._config.backpressure_policy
        if policy == "block":
            await sub.queue.put(envelope)
            return

        if sub.queue.full():
            if policy == "drop_oldest":
                with contextlib.suppress(asyncio.QueueEmpty):
                    sub.queue.get_nowait()
                    self._metrics.bus_events_dropped.labels(topic=envelope.topic).inc()
                sub.queue.put_nowait(envelope)
            else:  # reject
                self._metrics.bus_events_dropped.labels(topic=envelope.topic).inc()
                raise BackpressureError(
                    f"Subscriber queue full for pattern '{sub.pattern}' on topic '{envelope.topic}'"
                )
        else:
            sub.queue.put_nowait(envelope)

    async def _dispatch_loop(
        self,
        sub_id: str,
        queue: asyncio.Queue[EventEnvelope],
        handler: EventHandler,
    ) -> None:
        while True:
            envelope = await queue.get()
            try:
                await handler(envelope)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception(
                    "event_handler_error",
                    subscription_id=sub_id,
                    topic=envelope.topic,
                    event_id=envelope.event_id,
                )
            finally:
                queue.task_done()

    async def _zmq_receive_loop(self) -> None:
        if self._zmq_sub is None:
            return
        while self._running:
            try:
                frames = await self._zmq_sub.recv_multipart()
                if len(frames) != 2:
                    continue
                envelope = EventEnvelope.from_wire_bytes(frames[1])
                await self._deliver_local(envelope)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("zmq_receive_error")
