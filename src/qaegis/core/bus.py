"""Strongly typed async Event Bus supporting pub/sub, request/reply, and CurveZMQ auth."""

from __future__ import annotations

import asyncio
import contextlib
import fnmatch
import hashlib
import os
import tempfile
import uuid
from collections import deque
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import orjson
import zmq
import zmq.asyncio
from pydantic import BaseModel, Field, model_validator
from zmq.auth.asyncio import AsyncioAuthenticator

from qaegis.core.config import BusConfig
from qaegis.core.identity import constant_time_equal
from qaegis.core.telemetry import QAegisMetrics, get_logger

logger = get_logger(__name__)


class CurveKeyPair(BaseModel):
    """Z85-encoded Curve25519 keypair for ZeroMQ CurveZMQ mutual authentication."""

    public_key: str = Field(min_length=40, max_length=40)
    secret_key: str = Field(min_length=40, max_length=40)


def generate_curve_keypair() -> CurveKeyPair:
    """Generate a fresh Z85-encoded Curve25519 keypair via libzmq."""
    pub_bytes, sec_bytes = zmq.curve_keypair()
    return CurveKeyPair(
        public_key=pub_bytes.decode("ascii"),
        secret_key=sec_bytes.decode("ascii"),
    )


def load_or_create_curve_keypair(key_dir: Path, name: str = "node") -> CurveKeyPair:
    """Load or atomically create a Curve25519 keypair with strict 0o600 secret permissions."""
    key_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(key_dir, 0o700)
    sec_path = key_dir / f"{name}.curve.secret.json"
    pub_path = key_dir / f"{name}.curve.public"

    if sec_path.is_file():
        mode = sec_path.stat().st_mode & 0o777
        if mode & 0o077:
            raise PermissionError(f"Insecure permissions {oct(mode)} on {sec_path}; expected 0o600")
        return CurveKeyPair.model_validate(orjson.loads(sec_path.read_bytes()))

    pair = generate_curve_keypair()
    fd, tmp_name = tempfile.mkstemp(dir=key_dir, prefix=".qaegis-curve-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(orjson.dumps(pair.model_dump(mode="json"), option=orjson.OPT_SORT_KEYS))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, sec_path)
        os.chmod(sec_path, 0o600)
    except Exception:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise

    pub_path.write_text(pair.public_key, encoding="ascii")
    os.chmod(pub_path, 0o644)
    return pair


class CurvePeerAllowlistProvider:
    """ZMQ ZAP credentials provider enforcing Curve25519 public-key allowlist with metrics."""

    def __init__(
        self,
        allowed_public_keys: set[bytes],
        metrics: QAegisMetrics,
    ) -> None:
        self._allowed = set(allowed_public_keys)
        self._metrics = metrics
        self.accepted_count = 0
        self.rejected_count = 0

    def allow_key(self, z85_public_key: str) -> None:
        """Dynamically add a Z85 Curve25519 public key to the allowlist."""
        self._allowed.add(z85_public_key.encode("ascii"))

    def callback(self, domain: str, key: bytes) -> bool:
        """Validate a connecting client's Z85 Curve25519 public key during ZAP handshake."""
        for allowed in self._allowed:
            if constant_time_equal(allowed, key):
                self.accepted_count += 1
                return True
        self.rejected_count += 1
        self._metrics.bus_auth_rejections.labels(reason="unauthorized_curve_key").inc()
        logger.warning(
            "curvezmq_peer_rejected",
            domain=domain,
            key_prefix=key.decode("ascii", errors="replace")[:10],
        )
        return False


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
    """High-throughput typed async Event Bus with backpressure and optional CurveZMQ bridge."""

    def __init__(
        self,
        config: BusConfig | None = None,
        metrics: QAegisMetrics | None = None,
        curve_keypair: CurveKeyPair | None = None,
    ) -> None:
        self._config = config or BusConfig()
        self._metrics = metrics or QAegisMetrics()
        self._curve_keypair = curve_keypair
        self._subscriptions: dict[str, Subscription] = {}
        self._request_handlers: dict[str, RequestHandler] = {}
        self._pending_replies: dict[str, asyncio.Future[EventEnvelope]] = {}
        self._running = False
        self._zmq_ctx: zmq.asyncio.Context | None = None
        self._zmq_auth: AsyncioAuthenticator | None = None
        self._auth_provider: CurvePeerAllowlistProvider | None = None
        self._zmq_pub: zmq.asyncio.Socket | None = None
        self._zmq_sub: zmq.asyncio.Socket | None = None
        self._zmq_reader_task: asyncio.Task[None] | None = None
        self._bound_pub_endpoint: str | None = None
        self._recent_event_order: deque[str] = deque()
        self._recent_event_ids: set[str] = set()
        self._dedup_capacity = 4096

    async def __aenter__(self) -> EventBus:
        await self.start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.stop()

    def _record_event_id(self, event_id: str) -> bool:
        """Record `event_id` and return False if already seen recently (loopback dedup)."""
        if event_id in self._recent_event_ids:
            return False
        self._recent_event_ids.add(event_id)
        self._recent_event_order.append(event_id)
        while len(self._recent_event_order) > self._dedup_capacity:
            evicted = self._recent_event_order.popleft()
            self._recent_event_ids.discard(evicted)
        return True

    @property
    def is_running(self) -> bool:
        """Return whether the EventBus is started."""
        return self._running

    @property
    def curve_public_key(self) -> str | None:
        """Return this node's Curve25519 Z85 public key if CurveZMQ is active."""
        return self._curve_keypair.public_key if self._curve_keypair is not None else None

    @property
    def bound_pub_endpoint(self) -> str | None:
        """Return the resolved ZeroMQ PUB bind endpoint (useful when binding ephemeral port 0)."""
        return self._bound_pub_endpoint

    @property
    def auth_provider(self) -> CurvePeerAllowlistProvider | None:
        """Return the active CurveZMQ ZAP allowlist provider, if CurveZMQ server is running."""
        return self._auth_provider

    async def start(self) -> None:
        """Start the event bus and optional ZeroMQ / CurveZMQ authenticated bridge."""
        if self._running:
            return
        self._running = True
        if self._config.transport == "zmq":
            self._zmq_ctx = zmq.asyncio.Context()
            use_curve = self._config.zmq_security == "curve"
            if use_curve:
                if self._curve_keypair is None:
                    if self._config.zmq_curve_key_dir is not None:
                        self._curve_keypair = load_or_create_curve_keypair(
                            self._config.zmq_curve_key_dir
                        )
                    else:
                        self._curve_keypair = generate_curve_keypair()

                if self._config.zmq_bind_pub:
                    self._zmq_auth = AsyncioAuthenticator(self._zmq_ctx)
                    self._zmq_auth.start()
                    allowed_keys = {k.encode("ascii") for k in self._config.zmq_allowed_peer_keys}
                    # Allow own key if connecting local SUB to local PUB
                    if self._config.zmq_connect_sub:
                        allowed_keys.add(self._curve_keypair.public_key.encode("ascii"))
                    self._auth_provider = CurvePeerAllowlistProvider(
                        allowed_public_keys=allowed_keys,
                        metrics=self._metrics,
                    )
                    self._zmq_auth.configure_curve_callback(
                        domain="*",
                        credentials_provider=self._auth_provider,
                    )

            if self._config.zmq_bind_pub:
                self._zmq_pub = self._zmq_ctx.socket(zmq.PUB)
                if use_curve and self._curve_keypair is not None:
                    self._zmq_pub.setsockopt(zmq.CURVE_SERVER, 1)
                    self._zmq_pub.setsockopt(
                        zmq.CURVE_SECRETKEY, self._curve_keypair.secret_key.encode("ascii")
                    )
                    self._zmq_pub.setsockopt(
                        zmq.CURVE_PUBLICKEY, self._curve_keypair.public_key.encode("ascii")
                    )
                self._zmq_pub.bind(self._config.zmq_pub_endpoint)
                raw_ep = self._zmq_pub.getsockopt(zmq.LAST_ENDPOINT)
                self._bound_pub_endpoint = (
                    raw_ep.decode("utf-8") if isinstance(raw_ep, bytes) else str(raw_ep)
                )

            if self._config.zmq_connect_sub:
                self._zmq_sub = self._zmq_ctx.socket(zmq.SUB)
                if use_curve and self._curve_keypair is not None:
                    server_pub = (
                        self._config.zmq_server_public_key or self._curve_keypair.public_key
                    )
                    self._zmq_sub.setsockopt(zmq.CURVE_SERVERKEY, server_pub.encode("ascii"))
                    self._zmq_sub.setsockopt(
                        zmq.CURVE_PUBLICKEY, self._curve_keypair.public_key.encode("ascii")
                    )
                    self._zmq_sub.setsockopt(
                        zmq.CURVE_SECRETKEY, self._curve_keypair.secret_key.encode("ascii")
                    )
                sub_target = (
                    self._bound_pub_endpoint
                    if (
                        self._bound_pub_endpoint is not None
                        and self._config.zmq_sub_endpoint == self._config.zmq_pub_endpoint
                    )
                    else self._config.zmq_sub_endpoint
                )
                self._zmq_sub.connect(sub_target)
                self._zmq_sub.setsockopt(zmq.SUBSCRIBE, b"")
                self._zmq_reader_task = asyncio.create_task(self._zmq_receive_loop())

        logger.info(
            "event_bus_started",
            transport=self._config.transport,
            zmq_security=self._config.zmq_security,
        )

    async def stop(self) -> None:
        """Gracefully stop all subscriber workers, pending RPCs, CurveZMQ auth, and sockets."""
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
        self._bound_pub_endpoint = None

        if self._zmq_auth is not None:
            self._zmq_auth.stop()
            self._zmq_auth = None
        self._auth_provider = None

        if self._zmq_ctx is not None:
            self._zmq_ctx.destroy(linger=0)
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
        """Subscribe to a topic or glob pattern (e.g., `sensor.*`)."""
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

        self._record_event_id(envelope.event_id)
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
                if not self._record_event_id(envelope.event_id):
                    continue
                await self._deliver_local(envelope)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("zmq_receive_error")
