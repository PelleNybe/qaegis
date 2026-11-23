"""Asynchronous MQTT telemetry bridge using paho-mqtt v2 for IoT and Edge deployments."""

from __future__ import annotations

import asyncio
from typing import Any

import orjson
import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion
from pydantic import BaseModel, Field

from qaegis.core.bus import EventBus, EventEnvelope, Subscription
from qaegis.core.telemetry import get_logger

logger = get_logger(__name__)


class MqttBridgeConfig(BaseModel):
    """Configuration for connecting the Q-Aegis EventBus to an MQTT broker."""

    host: str = "127.0.0.1"
    port: int = Field(default=1883, ge=1, le=65535)
    client_id: str = "qaegis-mqtt-bridge"
    topic_prefix: str = "qaegis"
    keepalive_s: int = Field(default=60, ge=5)
    qos: int = Field(default=1, ge=0, le=2)
    use_tls: bool = False
    ca_certs: str | None = None
    username: str | None = None
    password: str | None = None
    outbound_bus_patterns: list[str] = Field(
        default_factory=lambda: ["reality_stamp.created", "chameleon.tier_changed"]
    )
    inbound_mqtt_topics: list[str] = Field(default_factory=lambda: ["qaegis/inbound/#"])


class AsyncMqttBridge:
    """Bidirectional MQTT <-> Q-Aegis EventBus adapter with Pydantic payload translation."""

    def __init__(self, bus: EventBus, config: MqttBridgeConfig | None = None) -> None:
        self._bus = bus
        self._config = config or MqttBridgeConfig()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._subscriptions: list[Subscription] = []
        self._connected = False
        self._client = mqtt.Client(
            callback_api_version=CallbackAPIVersion.VERSION2,
            client_id=self._config.client_id,
        )
        if self._config.username is not None:
            self._client.username_pw_set(self._config.username, self._config.password)
        if self._config.use_tls:
            self._client.tls_set(ca_certs=self._config.ca_certs)

        self._client.on_connect = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.on_message = self._on_message

    @property
    def is_connected(self) -> bool:
        return self._connected

    def map_bus_to_mqtt_topic(self, bus_topic: str) -> str:
        """Convert a dot-separated EventBus topic into a slash-separated MQTT topic."""
        return f"{self._config.topic_prefix}/{bus_topic.replace('.', '/')}"

    def map_mqtt_to_bus_topic(self, mqtt_topic: str) -> str:
        """Convert an inbound MQTT topic into a normalized Q-Aegis EventBus topic."""
        prefix = f"{self._config.topic_prefix}/"
        trimmed = mqtt_topic[len(prefix) :] if mqtt_topic.startswith(prefix) else mqtt_topic
        return trimmed.strip("/").replace("/", ".") or "mqtt.message"

    def encode_envelope_for_mqtt(self, envelope: EventEnvelope) -> tuple[str, bytes]:
        """Serialize a Q-Aegis EventEnvelope into an (mqtt_topic, payload_bytes) pair."""
        return (self.map_bus_to_mqtt_topic(envelope.topic), envelope.to_wire_bytes())

    async def ingest_mqtt_payload(self, mqtt_topic: str, raw_payload: bytes) -> EventEnvelope:
        """Decode an MQTT payload (JSON object or raw text) and publish onto the EventBus."""
        bus_topic = self.map_mqtt_to_bus_topic(mqtt_topic)
        try:
            decoded: Any = orjson.loads(raw_payload)
            payload: dict[str, Any] = decoded if isinstance(decoded, dict) else {"value": decoded}
        except orjson.JSONDecodeError:
            payload = {"raw_text": raw_payload.decode("utf-8", errors="replace")}
        return await self._bus.publish(topic=bus_topic, source="adapters.mqtt", payload=payload)

    async def start(self) -> None:
        """Connect to the configured MQTT broker and bridge EventBus topics."""
        self._loop = asyncio.get_running_loop()
        for pattern in self._config.outbound_bus_patterns:
            sub = self._bus.subscribe(pattern, handler=self._forward_bus_event)
            self._subscriptions.append(sub)
        self._client.connect_async(
            self._config.host,
            port=self._config.port,
            keepalive=self._config.keepalive_s,
        )
        self._client.loop_start()
        logger.info(
            "mqtt_bridge_started",
            host=self._config.host,
            port=self._config.port,
        )

    async def stop(self) -> None:
        """Disconnect cleanly from the MQTT broker and unsubscribe EventBus handlers."""
        for sub in self._subscriptions:
            await self._bus.unsubscribe(sub)
        self._subscriptions.clear()
        self._client.loop_stop()
        self._client.disconnect()
        self._connected = False
        logger.info("mqtt_bridge_stopped")

    async def _forward_bus_event(self, envelope: EventEnvelope) -> None:
        topic, data = self.encode_envelope_for_mqtt(envelope)
        if self._connected:
            self._client.publish(topic, payload=data, qos=self._config.qos)

    def _on_connect(
        self,
        client: mqtt.Client,
        userdata: Any,
        flags: Any,
        reason_code: Any,
        properties: Any,
    ) -> None:
        del userdata, flags, properties
        self._connected = not getattr(reason_code, "is_failure", False)
        if self._connected:
            for mqtt_topic in self._config.inbound_mqtt_topics:
                client.subscribe(mqtt_topic, qos=self._config.qos)
            logger.info("mqtt_bridge_connected", host=self._config.host)

    def _on_disconnect(
        self,
        client: mqtt.Client,
        userdata: Any,
        disconnect_flags: Any,
        reason_code: Any,
        properties: Any,
    ) -> None:
        del client, userdata, disconnect_flags, reason_code, properties
        self._connected = False

    def _on_message(
        self,
        client: mqtt.Client,
        userdata: Any,
        msg: mqtt.MQTTMessage,
    ) -> None:
        del client, userdata
        if self._loop is not None and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(
                self.ingest_mqtt_payload(msg.topic, bytes(msg.payload)),
                self._loop,
            )
