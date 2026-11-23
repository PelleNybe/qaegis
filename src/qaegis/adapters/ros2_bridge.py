"""Optional ROS 2 / DDS bridge with graceful runtime detection when rclpy is absent."""

from __future__ import annotations

import asyncio
import importlib.util
from typing import Any

import orjson
from pydantic import BaseModel

from qaegis.core.bus import EventBus, EventEnvelope, Subscription
from qaegis.core.telemetry import get_logger

logger = get_logger(__name__)


def is_ros2_available() -> bool:
    """Return True if ROS 2 (`rclpy` and `std_msgs`) is installed in the current environment."""
    return (
        importlib.util.find_spec("rclpy") is not None
        and importlib.util.find_spec("std_msgs") is not None
    )


class Ros2UnavailableError(RuntimeError):
    """Raised when starting a live ROS 2 node in an environment without `rclpy`."""


class Ros2BridgeConfig(BaseModel):
    """Configuration for the ROS 2 / DDS Q-Aegis adapter."""

    node_name: str = "qaegis_ros2_bridge"
    ros_namespace: str = "/qaegis"
    inbound_ros_topic: str = "/qaegis/perception_in"
    outbound_ros_topic: str = "/qaegis/reality_stamp_out"
    outbound_bus_pattern: str = "reality_stamp.created"
    qos_depth: int = 10


class Ros2Bridge:
    """Bridges ROS 2 DDS topics (`std_msgs/String` JSON envelopes) with the Q-Aegis EventBus."""

    def __init__(self, bus: EventBus, config: Ros2BridgeConfig | None = None) -> None:
        self._bus = bus
        self._config = config or Ros2BridgeConfig()
        self._available = is_ros2_available()
        self._node: Any = None
        self._publisher: Any = None
        self._spin_task: asyncio.Task[None] | None = None
        self._bus_sub: Subscription | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    @property
    def is_available(self) -> bool:
        return self._available

    def status(self) -> dict[str, Any]:
        """Return runtime status of the ROS 2 bridge without requiring rclpy."""
        return {
            "ros2_available": self._available,
            "running": self._node is not None,
            "node_name": self._config.node_name,
            "inbound_ros_topic": self._config.inbound_ros_topic,
            "outbound_ros_topic": self._config.outbound_ros_topic,
        }

    async def start(self) -> None:
        """Initialize the rclpy node and start bridging topics (requires ROS 2 installed)."""
        if not self._available:
            raise Ros2UnavailableError(
                "ROS 2 Python bindings (`rclpy` and `std_msgs`) are not installed. "
                "Source your ROS 2 environment (e.g. /opt/ros/jazzy/setup.bash) "
                "to enable Ros2Bridge."
            )
        import rclpy
        from std_msgs.msg import String as RosString

        self._loop = asyncio.get_running_loop()
        if not rclpy.ok():
            rclpy.init()
        self._node = rclpy.create_node(
            self._config.node_name,
            namespace=self._config.ros_namespace,
        )
        self._publisher = self._node.create_publisher(
            RosString,
            self._config.outbound_ros_topic,
            self._config.qos_depth,
        )
        self._node.create_subscription(
            RosString,
            self._config.inbound_ros_topic,
            self._on_ros_message,
            self._config.qos_depth,
        )
        self._bus_sub = self._bus.subscribe(
            self._config.outbound_bus_pattern,
            handler=self._forward_to_ros,
        )
        self._spin_task = asyncio.create_task(self._spin_loop())
        logger.info("ros2_bridge_started", node_name=self._config.node_name)

    async def stop(self) -> None:
        """Shut down the ROS 2 node and EventBus subscription cleanly."""
        if self._spin_task is not None:
            self._spin_task.cancel()
            await asyncio.gather(self._spin_task, return_exceptions=True)
            self._spin_task = None
        if self._bus_sub is not None:
            await self._bus.unsubscribe(self._bus_sub)
            self._bus_sub = None
        if self._node is not None:
            self._node.destroy_node()
            self._node = None
            self._publisher = None
            logger.info("ros2_bridge_stopped")

    async def _spin_loop(self) -> None:
        import rclpy

        while self._node is not None:
            rclpy.spin_once(self._node, timeout_sec=0.05)
            await asyncio.sleep(0.01)

    async def _forward_to_ros(self, envelope: EventEnvelope) -> None:
        if self._publisher is None:
            return
        from std_msgs.msg import String as RosString

        msg = RosString()
        msg.data = envelope.to_wire_bytes().decode("utf-8")
        self._publisher.publish(msg)

    def _on_ros_message(self, msg: Any) -> None:
        if self._loop is None or not self._loop.is_running():
            return
        raw = str(getattr(msg, "data", ""))
        try:
            decoded: Any = orjson.loads(raw)
            payload: dict[str, Any] = decoded if isinstance(decoded, dict) else {"data": decoded}
        except orjson.JSONDecodeError:
            payload = {"raw_text": raw}
        asyncio.run_coroutine_threadsafe(
            self._bus.publish("perception.ros2", payload=payload, source="adapters.ros2"),
            self._loop,
        )
