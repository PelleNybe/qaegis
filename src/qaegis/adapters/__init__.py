"""Edge telemetry adapters for MQTT (IoT) and ROS 2 (autonomous robotics)."""

from __future__ import annotations

from qaegis.adapters.mqtt_bridge import AsyncMqttBridge, MqttBridgeConfig
from qaegis.adapters.ros2_bridge import (
    Ros2Bridge,
    Ros2BridgeConfig,
    Ros2UnavailableError,
    is_ros2_available,
)

__all__ = [
    "AsyncMqttBridge",
    "MqttBridgeConfig",
    "Ros2Bridge",
    "Ros2BridgeConfig",
    "Ros2UnavailableError",
    "is_ros2_available",
]
