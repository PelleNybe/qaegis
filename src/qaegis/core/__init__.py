"""Q-Aegis microkernel core primitives."""

from __future__ import annotations

from qaegis.core.bus import BackpressureError, EventBus, EventEnvelope, Subscription
from qaegis.core.config import QAegisConfig, load_config
from qaegis.core.identity import (
    CBOMRecord,
    DeviceIdentity,
    IdentityManager,
    PublicIdentityBundle,
    compute_key_fingerprint,
    constant_time_equal,
    resolve_oqs_kem_algorithm,
    resolve_oqs_sig_algorithm,
)
from qaegis.core.lifecycle import LifecycleManager, ModeTransitionRecord, OperatingMode
from qaegis.core.storage import (
    AuditRecord,
    DreamProblemRecord,
    PolicySnapshotRecord,
    StorageEngine,
)
from qaegis.core.telemetry import QAegisMetrics, configure_logging, get_logger

__all__ = [
    "AuditRecord",
    "BackpressureError",
    "CBOMRecord",
    "DeviceIdentity",
    "DreamProblemRecord",
    "EventBus",
    "EventEnvelope",
    "IdentityManager",
    "LifecycleManager",
    "ModeTransitionRecord",
    "OperatingMode",
    "PolicySnapshotRecord",
    "PublicIdentityBundle",
    "QAegisConfig",
    "QAegisMetrics",
    "StorageEngine",
    "Subscription",
    "compute_key_fingerprint",
    "configure_logging",
    "constant_time_equal",
    "get_logger",
    "load_config",
    "resolve_oqs_kem_algorithm",
    "resolve_oqs_sig_algorithm",
]
