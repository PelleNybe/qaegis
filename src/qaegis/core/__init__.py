"""Q-Aegis microkernel core primitives."""

from __future__ import annotations

from qaegis.core.bus import (
    BackpressureError,
    CurveKeyPair,
    CurvePeerAllowlistProvider,
    EventBus,
    EventEnvelope,
    Subscription,
    generate_curve_keypair,
    load_or_create_curve_keypair,
)
from qaegis.core.config import QAegisConfig, load_config
from qaegis.core.hardware_seal import (
    HardwareSealer,
    HardwareSealerUnavailableError,
    PKCS11Sealer,
    SealedBlob,
    TPM2Sealer,
    detect_pkcs11_library,
)
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
    "CurveKeyPair",
    "CurvePeerAllowlistProvider",
    "DeviceIdentity",
    "DreamProblemRecord",
    "EventBus",
    "EventEnvelope",
    "HardwareSealer",
    "HardwareSealerUnavailableError",
    "IdentityManager",
    "LifecycleManager",
    "ModeTransitionRecord",
    "OperatingMode",
    "PKCS11Sealer",
    "PolicySnapshotRecord",
    "PublicIdentityBundle",
    "QAegisConfig",
    "QAegisMetrics",
    "SealedBlob",
    "StorageEngine",
    "Subscription",
    "TPM2Sealer",
    "compute_key_fingerprint",
    "configure_logging",
    "constant_time_equal",
    "detect_pkcs11_library",
    "generate_curve_keypair",
    "get_logger",
    "load_config",
    "load_or_create_curve_keypair",
    "resolve_oqs_kem_algorithm",
    "resolve_oqs_sig_algorithm",
]
