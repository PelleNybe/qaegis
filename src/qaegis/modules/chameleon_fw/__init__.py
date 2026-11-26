"""Module 2: Quantum Chameleon AI-Driven Adaptive PQC Firewall."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from qaegis.modules.chameleon_fw.crypto_agility import (
    CIPHER_SUITES,
    CryptoAgilityEngine,
    EncryptedEnvelope,
)
from qaegis.modules.chameleon_fw.features import (
    SensitivityTag,
    ThreatTier,
    TrafficFeatureExtractor,
    TrafficObservation,
    printable_ascii_ratio,
    shannon_entropy_bytes,
)

if TYPE_CHECKING:
    from qaegis.modules.chameleon_fw.detector import AdaptiveThreatDetector, ThreatAssessment
    from qaegis.modules.chameleon_fw.service import ChameleonFirewallService, ProtectedPacket

__all__ = [
    "CIPHER_SUITES",
    "AdaptiveThreatDetector",
    "ChameleonFirewallService",
    "CryptoAgilityEngine",
    "EncryptedEnvelope",
    "ProtectedPacket",
    "SensitivityTag",
    "ThreatAssessment",
    "ThreatTier",
    "TrafficFeatureExtractor",
    "TrafficObservation",
    "printable_ascii_ratio",
    "shannon_entropy_bytes",
]


def __getattr__(name: str) -> Any:
    if name in ("AdaptiveThreatDetector", "ThreatAssessment"):
        from qaegis.modules.chameleon_fw import detector

        return getattr(detector, name)
    if name in ("ChameleonFirewallService", "ProtectedPacket"):
        from qaegis.modules.chameleon_fw import service

        return getattr(service, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
