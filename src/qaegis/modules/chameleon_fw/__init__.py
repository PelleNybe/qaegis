"""Module 2: Quantum Chameleon AI-Driven Adaptive PQC Firewall."""

from __future__ import annotations

from qaegis.modules.chameleon_fw.crypto_agility import (
    CIPHER_SUITES,
    CryptoAgilityEngine,
    EncryptedEnvelope,
)
from qaegis.modules.chameleon_fw.detector import (
    AdaptiveThreatDetector,
    ThreatAssessment,
    ThreatTier,
)
from qaegis.modules.chameleon_fw.features import (
    SensitivityTag,
    TrafficFeatureExtractor,
    TrafficObservation,
    printable_ascii_ratio,
    shannon_entropy_bytes,
)
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
