"""Adaptive PQC Firewall & Policy Enforcer Service integrated with the Q-Aegis EventBus."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from qaegis.core.bus import EventBus, EventEnvelope
from qaegis.core.config import ChameleonConfig
from qaegis.core.identity import DeviceIdentity, PublicIdentityBundle
from qaegis.core.telemetry import QAegisMetrics, get_logger
from qaegis.modules.chameleon_fw.crypto_agility import CryptoAgilityEngine, EncryptedEnvelope
from qaegis.modules.chameleon_fw.detector import (
    AdaptiveThreatDetector,
    ThreatAssessment,
    ThreatTier,
)
from qaegis.modules.chameleon_fw.features import SensitivityTag, TrafficObservation

logger = get_logger(__name__)


class ProtectedPacket(BaseModel):
    """Combined output of Quantum Chameleon assessment and adaptive encryption."""

    assessment: ThreatAssessment
    envelope: EncryptedEnvelope


class ChameleonFirewallService:
    """Real-time AI-driven adaptive firewall upgrading transport crypto based on live risk."""

    def __init__(
        self,
        bus: EventBus,
        identity: DeviceIdentity,
        config: ChameleonConfig | None = None,
        metrics: QAegisMetrics | None = None,
        onnx_model_path: Path | None = None,
    ) -> None:
        self._bus = bus
        self._identity = identity
        self._config = config or ChameleonConfig()
        self._metrics = metrics or QAegisMetrics()
        self._detector = AdaptiveThreatDetector(
            config=self._config,
            onnx_model_path=onnx_model_path,
        )
        self._crypto = CryptoAgilityEngine(
            identity=identity,
            config=self._config,
            metrics=self._metrics,
        )
        self._last_tier: ThreatTier = ThreatTier.STANDARD

    @property
    def detector(self) -> AdaptiveThreatDetector:
        return self._detector

    @property
    def crypto_engine(self) -> CryptoAgilityEngine:
        return self._crypto

    @property
    def current_tier(self) -> ThreatTier:
        return self._last_tier

    async def start(self) -> None:
        """Register Chameleon RPC responders on the EventBus."""
        self._bus.register_responder("chameleon.protect", self._handle_protect_rpc)
        self._bus.register_responder("chameleon.unprotect", self._handle_unprotect_rpc)
        logger.info("chameleon_firewall_started", node_id=self._identity.node_id)

    async def protect(
        self,
        observation: TrafficObservation,
        recipient: PublicIdentityBundle,
        associated_data: bytes = b"",
        minimum_tier: ThreatTier | None = None,
    ) -> ProtectedPacket:
        """Classify risk, upgrade security tier if required, and encrypt the payload."""
        assessment = self._detector.assess(observation)
        chosen_tier = assessment.tier
        if minimum_tier is not None:
            order = {
                ThreatTier.STANDARD: 0,
                ThreatTier.ELEVATED: 1,
                ThreatTier.QUANTUM_CRITICAL: 2,
            }
            if order[minimum_tier] > order[chosen_tier]:
                chosen_tier = minimum_tier
                assessment = assessment.model_copy(
                    update={
                        "tier": chosen_tier,
                        "reasons": [*assessment.reasons, f"policy_floor={minimum_tier.value}"],
                    }
                )

        self._metrics.chameleon_tier_transitions.labels(tier=chosen_tier.value).inc()
        if chosen_tier != self._last_tier:
            prev = self._last_tier
            self._last_tier = chosen_tier
            await self._bus.publish(
                topic="chameleon.tier_changed",
                source="modules.chameleon_fw",
                payload={
                    "previous_tier": prev.value,
                    "new_tier": chosen_tier.value,
                    "risk_score": assessment.risk_score,
                    "reasons": assessment.reasons,
                },
            )

        envelope = self._crypto.encrypt(
            plaintext=observation.payload_bytes,
            recipient=recipient,
            tier=chosen_tier,
            associated_data=associated_data,
        )
        return ProtectedPacket(assessment=assessment, envelope=envelope)

    def unprotect(
        self,
        envelope: EncryptedEnvelope,
        expected_sender: PublicIdentityBundle | None = None,
    ) -> bytes:
        """Authenticate and decrypt a received Quantum Chameleon envelope."""
        return self._crypto.decrypt(envelope=envelope, expected_sender=expected_sender)

    async def _handle_protect_rpc(self, envelope: EventEnvelope) -> dict[str, Any]:
        p = envelope.payload
        raw_bytes = base64.b64decode(str(p["payload_b64"]))
        sensitivity: SensitivityTag = p.get("sensitivity", "internal")
        obs = TrafficObservation(
            source=str(p.get("source", envelope.source)),
            destination=str(p.get("destination", "peer")),
            topic=str(p.get("topic", "telemetry")),
            protocol=str(p.get("protocol", "lan")),
            sensitivity=sensitivity,
            payload_bytes=raw_bytes,
            long_term_retention_years=float(p.get("long_term_retention_years", 1.0)),
        )
        recipient = PublicIdentityBundle.model_validate(p["recipient"])
        packet = await self.protect(obs, recipient)
        return packet.model_dump(mode="json")

    async def _handle_unprotect_rpc(self, envelope: EventEnvelope) -> dict[str, Any]:
        p = envelope.payload
        enc = EncryptedEnvelope.model_validate(p["envelope"])
        sender = (
            PublicIdentityBundle.model_validate(p["expected_sender"])
            if p.get("expected_sender") is not None
            else None
        )
        plaintext = self.unprotect(enc, expected_sender=sender)
        return {
            "plaintext_b64": base64.b64encode(plaintext).decode("ascii"),
            "tier": enc.tier.value,
            "cipher_suite": enc.cipher_suite,
        }
