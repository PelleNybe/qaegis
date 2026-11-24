"""Event-bus integrated Proof-of-Reality service (QRNG + PQC Signer + Persistent Merkle Log)."""

from __future__ import annotations

import asyncio
from typing import Any

from qaegis.core.bus import EventBus, EventEnvelope, Subscription
from qaegis.core.config import RealityStampConfig
from qaegis.core.identity import DeviceIdentity, TrustKeyring
from qaegis.core.storage import StorageEngine
from qaegis.core.telemetry import QAegisMetrics, get_logger
from qaegis.modules.reality_stamp.merkle import MerkleTree
from qaegis.modules.reality_stamp.qrng import MultiSourceQrng
from qaegis.modules.reality_stamp.signer import (
    RealityPayload,
    RealitySigner,
    RealityStamp,
    StampVerificationResult,
    compute_stamp_leaf_hash,
    verify_reality_stamp,
)

logger = get_logger(__name__)


class RealityStampService:
    """Signs Edge-AI perception outputs with QRNG nonces, PQC signatures, and Merkle anchoring."""

    def __init__(
        self,
        bus: EventBus,
        identity: DeviceIdentity,
        storage: StorageEngine,
        config: RealityStampConfig | None = None,
        qrng: MultiSourceQrng | None = None,
        metrics: QAegisMetrics | None = None,
    ) -> None:
        self._bus = bus
        self._identity = identity
        self._storage = storage
        self._config = config or RealityStampConfig()
        self._metrics = metrics or QAegisMetrics()
        self._qrng = qrng or MultiSourceQrng(config=self._config, metrics=self._metrics)
        self._signer = RealitySigner(identity=identity, metrics=self._metrics)
        self._merkle = MerkleTree()
        self._merkle_lock = asyncio.Lock()
        self._sub: Subscription | None = None

    @property
    def merkle_root(self) -> str:
        """Return the current SHA-256 Merkle root hex digest."""
        return self._merkle.root_hex

    @property
    def tree_size(self) -> int:
        """Return the number of anchored RealityStamps in the Merkle tree."""
        return self._merkle.size

    async def start(self) -> None:
        """Hydrate the Merkle tree from SQLite WAL storage and bind EventBus subscriptions."""
        existing_leaves = await self._storage.list_merkle_leaf_hashes()
        self._merkle = MerkleTree.from_hex_leaves(existing_leaves)
        self._sub = self._bus.subscribe("perception.*", handler=self._on_perception_event)
        self._bus.register_responder("reality_stamp.verify", self._handle_verify_rpc)
        self._bus.register_responder("reality_stamp.create", self._handle_create_rpc)
        logger.info(
            "reality_stamp_service_started",
            merkle_leaves=self._merkle.size,
            merkle_root=self._merkle.root_hex[:16],
        )

    async def stop(self) -> None:
        """Unsubscribe from the EventBus."""
        if self._sub is not None:
            await self._bus.unsubscribe(self._sub)
            self._sub = None

    async def stamp_perception(
        self,
        sensor_id: str,
        perception_label: str,
        confidence: float,
        metadata: dict[str, Any] | None = None,
        use_stateless_hash_sig: bool = False,
    ) -> RealityStamp:
        """Harvest verified QRNG entropy, sign payload with PQC, and anchor into Merkle log."""
        entropy = await self._qrng.harvest(num_bytes=32)
        payload = RealityPayload(
            node_id=self._identity.node_id,
            sensor_id=sensor_id,
            perception_label=perception_label,
            confidence=confidence,
            qrng_nonce_hex=entropy.raw_hex,
            qrng_sources=entropy.sources,
            metadata=metadata or {},
        )
        stamp = self._signer.sign_payload(
            payload=payload,
            use_stateless_hash_sig=use_stateless_hash_sig,
        )

        # Anchor signed stamp canonically in Merkle Tree and SQLite WAL under a single lock
        leaf_hex = compute_stamp_leaf_hash(stamp)
        async with self._merkle_lock:
            idx = await self._storage.save_merkle_leaf(
                stamp_id=payload.stamp_id,
                leaf_hash=leaf_hex,
                algorithm=stamp.algorithm,
                payload_json=payload.canonical_bytes().decode("utf-8"),
                signature_b64=stamp.signature_b64,
                public_key_fingerprint=stamp.public_key_fingerprint,
            )
            tree_idx, _root = self._merkle.append_leaf_hash(leaf_hex)
            proof = self._merkle.generate_proof(tree_idx)
        anchored = stamp.model_copy(update={"merkle_proof": proof})

        await self._storage.append_audit_event(
            event_type="reality_stamp.anchored",
            actor="reality_stamp",
            payload={
                "stamp_id": payload.stamp_id,
                "leaf_index": idx,
                "merkle_root": proof.root_hash,
                "algorithm": stamp.algorithm,
            },
        )
        await self._bus.publish(
            topic="reality_stamp.created",
            source="modules.reality_stamp",
            payload=anchored.model_dump(mode="json"),
        )
        return anchored

    def verify(
        self,
        stamp: RealityStamp,
        keyring: TrustKeyring | None = None,
    ) -> StampVerificationResult:
        """Verify a RealityStamp signature, payload integrity, keyring, and Merkle proof."""
        return verify_reality_stamp(stamp, keyring=keyring, metrics=self._metrics)

    async def _on_perception_event(self, envelope: EventEnvelope) -> None:
        p = envelope.payload
        await self.stamp_perception(
            sensor_id=str(p.get("sensor_id", envelope.source)),
            perception_label=str(p.get("label", "unknown")),
            confidence=float(p.get("confidence", 0.0)),
            metadata=dict(p.get("metadata", {})),
            use_stateless_hash_sig=bool(p.get("use_stateless_hash_sig", False)),
        )

    async def _handle_create_rpc(self, envelope: EventEnvelope) -> dict[str, Any]:
        p = envelope.payload
        stamp = await self.stamp_perception(
            sensor_id=str(p["sensor_id"]),
            perception_label=str(p["perception_label"]),
            confidence=float(p["confidence"]),
            metadata=dict(p.get("metadata", {})),
            use_stateless_hash_sig=bool(p.get("use_stateless_hash_sig", False)),
        )
        return stamp.model_dump(mode="json")

    async def _handle_verify_rpc(self, envelope: EventEnvelope) -> dict[str, Any]:
        stamp = RealityStamp.model_validate(envelope.payload)
        res = self.verify(stamp)
        return res.model_dump(mode="json")
