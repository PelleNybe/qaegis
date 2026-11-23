"""NIST FIPS 204 (ML-DSA) & FIPS 205 (SLH-DSA) Proof-of-Reality Signing and Verification."""

from __future__ import annotations

import base64
import hashlib
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import orjson
from pydantic import BaseModel, Field

from qaegis.core.identity import (
    DeviceIdentity,
    compute_key_fingerprint,
    constant_time_equal,
)
from qaegis.core.telemetry import QAegisMetrics
from qaegis.modules.reality_stamp.merkle import MerkleProof, verify_merkle_proof


class RealityPayload(BaseModel):
    """Canonical sensor perception payload stamped with verified quantum entropy."""

    stamp_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    node_id: str
    sensor_id: str
    perception_label: str
    confidence: float = Field(ge=0.0, le=1.0)
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    qrng_nonce_hex: str = Field(min_length=32)
    qrng_sources: list[str]
    metadata: dict[str, Any] = Field(default_factory=dict)

    def canonical_bytes(self) -> bytes:
        """Produce deterministic canonical JSON bytes for signing and hashing."""
        return orjson.dumps(self.model_dump(mode="json"), option=orjson.OPT_SORT_KEYS)


class RealityStamp(BaseModel):
    """Cryptographically signed, quantum-seeded Proof-of-Reality artifact."""

    payload: RealityPayload
    payload_sha256: str
    algorithm: str
    key_id: str
    public_key_b64: str
    public_key_fingerprint: str
    signature_b64: str
    merkle_proof: MerkleProof | None = None


class StampVerificationResult(BaseModel):
    """Detailed verification outcome for a RealityStamp."""

    valid: bool
    payload_hash_ok: bool
    fingerprint_ok: bool
    signature_ok: bool
    merkle_proof_ok: bool | None = None
    algorithm: str
    stamp_id: str
    error: str | None = None


class RealitySigner:
    """Signs canonical Edge-AI RealityPayloads using ML-DSA-65 or SLH-DSA-SHA2-128f."""

    def __init__(
        self,
        identity: DeviceIdentity,
        metrics: QAegisMetrics | None = None,
    ) -> None:
        self._identity = identity
        self._metrics = metrics or QAegisMetrics()

    def sign_payload(
        self,
        payload: RealityPayload,
        use_stateless_hash_sig: bool = False,
    ) -> RealityStamp:
        """Sign a RealityPayload with real liboqs PQC signature algorithms."""
        canonical = payload.canonical_bytes()
        payload_digest = hashlib.sha256(canonical).hexdigest()

        start = time.perf_counter()
        alg, signature = self._identity.sign(canonical, use_fallback=use_stateless_hash_sig)
        elapsed = time.perf_counter() - start

        pub_key = (
            self._identity.fallback_sig_public
            if use_stateless_hash_sig
            else self._identity.primary_sig_public
        )
        fingerprint = compute_key_fingerprint(pub_key)

        self._metrics.reality_stamps_signed.labels(algorithm=alg).inc()
        self._metrics.crypto_op_latency_seconds.labels(operation="sign", algorithm=alg).observe(
            elapsed
        )

        return RealityStamp(
            payload=payload,
            payload_sha256=payload_digest,
            algorithm=alg,
            key_id=self._identity.key_id,
            public_key_b64=base64.b64encode(pub_key).decode("ascii"),
            public_key_fingerprint=fingerprint,
            signature_b64=base64.b64encode(signature).decode("ascii"),
        )


def verify_reality_stamp(
    stamp: RealityStamp,
    expected_public_key_fingerprint: str | None = None,
    metrics: QAegisMetrics | None = None,
) -> StampVerificationResult:
    """Perform complete offline verification of a RealityStamp and optional Merkle proof."""
    canonical = stamp.payload.canonical_bytes()
    computed_digest = hashlib.sha256(canonical).hexdigest()
    payload_hash_ok = constant_time_equal(
        computed_digest.encode("ascii"),
        stamp.payload_sha256.encode("ascii"),
    )

    try:
        pub_key = base64.b64decode(stamp.public_key_b64)
        signature = base64.b64decode(stamp.signature_b64)
    except Exception as exc:
        return StampVerificationResult(
            valid=False,
            payload_hash_ok=payload_hash_ok,
            fingerprint_ok=False,
            signature_ok=False,
            merkle_proof_ok=None,
            algorithm=stamp.algorithm,
            stamp_id=stamp.payload.stamp_id,
            error=f"Malformed base64 encoding: {exc}",
        )

    computed_fp = compute_key_fingerprint(pub_key)
    fingerprint_ok = constant_time_equal(
        computed_fp.encode("ascii"),
        stamp.public_key_fingerprint.encode("ascii"),
    )
    if expected_public_key_fingerprint is not None:
        fingerprint_ok = fingerprint_ok and constant_time_equal(
            computed_fp.encode("ascii"),
            expected_public_key_fingerprint.encode("ascii"),
        )

    start = time.perf_counter()
    try:
        signature_ok = DeviceIdentity.verify(canonical, signature, pub_key, stamp.algorithm)
    except Exception as exc:
        signature_ok = False
        err_msg: str | None = f"Signature verification error: {exc}"
    else:
        err_msg = None
    elapsed = time.perf_counter() - start

    merkle_ok: bool | None = None
    if stamp.merkle_proof is not None:
        merkle_ok = verify_merkle_proof(stamp.merkle_proof)

    overall = (
        payload_hash_ok and fingerprint_ok and signature_ok and (merkle_ok is None or merkle_ok)
    )

    if metrics is not None:
        metrics.reality_stamps_verified.labels(valid=str(overall).lower()).inc()
        metrics.crypto_op_latency_seconds.labels(
            operation="verify",
            algorithm=stamp.algorithm,
        ).observe(elapsed)

    return StampVerificationResult(
        valid=overall,
        payload_hash_ok=payload_hash_ok,
        fingerprint_ok=fingerprint_ok,
        signature_ok=signature_ok,
        merkle_proof_ok=merkle_ok,
        algorithm=stamp.algorithm,
        stamp_id=stamp.payload.stamp_id,
        error=err_msg,
    )
