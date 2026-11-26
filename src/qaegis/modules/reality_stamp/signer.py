"""NIST FIPS 204 (ML-DSA) & FIPS 205 (SLH-DSA) Proof-of-Reality Signing and Verification."""

from __future__ import annotations

import base64
import hashlib
import os
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import orjson
from pydantic import BaseModel, Field

from qaegis.core.identity import (
    DeviceIdentity,
    TrustKeyring,
    compute_key_fingerprint,
    constant_time_equal,
)
from qaegis.core.telemetry import QAegisMetrics
from qaegis.modules.reality_stamp.merkle import MerkleProof, hash_leaf, verify_merkle_proof


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
    key_version: int = 1
    public_key_b64: str
    public_key_fingerprint: str
    signature_b64: str
    merkle_proof: MerkleProof | None = None


def compute_stamp_leaf_hash(stamp: RealityStamp) -> str:
    """Compute the RFC 6962 domain-separated SHA-256 Merkle leaf hash bound to `stamp`."""
    leaf_bytes = orjson.dumps(
        {
            "payload_sha256": stamp.payload_sha256,
            "signature_b64": stamp.signature_b64,
            "algorithm": stamp.algorithm,
            "public_key_fingerprint": stamp.public_key_fingerprint,
        },
        option=orjson.OPT_SORT_KEYS,
    )
    return hash_leaf(leaf_bytes).hex()


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
            key_version=self._identity.key_version,
            public_key_b64=base64.b64encode(pub_key).decode("ascii"),
            public_key_fingerprint=fingerprint,
            signature_b64=base64.b64encode(signature).decode("ascii"),
        )


def verify_reality_stamp(
    stamp: RealityStamp,
    expected_public_key_fingerprint: str | None = None,
    keyring: TrustKeyring | None = None,
    metrics: QAegisMetrics | None = None,
) -> StampVerificationResult:
    """Perform offline verification of a RealityStamp, optional keyring, and Merkle proof."""
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

    keyring_err: str | None = None
    if keyring is not None:
        bundle = keyring.get_by_key_id(stamp.key_id) or keyring.get_by_version(stamp.key_version)
        if bundle is None:
            fingerprint_ok = False
            keyring_err = f"Key ID '{stamp.key_id}' (v{stamp.key_version}) not found in keyring"
        else:
            allowed_fps = (bundle.primary_sig_fingerprint, bundle.fallback_sig_fingerprint)
            if not any(
                constant_time_equal(computed_fp.encode("ascii"), fp.encode("ascii"))
                for fp in allowed_fps
            ):
                fingerprint_ok = False
                keyring_err = (
                    f"Stamp public key does not match trusted keyring entry '{bundle.key_id}'"
                )

    start = time.perf_counter()
    try:
        signature_ok = DeviceIdentity.verify(canonical, signature, pub_key, stamp.algorithm)
    except Exception as exc:
        signature_ok = False
        err_msg: str | None = f"Signature verification error: {exc}"
    else:
        err_msg = keyring_err
    elapsed = time.perf_counter() - start

    merkle_ok: bool | None = None
    if stamp.merkle_proof is not None:
        expected_leaf = compute_stamp_leaf_hash(stamp)
        leaf_bound = constant_time_equal(
            expected_leaf.encode("ascii"),
            stamp.merkle_proof.leaf_hash.encode("ascii"),
        )
        merkle_ok = leaf_bound and verify_merkle_proof(stamp.merkle_proof)
        if not leaf_bound and err_msg is None:
            err_msg = "Merkle inclusion proof leaf_hash does not match this RealityStamp"

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


class ArtifactSignatureBundle(BaseModel):
    """Detached NIST FIPS 204/205 post-quantum signature bundle for files, models, and SBOMs."""

    bundle_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    artifact_name: str
    size_bytes: int = Field(ge=0)
    sha256: str = Field(min_length=64, max_length=64)
    sha3_256: str = Field(min_length=64, max_length=64)
    qrng_nonce_hex: str = Field(min_length=32)
    signed_at_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    node_id: str
    key_id: str
    key_version: int = 1
    algorithm: str
    public_key_b64: str
    public_key_fingerprint: str
    signature_b64: str
    annotations: dict[str, Any] = Field(default_factory=dict)

    def signing_transcript(self) -> bytes:
        """Deterministic canonical transcript authenticated by ML-DSA-65 or SLH-DSA."""
        doc = {
            "annotations": self.annotations,
            "artifact_name": self.artifact_name,
            "bundle_id": self.bundle_id,
            "key_id": self.key_id,
            "key_version": self.key_version,
            "node_id": self.node_id,
            "qrng_nonce_hex": self.qrng_nonce_hex,
            "sha256": self.sha256,
            "sha3_256": self.sha3_256,
            "signed_at_utc": self.signed_at_utc.isoformat(),
            "size_bytes": self.size_bytes,
        }
        return orjson.dumps(doc, option=orjson.OPT_SORT_KEYS)


class ArtifactVerificationResult(BaseModel):
    """Detailed verification outcome for an ArtifactSignatureBundle."""

    valid: bool
    digest_ok: bool
    size_ok: bool
    fingerprint_ok: bool
    signature_ok: bool
    algorithm: str
    key_id: str
    key_version: int
    error: str | None = None


def _hash_stream_file(path: Path) -> tuple[int, str, str]:
    """Stream-hash an arbitrary file in 64 KiB chunks returning (size, sha256, sha3_256)."""
    h_sha2 = hashlib.sha256()
    h_sha3 = hashlib.sha3_256()
    total = 0
    with path.open("rb") as handle:
        while chunk := handle.read(65536):
            total += len(chunk)
            h_sha2.update(chunk)
            h_sha3.update(chunk)
    return total, h_sha2.hexdigest(), h_sha3.hexdigest()


def sign_artifact_bytes(
    data: bytes,
    identity: DeviceIdentity,
    artifact_name: str = "artifact.bin",
    use_stateless_hash_sig: bool = False,
    qrng_nonce_hex: str | None = None,
    annotations: dict[str, Any] | None = None,
) -> ArtifactSignatureBundle:
    """Sign raw bytes (model weights, SBOM, firmware, archive) with ML-DSA-65 or SLH-DSA."""
    sha2 = hashlib.sha256(data).hexdigest()
    sha3 = hashlib.sha3_256(data).hexdigest()
    nonce = qrng_nonce_hex or os.urandom(32).hex()
    pub_key = (
        identity.fallback_sig_public if use_stateless_hash_sig else identity.primary_sig_public
    )
    unsigned = ArtifactSignatureBundle(
        artifact_name=artifact_name,
        size_bytes=len(data),
        sha256=sha2,
        sha3_256=sha3,
        qrng_nonce_hex=nonce,
        node_id=identity.node_id,
        key_id=identity.key_id,
        key_version=identity.key_version,
        algorithm=identity.fallback_sig_alg if use_stateless_hash_sig else identity.primary_sig_alg,
        public_key_b64=base64.b64encode(pub_key).decode("ascii"),
        public_key_fingerprint=compute_key_fingerprint(pub_key),
        signature_b64="",
        annotations=annotations or {},
    )
    alg, sig = identity.sign(unsigned.signing_transcript(), use_fallback=use_stateless_hash_sig)
    return unsigned.model_copy(
        update={
            "algorithm": alg,
            "signature_b64": base64.b64encode(sig).decode("ascii"),
        }
    )


def sign_artifact_file(
    path: Path,
    identity: DeviceIdentity,
    use_stateless_hash_sig: bool = False,
    qrng_nonce_hex: str | None = None,
    annotations: dict[str, Any] | None = None,
) -> ArtifactSignatureBundle:
    """Stream-hash `path` and produce a detached post-quantum ArtifactSignatureBundle."""
    size_bytes, sha2, sha3 = _hash_stream_file(path)
    nonce = qrng_nonce_hex or os.urandom(32).hex()
    pub_key = (
        identity.fallback_sig_public if use_stateless_hash_sig else identity.primary_sig_public
    )
    unsigned = ArtifactSignatureBundle(
        artifact_name=path.name,
        size_bytes=size_bytes,
        sha256=sha2,
        sha3_256=sha3,
        qrng_nonce_hex=nonce,
        node_id=identity.node_id,
        key_id=identity.key_id,
        key_version=identity.key_version,
        algorithm=identity.fallback_sig_alg if use_stateless_hash_sig else identity.primary_sig_alg,
        public_key_b64=base64.b64encode(pub_key).decode("ascii"),
        public_key_fingerprint=compute_key_fingerprint(pub_key),
        signature_b64="",
        annotations=annotations or {},
    )
    alg, sig = identity.sign(unsigned.signing_transcript(), use_fallback=use_stateless_hash_sig)
    return unsigned.model_copy(
        update={
            "algorithm": alg,
            "signature_b64": base64.b64encode(sig).decode("ascii"),
        }
    )


def _verify_artifact_digests(
    bundle: ArtifactSignatureBundle,
    actual_size: int,
    actual_sha256: str,
    actual_sha3_256: str,
    expected_public_key_fingerprint: str | None = None,
    keyring: TrustKeyring | None = None,
) -> ArtifactVerificationResult:
    size_ok = actual_size == bundle.size_bytes
    digest_ok = constant_time_equal(
        actual_sha256.encode("ascii"),
        bundle.sha256.encode("ascii"),
    ) and constant_time_equal(
        actual_sha3_256.encode("ascii"),
        bundle.sha3_256.encode("ascii"),
    )
    try:
        pub_key = base64.b64decode(bundle.public_key_b64)
        sig_bytes = base64.b64decode(bundle.signature_b64)
    except Exception as exc:
        return ArtifactVerificationResult(
            valid=False,
            digest_ok=digest_ok,
            size_ok=size_ok,
            fingerprint_ok=False,
            signature_ok=False,
            algorithm=bundle.algorithm,
            key_id=bundle.key_id,
            key_version=bundle.key_version,
            error=f"Invalid base64 encoding: {exc}",
        )

    computed_fp = compute_key_fingerprint(pub_key)
    fp_ok = constant_time_equal(
        computed_fp.encode("ascii"),
        bundle.public_key_fingerprint.encode("ascii"),
    )
    if expected_public_key_fingerprint is not None:
        fp_ok = fp_ok and constant_time_equal(
            computed_fp.encode("ascii"),
            expected_public_key_fingerprint.encode("ascii"),
        )

    err_msg: str | None = None
    if keyring is not None:
        kr_entry = keyring.get_by_key_id(bundle.key_id) or keyring.get_by_version(
            bundle.key_version
        )
        if kr_entry is None:
            fp_ok = False
            err_msg = f"Key ID '{bundle.key_id}' not found in TrustKeyring"
        else:
            allowed_fps = (kr_entry.primary_sig_fingerprint, kr_entry.fallback_sig_fingerprint)
            if not any(
                constant_time_equal(computed_fp.encode("ascii"), allowed.encode("ascii"))
                for allowed in allowed_fps
            ):
                fp_ok = False
                err_msg = "Artifact signer public key does not match trusted keyring entry"

    try:
        sig_ok = DeviceIdentity.verify(
            bundle.signing_transcript(),
            sig_bytes,
            pub_key,
            bundle.algorithm,
        )
    except Exception as exc:
        sig_ok = False
        err_msg = f"Signature verification error: {exc}"

    if not digest_ok and err_msg is None:
        err_msg = "Artifact SHA-256 / SHA3-256 digest mismatch (file modified or tampered)"

    valid = size_ok and digest_ok and fp_ok and sig_ok
    return ArtifactVerificationResult(
        valid=valid,
        digest_ok=digest_ok,
        size_ok=size_ok,
        fingerprint_ok=fp_ok,
        signature_ok=sig_ok,
        algorithm=bundle.algorithm,
        key_id=bundle.key_id,
        key_version=bundle.key_version,
        error=err_msg,
    )


def verify_artifact_bytes(
    data: bytes,
    bundle: ArtifactSignatureBundle,
    expected_public_key_fingerprint: str | None = None,
    keyring: TrustKeyring | None = None,
) -> ArtifactVerificationResult:
    """Verify in-memory bytes against a detached post-quantum ArtifactSignatureBundle."""
    return _verify_artifact_digests(
        bundle=bundle,
        actual_size=len(data),
        actual_sha256=hashlib.sha256(data).hexdigest(),
        actual_sha3_256=hashlib.sha3_256(data).hexdigest(),
        expected_public_key_fingerprint=expected_public_key_fingerprint,
        keyring=keyring,
    )


def verify_artifact_file(
    path: Path,
    bundle: ArtifactSignatureBundle,
    expected_public_key_fingerprint: str | None = None,
    keyring: TrustKeyring | None = None,
) -> ArtifactVerificationResult:
    """Stream-verify a file on disk against a detached post-quantum ArtifactSignatureBundle."""
    actual_size, sha2, sha3 = _hash_stream_file(path)
    return _verify_artifact_digests(
        bundle=bundle,
        actual_size=actual_size,
        actual_sha256=sha2,
        actual_sha3_256=sha3,
        expected_public_key_fingerprint=expected_public_key_fingerprint,
        keyring=keyring,
    )
