"""Post-Quantum Device Identity, Zero-Downtime Key Rotation, Keyring, and CycloneDX CBOM."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import oqs
import orjson
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pydantic import BaseModel, Field

from qaegis import __version__
from qaegis.core.config import IdentityConfig
from qaegis.core.hardware_seal import HardwareSealer, SealedBlob
from qaegis.core.telemetry import QAegisMetrics, get_logger

logger = get_logger(__name__)

# Canonical alias mapping across liboqs versions for NIST FIPS 203 / 204 / 205
_SIG_ALIASES: dict[str, tuple[str, ...]] = {
    "ML-DSA-44": ("ML-DSA-44",),
    "ML-DSA-65": ("ML-DSA-65",),
    "ML-DSA-87": ("ML-DSA-87",),
    "SLH-DSA-SHA2-128f": (
        "SLH-DSA-SHA2-128f",
        "SLH_DSA_PURE_SHA2_128F",
        "SPHINCS+-SHA2-128f-simple",
    ),
    "SLH-DSA-SHA2-128s": (
        "SLH-DSA-SHA2-128s",
        "SLH_DSA_PURE_SHA2_128S",
        "SPHINCS+-SHA2-128s-simple",
    ),
    "SLH-DSA-SHAKE-128f": (
        "SLH-DSA-SHAKE-128f",
        "SLH_DSA_PURE_SHAKE_128F",
        "SPHINCS+-SHAKE-128f-simple",
    ),
}

_KEM_ALIASES: dict[str, tuple[str, ...]] = {
    "ML-KEM-512": ("ML-KEM-512", "Kyber512"),
    "ML-KEM-768": ("ML-KEM-768", "Kyber768"),
    "ML-KEM-1024": ("ML-KEM-1024", "Kyber1024"),
}

# NIST / IETF OIDs for CycloneDX 1.6 CBOM cryptographic asset descriptors
_ALGORITHM_OIDS: dict[str, tuple[str, int]] = {
    "ML-KEM-512": ("2.16.840.1.101.3.4.4.1", 1),
    "ML-KEM-768": ("2.16.840.1.101.3.4.4.2", 3),
    "ML-KEM-1024": ("2.16.840.1.101.3.4.4.3", 5),
    "ML-DSA-44": ("2.16.840.1.101.3.4.3.17", 2),
    "ML-DSA-65": ("2.16.840.1.101.3.4.3.18", 3),
    "ML-DSA-87": ("2.16.840.1.101.3.4.3.19", 5),
    "SLH-DSA-SHA2-128s": ("2.16.840.1.101.3.4.3.20", 1),
    "SLH_DSA_PURE_SHA2_128S": ("2.16.840.1.101.3.4.3.20", 1),
    "SLH-DSA-SHA2-128f": ("2.16.840.1.101.3.4.3.21", 1),
    "SLH_DSA_PURE_SHA2_128F": ("2.16.840.1.101.3.4.3.21", 1),
    "SLH-DSA-SHA2-192s": ("2.16.840.1.101.3.4.3.22", 3),
    "SLH_DSA_PURE_SHA2_192S": ("2.16.840.1.101.3.4.3.22", 3),
    "SLH-DSA-SHA2-192f": ("2.16.840.1.101.3.4.3.23", 3),
    "SLH_DSA_PURE_SHA2_192F": ("2.16.840.1.101.3.4.3.23", 3),
    "SLH-DSA-SHA2-256s": ("2.16.840.1.101.3.4.3.24", 5),
    "SLH_DSA_PURE_SHA2_256S": ("2.16.840.1.101.3.4.3.24", 5),
    "SLH-DSA-SHA2-256f": ("2.16.840.1.101.3.4.3.25", 5),
    "SLH_DSA_PURE_SHA2_256F": ("2.16.840.1.101.3.4.3.25", 5),
    "SLH-DSA-SHAKE-128s": ("2.16.840.1.101.3.4.3.26", 1),
    "SLH_DSA_PURE_SHAKE_128S": ("2.16.840.1.101.3.4.3.26", 1),
    "SLH-DSA-SHAKE-128f": ("2.16.840.1.101.3.4.3.27", 1),
    "SLH_DSA_PURE_SHAKE_128F": ("2.16.840.1.101.3.4.3.27", 1),
    "SLH-DSA-SHAKE-192s": ("2.16.840.1.101.3.4.3.28", 3),
    "SLH_DSA_PURE_SHAKE_192S": ("2.16.840.1.101.3.4.3.28", 3),
    "SLH-DSA-SHAKE-192f": ("2.16.840.1.101.3.4.3.29", 3),
    "SLH_DSA_PURE_SHAKE_192F": ("2.16.840.1.101.3.4.3.29", 3),
    "SLH-DSA-SHAKE-256s": ("2.16.840.1.101.3.4.3.30", 5),
    "SLH_DSA_PURE_SHAKE_256S": ("2.16.840.1.101.3.4.3.30", 5),
    "SLH-DSA-SHAKE-256f": ("2.16.840.1.101.3.4.3.31", 5),
    "SLH_DSA_PURE_SHAKE_256F": ("2.16.840.1.101.3.4.3.31", 5),
    "X25519": ("1.3.101.110", 0),
    "AES-256-GCM": ("2.16.840.1.101.3.4.1.46", 5),
    "HKDF-SHA384": ("2.16.840.1.101.3.4.2.2", 5),
}


def resolve_oqs_sig_algorithm(requested: str) -> str:
    """Resolve a NIST signature algorithm name to an enabled liboqs mechanism."""
    enabled = set(oqs.get_enabled_sig_mechanisms())
    if requested in enabled:
        return requested
    for candidate in _SIG_ALIASES.get(requested, ()):
        if candidate in enabled:
            return candidate
    normalized = requested.replace("-", "_").upper()
    for mech in enabled:
        if mech.upper() == normalized:
            return str(mech)
    raise ValueError(
        f"Signature algorithm '{requested}' is not enabled in liboqs {oqs.oqs_version()}"
    )


def resolve_oqs_kem_algorithm(requested: str) -> str:
    """Resolve a NIST KEM algorithm name to an enabled liboqs mechanism."""
    enabled = set(oqs.get_enabled_kem_mechanisms())
    if requested in enabled:
        return requested
    for candidate in _KEM_ALIASES.get(requested, ()):
        if candidate in enabled:
            return candidate
    raise ValueError(f"KEM algorithm '{requested}' is not enabled in liboqs {oqs.oqs_version()}")


def compute_key_fingerprint(public_key: bytes) -> str:
    """Return a SHA3-256 hex fingerprint for a public key."""
    return hashlib.sha3_256(public_key).hexdigest()


def constant_time_equal(left: bytes, right: bytes) -> bool:
    """Constant-time byte equality check to resist timing side-channels."""
    return hmac.compare_digest(left, right)


def _zero_bytearray(buf: bytearray) -> None:
    """Overwrite a mutable secret byte buffer with zeros in place."""
    for idx in range(len(buf)):
        buf[idx] = 0


def _atomic_write_file(
    path: Path, content: bytes, mode: int, parent_mode: int | None = None
) -> None:
    """Write a file atomically with explicit permissions and fsync durability."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if parent_mode is not None:
        os.chmod(path.parent, parent_mode)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".qaegis-tmp-")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
        os.chmod(path, mode)
    except Exception:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise


def _atomic_write_secret(path: Path, content: bytes) -> None:
    """Write sensitive key material atomically with strict 0o600 permissions."""
    _atomic_write_file(path, content, mode=0o600, parent_mode=0o700)


class PublicIdentityBundle(BaseModel):
    """Exportable, non-secret public key bundle for a Q-Aegis edge node."""

    node_id: str
    key_id: str
    key_version: int = Field(default=1, ge=1)
    created_at_utc: datetime
    retired_at_utc: datetime | None = None
    primary_sig_alg: str
    primary_sig_public_b64: str
    primary_sig_fingerprint: str
    fallback_sig_alg: str
    fallback_sig_public_b64: str
    fallback_sig_fingerprint: str
    kem_alg: str
    kem_public_b64: str
    kem_fingerprint: str
    x25519_public_b64: str
    x25519_fingerprint: str


class TrustKeyring(BaseModel):
    """Versioned trust keyring retaining historical public keys for zero-downtime verification."""

    node_id: str
    current_key_id: str
    current_version: int = Field(default=1, ge=1)
    updated_at_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    keys: dict[str, PublicIdentityBundle] = Field(default_factory=dict)

    def get_by_key_id(self, key_id: str) -> PublicIdentityBundle | None:
        """Look up a current or historical public key bundle by `key_id`."""
        return self.keys.get(key_id)

    def get_by_version(self, key_version: int) -> PublicIdentityBundle | None:
        """Look up a current or historical public key bundle by `key_version`."""
        for bundle in self.keys.values():
            if bundle.key_version == key_version:
                return bundle
        return None


class DeviceIdentity:
    """In-memory handle holding real NIST PQC + classical X25519 keys for a node."""

    def __init__(
        self,
        node_id: str,
        key_id: str,
        created_at_utc: datetime,
        primary_sig_alg: str,
        primary_sig_public: bytes,
        primary_sig_secret: bytes,
        fallback_sig_alg: str,
        fallback_sig_public: bytes,
        fallback_sig_secret: bytes,
        kem_alg: str,
        kem_public: bytes,
        kem_secret: bytes,
        x25519_private: X25519PrivateKey,
        key_version: int = 1,
    ) -> None:
        self.node_id = node_id
        self.key_id = key_id
        self.key_version = key_version
        self.created_at_utc = created_at_utc
        self.primary_sig_alg = primary_sig_alg
        self.primary_sig_public = primary_sig_public
        self._primary_sig_secret = bytearray(primary_sig_secret)
        self.fallback_sig_alg = fallback_sig_alg
        self.fallback_sig_public = fallback_sig_public
        self._fallback_sig_secret = bytearray(fallback_sig_secret)
        self.kem_alg = kem_alg
        self.kem_public = kem_public
        self._kem_secret = bytearray(kem_secret)
        self._x25519_private = x25519_private
        self.x25519_public_bytes: bytes = x25519_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._zeroized = False

    def _ensure_active(self) -> None:
        if self._zeroized:
            raise RuntimeError(
                f"DeviceIdentity '{self.key_id}' secrets have been zeroized upon retirement"
            )

    @property
    def is_zeroized(self) -> bool:
        """Return True if this identity's private key buffers have been zeroized."""
        return self._zeroized

    @property
    def x25519_private(self) -> X25519PrivateKey:
        self._ensure_active()
        return self._x25519_private

    @property
    def x25519_public(self) -> X25519PublicKey:
        return self._x25519_private.public_key()

    @property
    def primary_sig_secret(self) -> bytes:
        return bytes(self._primary_sig_secret)

    @property
    def fallback_sig_secret(self) -> bytes:
        return bytes(self._fallback_sig_secret)

    @property
    def kem_secret(self) -> bytes:
        return bytes(self._kem_secret)

    def zeroize_secrets(self) -> None:
        """Zero out mutable in-memory PQC private key buffers upon retirement."""
        _zero_bytearray(self._primary_sig_secret)
        _zero_bytearray(self._fallback_sig_secret)
        _zero_bytearray(self._kem_secret)
        self._zeroized = True

    def sign(self, message: bytes, use_fallback: bool = False) -> tuple[str, bytes]:
        """Sign `message` using ML-DSA (primary) or SLH-DSA (fallback)."""
        self._ensure_active()
        alg = self.fallback_sig_alg if use_fallback else self.primary_sig_alg
        secret = bytes(self._fallback_sig_secret if use_fallback else self._primary_sig_secret)
        with oqs.Signature(alg, secret_key=secret) as signer:
            signature: bytes = signer.sign(message)
        return alg, signature

    @staticmethod
    def verify(message: bytes, signature: bytes, public_key: bytes, algorithm: str) -> bool:
        """Verify a PQC signature using liboqs."""
        resolved = resolve_oqs_sig_algorithm(algorithm)
        with oqs.Signature(resolved) as verifier:
            valid: bool = verifier.verify(message, signature, public_key)
        return valid

    def decap_kem(self, ciphertext: bytes) -> bytes:
        """Decapsulate a post-quantum ML-KEM shared secret."""
        self._ensure_active()
        with oqs.KeyEncapsulation(self.kem_alg, secret_key=bytes(self._kem_secret)) as kem:
            shared: bytes = kem.decap_secret(ciphertext)
        return shared

    def public_bundle(self, retired_at_utc: datetime | None = None) -> PublicIdentityBundle:
        """Return a serializable public-key-only representation of this device identity."""
        return PublicIdentityBundle(
            node_id=self.node_id,
            key_id=self.key_id,
            key_version=self.key_version,
            created_at_utc=self.created_at_utc,
            retired_at_utc=retired_at_utc,
            primary_sig_alg=self.primary_sig_alg,
            primary_sig_public_b64=base64.b64encode(self.primary_sig_public).decode("ascii"),
            primary_sig_fingerprint=compute_key_fingerprint(self.primary_sig_public),
            fallback_sig_alg=self.fallback_sig_alg,
            fallback_sig_public_b64=base64.b64encode(self.fallback_sig_public).decode("ascii"),
            fallback_sig_fingerprint=compute_key_fingerprint(self.fallback_sig_public),
            kem_alg=self.kem_alg,
            kem_public_b64=base64.b64encode(self.kem_public).decode("ascii"),
            kem_fingerprint=compute_key_fingerprint(self.kem_public),
            x25519_public_b64=base64.b64encode(self.x25519_public_bytes).decode("ascii"),
            x25519_fingerprint=compute_key_fingerprint(self.x25519_public_bytes),
        )


class CBOMRecord(BaseModel):
    """Cryptographic Bill of Materials entry for compliance and PQC migration auditing."""

    generated_at_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    node_id: str
    key_id: str
    key_version: int = 1
    liboqs_version: str
    algorithms: list[dict[str, Any]]


class IdentityManager:
    """Manages generation, secure persistence (0o600), zero-downtime rotation, and CBOM export."""

    KEYFILE_NAME = "device_identity.secret.json"
    SEALED_KEYFILE_NAME = "device_identity.sealed.json"
    PUBFILE_NAME = "device_identity.public.json"
    KEYRING_NAME = "keyring.json"

    def __init__(
        self,
        keys_dir: Path,
        node_id: str,
        config: IdentityConfig | None = None,
    ) -> None:
        self._keys_dir = keys_dir
        self._node_id = node_id
        self._config = config or IdentityConfig()

    @property
    def secret_path(self) -> Path:
        return self._keys_dir / self.KEYFILE_NAME

    @property
    def sealed_path(self) -> Path:
        return self._keys_dir / self.SEALED_KEYFILE_NAME

    @property
    def public_path(self) -> Path:
        return self._keys_dir / self.PUBFILE_NAME

    @property
    def keyring_path(self) -> Path:
        return self._keys_dir / self.KEYRING_NAME

    def generate(self, key_version: int = 1) -> DeviceIdentity:
        """Generate a fresh hybrid PQC + classical device identity using liboqs and X25519."""
        primary_alg = resolve_oqs_sig_algorithm(self._config.primary_sig_alg)
        fallback_alg = resolve_oqs_sig_algorithm(self._config.fallback_sig_alg)
        kem_alg = resolve_oqs_kem_algorithm(self._config.kem_alg)

        with oqs.Signature(primary_alg) as primary_sig:
            primary_pub: bytes = primary_sig.generate_keypair()
            primary_sec: bytes = primary_sig.export_secret_key()

        with oqs.Signature(fallback_alg) as fallback_sig:
            fallback_pub: bytes = fallback_sig.generate_keypair()
            fallback_sec: bytes = fallback_sig.export_secret_key()

        with oqs.KeyEncapsulation(kem_alg) as kem:
            kem_pub: bytes = kem.generate_keypair()
            kem_sec: bytes = kem.export_secret_key()

        x25519_priv = X25519PrivateKey.generate()
        key_id = f"kid-v{key_version}-{uuid.uuid4().hex[:14]}"
        identity = DeviceIdentity(
            node_id=self._node_id,
            key_id=key_id,
            key_version=key_version,
            created_at_utc=datetime.now(UTC),
            primary_sig_alg=primary_alg,
            primary_sig_public=primary_pub,
            primary_sig_secret=primary_sec,
            fallback_sig_alg=fallback_alg,
            fallback_sig_public=fallback_pub,
            fallback_sig_secret=fallback_sec,
            kem_alg=kem_alg,
            kem_public=kem_pub,
            kem_secret=kem_sec,
            x25519_private=x25519_priv,
        )
        self.save(identity)
        self._register_in_keyring(identity.public_bundle())
        logger.info(
            "device_identity_generated",
            node_id=self._node_id,
            key_id=key_id,
            key_version=key_version,
            primary_sig=primary_alg,
            fallback_sig=fallback_alg,
            kem=kem_alg,
        )
        return identity

    def save(self, identity: DeviceIdentity) -> None:
        """Persist secret key material with 0o600 permissions and export public bundle."""
        secret_bytes = self._serialize_secret_bytes(identity)
        _atomic_write_secret(self.secret_path, secret_bytes)
        self._write_public_bundle(identity)

    def _serialize_secret_bytes(self, identity: DeviceIdentity) -> bytes:
        x25519_raw = identity.x25519_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        secret_doc = {
            "node_id": identity.node_id,
            "key_id": identity.key_id,
            "key_version": identity.key_version,
            "created_at_utc": identity.created_at_utc.isoformat(),
            "primary_sig_alg": identity.primary_sig_alg,
            "primary_sig_public_b64": base64.b64encode(identity.primary_sig_public).decode("ascii"),
            "primary_sig_secret_b64": base64.b64encode(identity.primary_sig_secret).decode("ascii"),
            "fallback_sig_alg": identity.fallback_sig_alg,
            "fallback_sig_public_b64": base64.b64encode(identity.fallback_sig_public).decode(
                "ascii"
            ),
            "fallback_sig_secret_b64": base64.b64encode(identity.fallback_sig_secret).decode(
                "ascii"
            ),
            "kem_alg": identity.kem_alg,
            "kem_public_b64": base64.b64encode(identity.kem_public).decode("ascii"),
            "kem_secret_b64": base64.b64encode(identity.kem_secret).decode("ascii"),
            "x25519_private_b64": base64.b64encode(x25519_raw).decode("ascii"),
        }
        return orjson.dumps(secret_doc, option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS)

    def _write_public_bundle(self, identity: DeviceIdentity) -> None:
        pub_bytes = orjson.dumps(
            identity.public_bundle().model_dump(mode="json"),
            option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS,
        )
        _atomic_write_file(self.public_path, pub_bytes, mode=0o644)

    @staticmethod
    def _deserialize_secret_bytes(raw_bytes: bytes) -> DeviceIdentity:
        raw = orjson.loads(raw_bytes)
        x25519_priv = X25519PrivateKey.from_private_bytes(
            base64.b64decode(raw["x25519_private_b64"])
        )
        return DeviceIdentity(
            node_id=raw["node_id"],
            key_id=raw["key_id"],
            key_version=int(raw.get("key_version", 1)),
            created_at_utc=datetime.fromisoformat(raw["created_at_utc"]),
            primary_sig_alg=resolve_oqs_sig_algorithm(raw["primary_sig_alg"]),
            primary_sig_public=base64.b64decode(raw["primary_sig_public_b64"]),
            primary_sig_secret=base64.b64decode(raw["primary_sig_secret_b64"]),
            fallback_sig_alg=resolve_oqs_sig_algorithm(raw["fallback_sig_alg"]),
            fallback_sig_public=base64.b64decode(raw["fallback_sig_public_b64"]),
            fallback_sig_secret=base64.b64decode(raw["fallback_sig_secret_b64"]),
            kem_alg=resolve_oqs_kem_algorithm(raw["kem_alg"]),
            kem_public=base64.b64decode(raw["kem_public_b64"]),
            kem_secret=base64.b64decode(raw["kem_secret_b64"]),
            x25519_private=x25519_priv,
        )

    def load_keyring(self) -> TrustKeyring:
        """Load the persisted versioned trust keyring (`0o600`), enforcing file permissions."""
        if not self.keyring_path.is_file():
            identity = self.load_or_create()
            return self._register_in_keyring(identity.public_bundle())
        mode = self.keyring_path.stat().st_mode & 0o777
        if mode & 0o077:
            raise PermissionError(
                f"Insecure permissions {oct(mode)} on {self.keyring_path}; expected 0o600"
            )
        return TrustKeyring.model_validate(orjson.loads(self.keyring_path.read_bytes()))

    def save_keyring(self, keyring: TrustKeyring) -> None:
        """Atomically persist the versioned trust keyring with 0o600 permissions."""
        payload = orjson.dumps(
            keyring.model_dump(mode="json"),
            option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS,
        )
        _atomic_write_secret(self.keyring_path, payload)

    def _register_in_keyring(
        self,
        bundle: PublicIdentityBundle,
        retired_previous: PublicIdentityBundle | None = None,
    ) -> TrustKeyring:
        if self.keyring_path.is_file():
            kr = self.load_keyring()
        else:
            kr = TrustKeyring(
                node_id=bundle.node_id,
                current_key_id=bundle.key_id,
                current_version=bundle.key_version,
                keys={},
            )
        if retired_previous is not None:
            kr.keys[retired_previous.key_id] = retired_previous
        kr.keys[bundle.key_id] = bundle
        kr.current_key_id = bundle.key_id
        kr.current_version = bundle.key_version
        kr.updated_at_utc = datetime.now(UTC)
        self.save_keyring(kr)
        return kr

    def seal_identity(
        self,
        identity: DeviceIdentity,
        sealer: HardwareSealer,
        remove_plaintext_secret: bool = False,
    ) -> SealedBlob:
        """Hardware-seal PQC secret key material via PKCS#11 or TPM 2.0 and persist 0o600."""
        secret_bytes = self._serialize_secret_bytes(identity)
        aad = f"{identity.node_id}|{identity.key_id}".encode()
        blob = sealer.seal(secret_bytes, associated_data=aad)
        blob_bytes = orjson.dumps(
            blob.model_dump(mode="json"),
            option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS,
        )
        _atomic_write_secret(self.sealed_path, blob_bytes)
        self._write_public_bundle(identity)
        if remove_plaintext_secret and self.secret_path.is_file():
            self.secret_path.unlink()
        return blob

    def load_sealed(self, sealer: HardwareSealer) -> DeviceIdentity:
        """Load and hardware-unseal the persisted PQC identity from sealed storage."""
        if not self.sealed_path.is_file():
            raise FileNotFoundError(f"Sealed identity file not found: {self.sealed_path}")
        mode = self.sealed_path.stat().st_mode & 0o777
        if mode & 0o077:
            raise PermissionError(
                f"Insecure permissions {oct(mode)} on {self.sealed_path}; expected 0o600"
            )
        blob = SealedBlob.model_validate(orjson.loads(self.sealed_path.read_bytes()))
        plaintext = sealer.unseal(blob)
        return self._deserialize_secret_bytes(plaintext)

    def load_or_create(self, sealer: HardwareSealer | None = None) -> DeviceIdentity:
        """Load the existing device identity (unsealing if needed), or generate a new one."""
        if self.secret_path.is_file():
            return self.load()
        if sealer is not None and self.sealed_path.is_file():
            return self.load_sealed(sealer)
        return self.generate()

    def load_active(self, sealer: HardwareSealer | None = None) -> DeviceIdentity:
        """Load the active device identity, preferring sealed storage when `sealer` is given."""
        if sealer is not None and self.sealed_path.is_file():
            return self.load_sealed(sealer)
        return self.load()

    def load(self) -> DeviceIdentity:
        """Load the persisted device identity after enforcing strict file permissions."""
        if not self.secret_path.is_file():
            raise FileNotFoundError(f"Secret identity file not found: {self.secret_path}")
        mode = self.secret_path.stat().st_mode & 0o777
        if mode & 0o077:
            raise PermissionError(
                f"Insecure permissions {oct(mode)} on {self.secret_path}; expected 0o600"
            )
        return self._deserialize_secret_bytes(self.secret_path.read_bytes())

    def rotate_keys(
        self,
        sealer: HardwareSealer | None = None,
        metrics: QAegisMetrics | None = None,
        remove_plaintext_secret: bool = False,
    ) -> tuple[DeviceIdentity, TrustKeyring]:
        """Perform zero-downtime PQC key rotation while preserving historical verification keys.

        1. Captures the outgoing public bundle with a retirement timestamp into `keyring.json`.
        2. Overwrites & zeroizes outgoing private keys in memory and archives public history.
        3. Generates fresh ML-DSA-65, SLH-DSA, ML-KEM-768, and X25519 keys at `key_version + 1`.
        4. Optionally hardware-seals the rotated secret identity using `sealer`.
        """
        retired_bundle: PublicIdentityBundle | None = None
        next_version = 1

        if self.secret_path.is_file():
            previous = self.load()
            retired_bundle = previous.public_bundle(retired_at_utc=datetime.now(UTC))
            next_version = previous.key_version + 1
            previous.zeroize_secrets()
            archive_name = (
                f"archived_v{previous.key_version}_{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
                ".public.json"
            )
            _atomic_write_file(
                self._keys_dir / archive_name,
                orjson.dumps(
                    retired_bundle.model_dump(mode="json"),
                    option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS,
                ),
                mode=0o644,
            )
        elif self.public_path.is_file():
            prev_pub = PublicIdentityBundle.model_validate(
                orjson.loads(self.public_path.read_bytes())
            )
            retired_bundle = prev_pub.model_copy(update={"retired_at_utc": datetime.now(UTC)})
            next_version = prev_pub.key_version + 1

        new_identity = self.generate(key_version=next_version)
        keyring = self._register_in_keyring(
            new_identity.public_bundle(),
            retired_previous=retired_bundle,
        )
        if sealer is not None:
            self.seal_identity(
                new_identity,
                sealer,
                remove_plaintext_secret=remove_plaintext_secret,
            )

        if metrics is not None:
            metrics.identity_key_rotations.labels(node_id=self._node_id).inc()

        logger.info(
            "device_identity_rotated",
            node_id=self._node_id,
            new_key_id=new_identity.key_id,
            new_version=new_identity.key_version,
            keyring_size=len(keyring.keys),
        )
        return new_identity, keyring

    def rotate(self) -> DeviceIdentity:
        """Rotate keys and return the newly active DeviceIdentity."""
        new_identity, _keyring = self.rotate_keys()
        return new_identity

    def generate_cbom(self, identity: DeviceIdentity) -> CBOMRecord:
        """Produce a structured Cryptographic Bill of Materials (CBOM) for auditing."""
        return CBOMRecord(
            node_id=identity.node_id,
            key_id=identity.key_id,
            key_version=identity.key_version,
            liboqs_version=str(oqs.oqs_version()),
            algorithms=[
                {
                    "role": "primary_digital_signature",
                    "algorithm": identity.primary_sig_alg,
                    "standard": "NIST FIPS 204",
                    "quantum_safe": True,
                    "public_key_bytes": len(identity.primary_sig_public),
                    "fingerprint_sha3_256": compute_key_fingerprint(identity.primary_sig_public),
                },
                {
                    "role": "stateless_hash_signature_fallback",
                    "algorithm": identity.fallback_sig_alg,
                    "standard": "NIST FIPS 205",
                    "quantum_safe": True,
                    "public_key_bytes": len(identity.fallback_sig_public),
                    "fingerprint_sha3_256": compute_key_fingerprint(identity.fallback_sig_public),
                },
                {
                    "role": "post_quantum_kem",
                    "algorithm": identity.kem_alg,
                    "standard": "NIST FIPS 203",
                    "quantum_safe": True,
                    "public_key_bytes": len(identity.kem_public),
                    "fingerprint_sha3_256": compute_key_fingerprint(identity.kem_public),
                },
                {
                    "role": "classical_hybrid_kex",
                    "algorithm": "X25519",
                    "standard": "RFC 7748",
                    "quantum_safe": False,
                    "public_key_bytes": len(identity.x25519_public_bytes),
                    "fingerprint_sha3_256": compute_key_fingerprint(identity.x25519_public_bytes),
                },
                {
                    "role": "symmetric_aead",
                    "algorithm": "AES-256-GCM",
                    "standard": "NIST SP 800-38D",
                    "quantum_safe": True,
                    "key_bits": 256,
                },
                {
                    "role": "key_derivation",
                    "algorithm": "HKDF-SHA384",
                    "standard": "RFC 5869 / FIPS 180-4",
                    "quantum_safe": True,
                    "output_bits": 256,
                },
            ],
        )

    def generate_cyclonedx_cbom(self, identity: DeviceIdentity) -> dict[str, Any]:
        """Export a standards-compliant CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)."""
        cbom = self.generate_cbom(identity)
        components: list[dict[str, Any]] = []
        for idx, alg in enumerate(cbom.algorithms, start=1):
            alg_name = str(alg["algorithm"])
            oid, nist_level = _ALGORITHM_OIDS.get(alg_name, ("1.3.6.1.4.1.0", 0))
            primitive = (
                "signature"
                if "signature" in str(alg["role"])
                else "kem"
                if "kem" in str(alg["role"])
                else "key-agree"
                if "kex" in str(alg["role"])
                else "ae"
                if "aead" in str(alg["role"])
                else "kdf"
            )
            props: list[dict[str, str]] = [
                {"name": "qaegis:role", "value": str(alg["role"])},
                {"name": "qaegis:standard", "value": str(alg["standard"])},
                {"name": "qaegis:quantum_safe", "value": str(alg["quantum_safe"]).lower()},
            ]
            if "public_key_bytes" in alg:
                props.append(
                    {"name": "qaegis:public_key_bytes", "value": str(alg["public_key_bytes"])}
                )
            if "fingerprint_sha3_256" in alg:
                props.append(
                    {
                        "name": "qaegis:fingerprint_sha3_256",
                        "value": str(alg["fingerprint_sha3_256"]),
                    }
                )
            components.append(
                {
                    "type": "cryptographic-asset",
                    "bom-ref": f"crypto-{idx}-{alg_name.lower()}",
                    "name": alg_name,
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "oid": oid,
                        "algorithmProperties": {
                            "primitive": primitive,
                            "nistQuantumSecurityLevel": nist_level,
                        },
                    },
                    "properties": props,
                }
            )

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": identity.key_version,
            "metadata": {
                "timestamp": datetime.now(UTC).isoformat(),
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "qaegis",
                            "version": __version__,
                        }
                    ]
                },
                "component": {
                    "type": "device",
                    "name": identity.node_id,
                    "version": f"key-v{identity.key_version}",
                    "properties": [
                        {"name": "qaegis:key_id", "value": identity.key_id},
                        {"name": "qaegis:liboqs_version", "value": cbom.liboqs_version},
                    ],
                },
            },
            "components": components,
        }
