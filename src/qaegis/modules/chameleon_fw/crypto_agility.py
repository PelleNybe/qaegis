"""Dynamic Crypto-Agility Engine: Classical X25519 <-> Hybrid ML-KEM-768 + ML-DSA-65/SLH-DSA."""

from __future__ import annotations

import base64
import hashlib
import os
import time
import uuid
from collections import deque
from datetime import UTC, datetime

import oqs
import orjson
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import BaseModel, Field

from qaegis.core.config import ChameleonConfig
from qaegis.core.identity import (
    DeviceIdentity,
    PublicIdentityBundle,
    TrustKeyring,
    constant_time_equal,
    resolve_oqs_kem_algorithm,
)
from qaegis.core.telemetry import QAegisMetrics
from qaegis.modules.chameleon_fw.detector import ThreatTier

CIPHER_SUITES: dict[ThreatTier, str] = {
    ThreatTier.STANDARD: "X25519-HKDF-SHA384-AES256GCM",
    ThreatTier.ELEVATED: "HYBRID-X25519-MLKEM768-HKDF-SHA384-AES256GCM",
    ThreatTier.QUANTUM_CRITICAL: "HYBRID-X25519-MLKEM768-AES256GCM-PQC-SIGNED",
}


class EncryptedEnvelope(BaseModel):
    """Self-describing crypto-agile encrypted message envelope."""

    envelope_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    created_at_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tier: ThreatTier
    cipher_suite: str
    sender_node_id: str
    sender_key_id: str
    recipient_node_id: str
    recipient_key_id: str
    session_epoch: int = Field(ge=0)
    message_counter: int = Field(ge=0)
    ephemeral_x25519_pub_b64: str
    kem_alg: str | None = None
    kem_ciphertext_b64: str | None = None
    nonce_b64: str
    aad_b64: str
    ciphertext_b64: str
    sig_alg: str | None = None
    signature_b64: str | None = None
    sender_sig_pub_b64: str | None = None

    def signing_transcript(self) -> bytes:
        """Deterministic canonical transcript authenticated by PQC signature in CRITICAL tier."""
        doc = {
            "envelope_id": self.envelope_id,
            "created_at_utc": self.created_at_utc.isoformat(),
            "tier": self.tier.value,
            "cipher_suite": self.cipher_suite,
            "sender_node_id": self.sender_node_id,
            "sender_key_id": self.sender_key_id,
            "recipient_node_id": self.recipient_node_id,
            "recipient_key_id": self.recipient_key_id,
            "session_epoch": self.session_epoch,
            "message_counter": self.message_counter,
            "ephemeral_x25519_pub_b64": self.ephemeral_x25519_pub_b64,
            "kem_alg": self.kem_alg,
            "kem_ciphertext_b64": self.kem_ciphertext_b64,
            "nonce_b64": self.nonce_b64,
            "aad_b64": self.aad_b64,
            "ciphertext_b64": self.ciphertext_b64,
        }
        return orjson.dumps(doc, option=orjson.OPT_SORT_KEYS)


def _derive_aead_key(
    ikm: bytes,
    salt: bytes,
    tier: ThreatTier,
    session_epoch: int,
    message_counter: int,
) -> bytes:
    """Derive a 256-bit AES-GCM key using HKDF-SHA384 bound to tier and session epoch."""
    info = f"qaegis-chameleon-v1|{tier.value}|epoch={session_epoch}|ctr={message_counter}".encode()
    hkdf = HKDF(
        algorithm=hashes.SHA384(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)


class CryptoAgilityEngine:
    """Switches seamlessly between Classical, Hybrid ML-KEM-768, and PQC-Signed envelopes."""

    def __init__(
        self,
        identity: DeviceIdentity,
        config: ChameleonConfig | None = None,
        metrics: QAegisMetrics | None = None,
        enable_replay_protection: bool = True,
        replay_cache_size: int = 8192,
    ) -> None:
        self._identity = identity
        self._config = config or ChameleonConfig()
        self._metrics = metrics or QAegisMetrics()
        self._session_epoch = 0
        self._message_counter = 0
        self._enable_replay_protection = enable_replay_protection
        self._replay_cache_size = replay_cache_size
        self._seen_envelopes: set[str] = set()
        self._seen_envelope_order: deque[str] = deque()

    @property
    def session_epoch(self) -> int:
        return self._session_epoch

    @property
    def message_counter(self) -> int:
        return self._message_counter

    def _advance_counters(self, force_rekey: bool = False) -> tuple[int, int]:
        self._message_counter += 1
        if force_rekey or self._message_counter > self._config.rekey_after_messages:
            self._session_epoch += 1
            self._message_counter = 1
        return self._session_epoch, self._message_counter

    def encrypt(
        self,
        plaintext: bytes,
        recipient: PublicIdentityBundle,
        tier: ThreatTier,
        associated_data: bytes = b"",
        use_stateless_sig: bool = False,
    ) -> EncryptedEnvelope:
        """Encrypt `plaintext` for `recipient` using the cipher suite mandated by `tier`."""
        start = time.perf_counter()
        # QUANTUM_CRITICAL always forces fresh ephemeral forward-secret epoch rekeying
        epoch, counter = self._advance_counters(force_rekey=(tier == ThreatTier.QUANTUM_CRITICAL))

        # Ephemeral X25519 key agreement (present in all tiers for forward secrecy)
        eph_priv = X25519PrivateKey.generate()
        eph_pub_bytes = eph_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        recipient_x25519_pub = X25519PublicKey.from_public_bytes(
            base64.b64decode(recipient.x25519_public_b64)
        )
        ss_x25519 = eph_priv.exchange(recipient_x25519_pub)

        kem_alg: str | None = None
        kem_ct_bytes: bytes | None = None
        ikm = ss_x25519
        salt_input = eph_pub_bytes + base64.b64decode(recipient.x25519_public_b64)

        if tier in (ThreatTier.ELEVATED, ThreatTier.QUANTUM_CRITICAL):
            kem_alg = resolve_oqs_kem_algorithm(recipient.kem_alg)
            recipient_kem_pub = base64.b64decode(recipient.kem_public_b64)
            with oqs.KeyEncapsulation(kem_alg) as kem:
                kem_ct_bytes, ss_kem = kem.encap_secret(recipient_kem_pub)
            ikm = ss_x25519 + ss_kem
            salt_input += kem_ct_bytes

        salt = hashlib.sha384(salt_input).digest()
        aead_key = _derive_aead_key(ikm, salt, tier, epoch, counter)

        nonce = os.urandom(12)
        aad_suffix = (
            f"|{tier.value}|{self._identity.node_id}|{recipient.node_id}|{epoch}|{counter}"
        ).encode()
        bound_aad = associated_data + aad_suffix
        ciphertext = AESGCM(aead_key).encrypt(nonce, plaintext, bound_aad)

        envelope = EncryptedEnvelope(
            tier=tier,
            cipher_suite=CIPHER_SUITES[tier],
            sender_node_id=self._identity.node_id,
            sender_key_id=self._identity.key_id,
            recipient_node_id=recipient.node_id,
            recipient_key_id=recipient.key_id,
            session_epoch=epoch,
            message_counter=counter,
            ephemeral_x25519_pub_b64=base64.b64encode(eph_pub_bytes).decode("ascii"),
            kem_alg=kem_alg,
            kem_ciphertext_b64=(
                base64.b64encode(kem_ct_bytes).decode("ascii") if kem_ct_bytes is not None else None
            ),
            nonce_b64=base64.b64encode(nonce).decode("ascii"),
            aad_b64=base64.b64encode(associated_data).decode("ascii"),
            ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
        )

        if tier == ThreatTier.QUANTUM_CRITICAL:
            transcript = envelope.signing_transcript()
            sig_alg, signature = self._identity.sign(transcript, use_fallback=use_stateless_sig)
            sig_pub = (
                self._identity.fallback_sig_public
                if use_stateless_sig
                else self._identity.primary_sig_public
            )
            envelope = envelope.model_copy(
                update={
                    "sig_alg": sig_alg,
                    "signature_b64": base64.b64encode(signature).decode("ascii"),
                    "sender_sig_pub_b64": base64.b64encode(sig_pub).decode("ascii"),
                }
            )

        elapsed = time.perf_counter() - start
        self._metrics.crypto_op_latency_seconds.labels(
            operation="encrypt",
            algorithm=envelope.cipher_suite,
        ).observe(elapsed)
        return envelope

    def _check_and_record_replay(self, envelope: EncryptedEnvelope) -> None:
        replay_token = (
            f"{envelope.sender_node_id}|{envelope.envelope_id}|"
            f"{envelope.session_epoch}|{envelope.message_counter}"
        )
        if replay_token in self._seen_envelopes:
            raise ValueError(
                f"Replay attack detected: duplicate Chameleon envelope '{envelope.envelope_id}'"
            )
        self._seen_envelopes.add(replay_token)
        self._seen_envelope_order.append(replay_token)
        while len(self._seen_envelope_order) > self._replay_cache_size:
            evicted = self._seen_envelope_order.popleft()
            self._seen_envelopes.discard(evicted)

    def decrypt(
        self,
        envelope: EncryptedEnvelope,
        expected_sender: PublicIdentityBundle | None = None,
        expected_sender_keyring: TrustKeyring | None = None,
        verify_recipient: bool = True,
        allow_replay: bool = False,
    ) -> bytes:
        """Verify (if signed) and decrypt an `EncryptedEnvelope` using this node's identity."""
        start = time.perf_counter()

        expected_suite = CIPHER_SUITES[envelope.tier]
        if envelope.cipher_suite != expected_suite:
            raise ValueError(
                f"Cipher suite mismatch for tier {envelope.tier.value}: "
                f"expected '{expected_suite}', got '{envelope.cipher_suite}'"
            )

        if verify_recipient and envelope.recipient_node_id != self._identity.node_id:
            raise ValueError(
                f"Envelope addressed to '{envelope.recipient_node_id}', "
                f"not local node '{self._identity.node_id}'"
            )

        if envelope.tier == ThreatTier.QUANTUM_CRITICAL:
            if not (envelope.sig_alg and envelope.signature_b64 and envelope.sender_sig_pub_b64):
                raise ValueError("QUANTUM_CRITICAL envelope is missing mandatory PQC signature")
            sig_bytes = base64.b64decode(envelope.signature_b64)
            sig_pub = base64.b64decode(envelope.sender_sig_pub_b64)
            sender_bundle = expected_sender
            if sender_bundle is None and expected_sender_keyring is not None:
                sender_bundle = expected_sender_keyring.get_by_key_id(envelope.sender_key_id)
                if sender_bundle is None:
                    raise ValueError(
                        f"Sender key ID '{envelope.sender_key_id}' not found in trusted keyring"
                    )
            if sender_bundle is not None:
                allowed_pubs = (
                    base64.b64decode(sender_bundle.primary_sig_public_b64),
                    base64.b64decode(sender_bundle.fallback_sig_public_b64),
                )
                if not any(constant_time_equal(sig_pub, allowed) for allowed in allowed_pubs):
                    raise ValueError("Envelope signature public key does not match expected sender")
            if not DeviceIdentity.verify(
                envelope.signing_transcript(),
                sig_bytes,
                sig_pub,
                envelope.sig_alg,
            ):
                raise ValueError("PQC signature verification failed on QUANTUM_CRITICAL envelope")

        eph_pub_bytes = base64.b64decode(envelope.ephemeral_x25519_pub_b64)
        eph_pub = X25519PublicKey.from_public_bytes(eph_pub_bytes)
        ss_x25519 = self._identity.x25519_private.exchange(eph_pub)

        ikm = ss_x25519
        salt_input = eph_pub_bytes + self._identity.x25519_public_bytes

        if envelope.tier in (ThreatTier.ELEVATED, ThreatTier.QUANTUM_CRITICAL):
            if envelope.kem_ciphertext_b64 is None:
                raise ValueError(f"Tier {envelope.tier.value} requires ML-KEM ciphertext")
            kem_ct = base64.b64decode(envelope.kem_ciphertext_b64)
            ss_kem = self._identity.decap_kem(kem_ct)
            ikm = ss_x25519 + ss_kem
            salt_input += kem_ct

        salt = hashlib.sha384(salt_input).digest()
        aead_key = _derive_aead_key(
            ikm,
            salt,
            envelope.tier,
            envelope.session_epoch,
            envelope.message_counter,
        )

        nonce = base64.b64decode(envelope.nonce_b64)
        raw_aad = base64.b64decode(envelope.aad_b64)
        bound_aad = (
            raw_aad
            + (
                f"|{envelope.tier.value}|{envelope.sender_node_id}|"
                f"{envelope.recipient_node_id}|{envelope.session_epoch}|{envelope.message_counter}"
            ).encode()
        )
        ciphertext = base64.b64decode(envelope.ciphertext_b64)
        plaintext = AESGCM(aead_key).decrypt(nonce, ciphertext, bound_aad)

        # Record replay token only after full AEAD authentication succeeds
        if self._enable_replay_protection and not allow_replay:
            self._check_and_record_replay(envelope)

        elapsed = time.perf_counter() - start
        self._metrics.crypto_op_latency_seconds.labels(
            operation="decrypt",
            algorithm=envelope.cipher_suite,
        ).observe(elapsed)
        return plaintext
