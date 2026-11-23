"""Hardware-backed key sealing for PQC identities via PKCS#11 (HSM/SoftHSM2) and Linux TPM 2.0."""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import pkcs11
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pydantic import BaseModel, Field

from qaegis.core.telemetry import get_logger

logger = get_logger(__name__)

_DEFAULT_PKCS11_PATHS: tuple[str, ...] = (
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
)

# Cache initialized pkcs11 dynamic library handles per shared object path
_PKCS11_LIB_CACHE: dict[str, Any] = {}


class HardwareSealerUnavailableError(RuntimeError):
    """Raised when a requested hardware security module (TPM 2.0 or PKCS#11) is unavailable."""


class SealedBlob(BaseModel):
    """Authenticated hardware-sealed key envelope (envelope encryption: HSM/TPM KEK + AES-GCM)."""

    version: str = "1.0"
    backend: str
    key_label: str
    sealed_at_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    wrapped_dek_b64: str
    kek_iv_b64: str
    gcm_nonce_b64: str
    ciphertext_b64: str
    aad_b64: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


@runtime_checkable
class HardwareSealer(Protocol):
    """Pluggable protocol for sealing and unsealing PQC secret key material in hardware."""

    @property
    def backend_name(self) -> str: ...

    def is_available(self) -> bool: ...

    def seal(self, plaintext: bytes, associated_data: bytes = b"") -> SealedBlob: ...

    def unseal(self, blob: SealedBlob, associated_data: bytes = b"") -> bytes: ...


def detect_pkcs11_library(explicit_path: str | Path | None = None) -> Path | None:
    """Locate an installed PKCS#11 shared library (e.g. SoftHSM2 or hardware HSM module)."""
    if explicit_path is not None:
        candidate = Path(explicit_path)
        return candidate if candidate.is_file() else None
    env_lib = os.environ.get("QAEGIS_PKCS11_LIBRARY")
    if env_lib:
        candidate = Path(env_lib)
        if candidate.is_file():
            return candidate
    for path_str in _DEFAULT_PKCS11_PATHS:
        candidate = Path(path_str)
        if candidate.is_file():
            return candidate
    return None


def _get_pkcs11_lib(library_path: Path) -> Any:
    key = str(library_path.resolve())
    lib = _PKCS11_LIB_CACHE.get(key)
    if lib is None:
        lib = pkcs11.lib(key)
        _PKCS11_LIB_CACHE[key] = lib
    return lib


class PKCS11Sealer:
    """Real PKCS#11 HSM / SoftHSM2 sealer using non-extractable AES-256 wrapping keys."""

    def __init__(
        self,
        token_label: str = "qaegis",  # noqa: S107
        user_pin: str | None = None,
        key_label: str = "qaegis-pqc-kek",
        library_path: str | Path | None = None,
    ) -> None:
        self._token_label = token_label
        self._user_pin = (
            user_pin if user_pin is not None else os.environ.get("QAEGIS_PKCS11_PIN", "")
        )
        self._key_label = key_label
        self._library_path = detect_pkcs11_library(library_path)

    @property
    def backend_name(self) -> str:
        return "pkcs11"

    @property
    def library_path(self) -> Path | None:
        return self._library_path

    def is_available(self) -> bool:
        """Return True if the PKCS#11 shared library exists and the target token is accessible."""
        if self._library_path is None or not self._library_path.is_file():
            return False
        try:
            lib = _get_pkcs11_lib(self._library_path)
            lib.get_token(token_label=self._token_label)
            return True
        except Exception:
            return False

    def list_slots(self) -> list[dict[str, Any]]:
        """Enumerate initialized PKCS#11 slots/tokens for `qaegis doctor` diagnostics."""
        if self._library_path is None or not self._library_path.is_file():
            return []
        lib = _get_pkcs11_lib(self._library_path)
        slots_info: list[dict[str, Any]] = []
        for slot in lib.get_slots(token_present=True):
            tok = slot.get_token()
            slots_info.append(
                {
                    "slot_id": int(slot.slot_id),
                    "label": str(tok.label).strip(),
                    "manufacturer": str(tok.manufacturer_id).strip(),
                    "serial": str(tok.serial).strip(),
                }
            )
        return slots_info

    def _get_or_create_kek(self, session: Any) -> Any:
        existing = list(
            session.get_objects(
                {
                    Attribute.CLASS: ObjectClass.SECRET_KEY,
                    Attribute.KEY_TYPE: KeyType.AES,
                    Attribute.LABEL: self._key_label,
                }
            )
        )
        if existing:
            return existing[0]
        return session.generate_key(
            KeyType.AES,
            256,
            label=self._key_label,
            store=True,
            template={
                Attribute.EXTRACTABLE: False,
                Attribute.SENSITIVE: True,
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
            },
        )

    def seal(self, plaintext: bytes, associated_data: bytes = b"") -> SealedBlob:
        """Seal `plaintext` with an ephemeral AES-256-GCM DEK wrapped by the HSM AES-256 KEK."""
        if self._library_path is None:
            raise HardwareSealerUnavailableError("No PKCS#11 shared library found on host")
        lib = _get_pkcs11_lib(self._library_path)
        token = lib.get_token(token_label=self._token_label)

        dek = os.urandom(32)
        kek_iv = os.urandom(16)
        with token.open(rw=True, user_pin=self._user_pin) as session:
            kek = self._get_or_create_kek(session)
            wrapped_dek: bytes = bytes(
                kek.encrypt(dek, mechanism=Mechanism.AES_CBC_PAD, mechanism_param=kek_iv)
            )

        gcm_nonce = os.urandom(12)
        bound_aad = associated_data + b"|pkcs11|" + wrapped_dek + kek_iv
        ciphertext = AESGCM(dek).encrypt(gcm_nonce, plaintext, bound_aad)

        logger.info(
            "identity_sealed_pkcs11",
            token_label=self._token_label,
            key_label=self._key_label,
        )
        return SealedBlob(
            backend=self.backend_name,
            key_label=self._key_label,
            wrapped_dek_b64=base64.b64encode(wrapped_dek).decode("ascii"),
            kek_iv_b64=base64.b64encode(kek_iv).decode("ascii"),
            gcm_nonce_b64=base64.b64encode(gcm_nonce).decode("ascii"),
            ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
            aad_b64=base64.b64encode(associated_data).decode("ascii"),
            metadata={"token_label": self._token_label},
        )

    def unseal(self, blob: SealedBlob, associated_data: bytes = b"") -> bytes:
        """Unwrap the DEK inside the PKCS#11 token and decrypt/authenticate the PQC secret blob."""
        if blob.backend != self.backend_name:
            raise ValueError(f"Expected pkcs11 sealed blob, got '{blob.backend}'")
        if self._library_path is None:
            raise HardwareSealerUnavailableError("No PKCS#11 shared library found on host")

        lib = _get_pkcs11_lib(self._library_path)
        token_label = str(blob.metadata.get("token_label", self._token_label))
        token = lib.get_token(token_label=token_label)

        wrapped_dek = base64.b64decode(blob.wrapped_dek_b64)
        kek_iv = base64.b64decode(blob.kek_iv_b64)
        with token.open(rw=False, user_pin=self._user_pin) as session:
            matches = list(
                session.get_objects(
                    {
                        Attribute.CLASS: ObjectClass.SECRET_KEY,
                        Attribute.KEY_TYPE: KeyType.AES,
                        Attribute.LABEL: blob.key_label,
                    }
                )
            )
            if not matches:
                raise KeyError(f"PKCS#11 KEK '{blob.key_label}' not found in token '{token_label}'")
            dek: bytes = bytes(
                matches[0].decrypt(
                    wrapped_dek,
                    mechanism=Mechanism.AES_CBC_PAD,
                    mechanism_param=kek_iv,
                )
            )

        gcm_nonce = base64.b64decode(blob.gcm_nonce_b64)
        ciphertext = base64.b64decode(blob.ciphertext_b64)
        effective_aad = associated_data if associated_data else base64.b64decode(blob.aad_b64)
        bound_aad = effective_aad + b"|pkcs11|" + wrapped_dek + kek_iv
        return AESGCM(dek).decrypt(gcm_nonce, ciphertext, bound_aad)


class TPM2Sealer:
    """Real Linux TPM 2.0 sealer invoking `tpm2-tools` with PCR-bound sealing on `/dev/tpmrm0`."""

    REQUIRED_BINARIES: tuple[str, ...] = (
        "tpm2_createprimary",
        "tpm2_create",
        "tpm2_load",
        "tpm2_unseal",
    )

    def __init__(
        self,
        device_path: Path = Path("/dev/tpmrm0"),
        pcr_spec: str = "sha256:0,7",
        key_label: str = "qaegis-tpm2-kek",
    ) -> None:
        self._device_path = device_path
        self._pcr_spec = pcr_spec
        self._key_label = key_label

    @property
    def backend_name(self) -> str:
        return "tpm2"

    @property
    def device_path(self) -> Path:
        return self._device_path

    @property
    def pcr_spec(self) -> str:
        return self._pcr_spec

    def tools_installed(self) -> bool:
        """Return True if all required `tpm2-tools` CLI binaries are installed."""
        return all(shutil.which(binary) is not None for binary in self.REQUIRED_BINARIES)

    def is_available(self) -> bool:
        """Return True if `/dev/tpmrm0` (or configured TPM device) and `tpm2-tools` exist."""
        return self._device_path.exists() and self.tools_installed()

    def build_seal_commands(
        self,
        work_dir: Path,
        secret_in: Path,
    ) -> list[list[str]]:
        """Construct the exact `tpm2-tools` command pipeline for PCR-bound DEK sealing."""
        tcti = f"device:{self._device_path}"
        primary_ctx = work_dir / "primary.ctx"
        policy_digest = work_dir / "pcr.policy"
        pub_out = work_dir / "sealed.pub"
        priv_out = work_dir / "sealed.priv"

        return [
            [
                "tpm2_createprimary",
                "-T",
                tcti,
                "-C",
                "o",
                "-g",
                "sha256",
                "-G",
                "rsa",
                "-c",
                str(primary_ctx),
            ],
            [
                "tpm2_createpolicy",
                "-T",
                tcti,
                "--policy-pcr",
                "-l",
                self._pcr_spec,
                "-L",
                str(policy_digest),
            ],
            [
                "tpm2_create",
                "-T",
                tcti,
                "-C",
                str(primary_ctx),
                "-L",
                str(policy_digest),
                "-i",
                str(secret_in),
                "-u",
                str(pub_out),
                "-r",
                str(priv_out),
            ],
        ]

    def build_unseal_commands(
        self,
        work_dir: Path,
        pub_in: Path,
        priv_in: Path,
        secret_out: Path,
    ) -> list[list[str]]:
        """Construct the exact `tpm2-tools` command pipeline for PCR-bound DEK unsealing."""
        tcti = f"device:{self._device_path}"
        primary_ctx = work_dir / "primary.ctx"
        loaded_ctx = work_dir / "sealed.ctx"
        return [
            [
                "tpm2_createprimary",
                "-T",
                tcti,
                "-C",
                "o",
                "-g",
                "sha256",
                "-G",
                "rsa",
                "-c",
                str(primary_ctx),
            ],
            [
                "tpm2_load",
                "-T",
                tcti,
                "-C",
                str(primary_ctx),
                "-u",
                str(pub_in),
                "-r",
                str(priv_in),
                "-c",
                str(loaded_ctx),
            ],
            [
                "tpm2_unseal",
                "-T",
                tcti,
                "-c",
                str(loaded_ctx),
                "-p",
                f"pcr:{self._pcr_spec}",
                "-o",
                str(secret_out),
            ],
        ]

    def seal(self, plaintext: bytes, associated_data: bytes = b"") -> SealedBlob:
        """Seal `plaintext` by binding an ephemeral 32-byte AES-GCM DEK to TPM 2.0 PCRs."""
        if not self.is_available():
            raise HardwareSealerUnavailableError(
                f"TPM 2.0 sealing unavailable: device={self._device_path} "
                f"(exists={self._device_path.exists()}), tools_installed={self.tools_installed()}"
            )
        dek = os.urandom(32)
        with tempfile.TemporaryDirectory(prefix="qaegis-tpm2-") as td:
            work_dir = Path(td)
            secret_in = work_dir / "dek.bin"
            secret_in.write_bytes(dek)
            os.chmod(secret_in, 0o600)

            for cmd in self.build_seal_commands(work_dir, secret_in):
                subprocess.run(cmd, check=True, capture_output=True)  # noqa: S603

            pub_bytes = (work_dir / "sealed.pub").read_bytes()
            priv_bytes = (work_dir / "sealed.priv").read_bytes()

        gcm_nonce = os.urandom(12)
        bound_aad = associated_data + b"|tpm2|" + pub_bytes + priv_bytes
        ciphertext = AESGCM(dek).encrypt(gcm_nonce, plaintext, bound_aad)

        return SealedBlob(
            backend=self.backend_name,
            key_label=self._key_label,
            wrapped_dek_b64=base64.b64encode(priv_bytes).decode("ascii"),
            kek_iv_b64=base64.b64encode(pub_bytes).decode("ascii"),
            gcm_nonce_b64=base64.b64encode(gcm_nonce).decode("ascii"),
            ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
            aad_b64=base64.b64encode(associated_data).decode("ascii"),
            metadata={"pcr_spec": self._pcr_spec, "device": str(self._device_path)},
        )

    def unseal(self, blob: SealedBlob, associated_data: bytes = b"") -> bytes:
        """Unseal the TPM 2.0 PCR-bound DEK and decrypt/authenticate the PQC secret blob."""
        if blob.backend != self.backend_name:
            raise ValueError(f"Expected tpm2 sealed blob, got '{blob.backend}'")
        if not self.is_available():
            raise HardwareSealerUnavailableError(
                f"TPM 2.0 unsealing unavailable on {self._device_path}"
            )
        priv_bytes = base64.b64decode(blob.wrapped_dek_b64)
        pub_bytes = base64.b64decode(blob.kek_iv_b64)

        with tempfile.TemporaryDirectory(prefix="qaegis-tpm2-") as td:
            work_dir = Path(td)
            pub_in = work_dir / "sealed.pub"
            priv_in = work_dir / "sealed.priv"
            secret_out = work_dir / "dek.out"
            pub_in.write_bytes(pub_bytes)
            priv_in.write_bytes(priv_bytes)

            for cmd in self.build_unseal_commands(work_dir, pub_in, priv_in, secret_out):
                subprocess.run(cmd, check=True, capture_output=True)  # noqa: S603
            dek = secret_out.read_bytes()

        gcm_nonce = base64.b64decode(blob.gcm_nonce_b64)
        ciphertext = base64.b64decode(blob.ciphertext_b64)
        effective_aad = associated_data if associated_data else base64.b64decode(blob.aad_b64)
        bound_aad = effective_aad + b"|tpm2|" + pub_bytes + priv_bytes
        return AESGCM(dek).decrypt(gcm_nonce, ciphertext, bound_aad)
