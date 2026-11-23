"""Real PKCS#11 (SoftHSM2) and Linux TPM 2.0 hardware key sealing tests."""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from typer.testing import CliRunner

from qaegis.cli import app
from qaegis.core.config import QAegisConfig
from qaegis.core.hardware_seal import (
    HardwareSealerUnavailableError,
    PKCS11Sealer,
    TPM2Sealer,
    detect_pkcs11_library,
)
from qaegis.core.identity import DeviceIdentity, IdentityManager, constant_time_equal


@pytest.fixture(scope="module")
def softhsm2_token(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, str, str]:
    """Initialize a real isolated SoftHSM2 token for C-level PKCS#11 sealing tests."""
    lib_path = detect_pkcs11_library()
    softhsm_bin = shutil.which("softhsm2-util")
    if lib_path is None or softhsm_bin is None:
        pytest.skip("SoftHSM2 is not installed on this host")

    base_dir = tmp_path_factory.mktemp("softhsm2_env")
    token_dir = base_dir / "tokens"
    token_dir.mkdir(mode=0o700)
    conf_path = base_dir / "softhsm2.conf"
    conf_path.write_text(
        f"directories.tokendir = {token_dir}\nobjectstore.backend = file\nlog.level = ERROR\n",
        encoding="utf-8",
    )

    token_label = "qaegis-pytest-hsm"
    user_pin = "5678"
    env = {**os.environ, "SOFTHSM2_CONF": str(conf_path)}
    subprocess.run(  # noqa: S603
        [
            softhsm_bin,
            "--init-token",
            "--free",
            "--label",
            token_label,
            "--so-pin",
            "1234",
            "--pin",
            user_pin,
        ],
        env=env,
        check=True,
        capture_output=True,
    )
    os.environ["SOFTHSM2_CONF"] = str(conf_path)
    return (lib_path, token_label, user_pin)


@pytest.mark.crypto
def test_pkcs11_softhsm2_pqc_identity_seal_unseal_and_tamper(
    softhsm2_token: tuple[Path, str, str],
    qaegis_config: QAegisConfig,
) -> None:
    lib_path, token_label, user_pin = softhsm2_token
    sealer = PKCS11Sealer(
        token_label=token_label,
        user_pin=user_pin,
        key_label="qaegis-test-kek",
        library_path=lib_path,
    )
    assert sealer.is_available() is True
    slots = sealer.list_slots()
    assert any(s["label"] == token_label for s in slots)

    mgr = IdentityManager(
        keys_dir=qaegis_config.keys_dir,
        node_id=qaegis_config.node_id,
        config=qaegis_config.identity,
    )
    original = mgr.generate()
    blob = mgr.seal_identity(original, sealer, remove_plaintext_secret=True)
    assert blob.backend == "pkcs11"
    assert not mgr.secret_path.exists()
    assert mgr.sealed_path.is_file()
    assert (mgr.sealed_path.stat().st_mode & 0o777) == 0o600

    # Unseal via real SoftHSM2 non-extractable AES-256 KEK and verify PQC signing still matches
    restored = mgr.load_sealed(sealer)
    assert restored.key_id == original.key_id
    assert constant_time_equal(restored.primary_sig_secret, original.primary_sig_secret)
    assert constant_time_equal(restored.kem_secret, original.kem_secret)

    msg = b"hardware-sealed-pqc-telemetry"
    alg, sig = restored.sign(msg)
    assert DeviceIdentity.verify(msg, sig, original.primary_sig_public, alg)

    # Tamper detection on sealed ciphertext must raise InvalidTag
    ct_raw = bytearray(base64.b64decode(blob.ciphertext_b64))
    ct_raw[0] ^= 0xFF
    tampered_blob = blob.model_copy(
        update={"ciphertext_b64": base64.b64encode(bytes(ct_raw)).decode("ascii")}
    )
    with pytest.raises(InvalidTag):
        sealer.unseal(tampered_blob)

    # Tamper detection on AAD must also raise InvalidTag
    with pytest.raises(InvalidTag):
        sealer.unseal(blob, associated_data=b"wrong-node-aad")


@pytest.mark.crypto
def test_cli_seal_identity_pkcs11(
    softhsm2_token: tuple[Path, str, str],
    tmp_path: Path,
) -> None:
    lib_path, token_label, user_pin = softhsm2_token
    cfg_file = tmp_path / "seal_cli.yaml"
    cfg_file.write_text(
        (
            f"node_id: hsm-cli-node\n"
            f"data_dir: {tmp_path}/data\n"
            f"keys_dir: {tmp_path}/keys\n"
            f"db_path: {tmp_path}/data/q.db\n"
        ),
        encoding="utf-8",
    )
    runner = CliRunner()
    res = runner.invoke(
        app,
        [
            "seal-identity",
            "--backend",
            "pkcs11",
            "--token-label",
            token_label,
            "--pin",
            user_pin,
            "--pkcs11-lib",
            str(lib_path),
            "--config",
            str(cfg_file),
        ],
    )
    assert res.exit_code == 0, res.output
    assert "Sealed identity" in res.output
    assert (tmp_path / "keys" / "device_identity.sealed.json").is_file()


@pytest.mark.crypto
def test_tpm2_sealer_commands_and_graceful_detection(tmp_path: Path) -> None:
    nonexistent_dev = tmp_path / "no_tpmrm0"
    tpm = TPM2Sealer(device_path=nonexistent_dev, pcr_spec="sha256:0,7")
    assert tpm.backend_name == "tpm2"
    assert tpm.is_available() is False

    seal_cmds = tpm.build_seal_commands(tmp_path, tmp_path / "dek.bin")
    assert len(seal_cmds) == 3
    assert seal_cmds[0][0] == "tpm2_createprimary"
    assert "sha256:0,7" in seal_cmds[1]
    assert seal_cmds[2][0] == "tpm2_create"

    unseal_cmds = tpm.build_unseal_commands(
        tmp_path,
        tmp_path / "sealed.pub",
        tmp_path / "sealed.priv",
        tmp_path / "dek.out",
    )
    assert len(unseal_cmds) == 3
    assert unseal_cmds[1][0] == "tpm2_load"
    assert unseal_cmds[2][0] == "tpm2_unseal"

    with pytest.raises(HardwareSealerUnavailableError):
        tpm.seal(b"secret-key-material")
