"""Integration tests for `QAegisClient` SDK and CLI file signing, encryption & config bootstrap."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from qaegis import QAegisClient
from qaegis.cli import app
from qaegis.modules.chameleon_fw.features import ThreatTier
from qaegis.modules.reality_stamp.signer import sign_artifact_bytes, verify_artifact_bytes


@pytest.mark.integration
async def test_qaegis_client_sdk_end_to_end(tmp_path: Path) -> None:
    """Verify high-level `QAegisClient` across stamping, file signing, encryption, AI & QAOA."""
    unstarted = QAegisClient(tmp_path / "unstarted_ws")
    with pytest.raises(RuntimeError, match="not started"):
        _ = unstarted.identity

    async with QAegisClient(tmp_path / "sdk_ws", strict_nist_checks=False) as client:
        assert client.config.node_id == "qaegis-edge-01"
        assert client.public_bundle.key_version == 1

        # 1. Perception stamp + historical keyring verification
        stamp = await client.stamp(
            "cam-sdk-01",
            "obstacle_person",
            confidence=0.96,
            metadata={"bbox": [12, 20, 120, 240]},
        )
        ver_stamp = client.verify_stamp(stamp)
        assert ver_stamp.valid is True
        assert ver_stamp.merkle_proof_ok is True

        # 2. Detached file signing (ML-DSA-65) + tamper rejection
        model_file = tmp_path / "encoder_weights.onnx"
        model_file.write_bytes(b"real-binary-model-payload-" * 256)
        sig_bundle = await client.sign_file(model_file, annotations={"release": "0.7.0"})
        ver_file_ok = client.verify_file(model_file, sig_bundle)
        assert ver_file_ok.valid is True
        assert ver_file_ok.digest_ok is True

        tampered_file = tmp_path / "encoder_weights_tampered.onnx"
        tampered_file.write_bytes(model_file.read_bytes() + b"\x00")
        ver_file_bad = client.verify_file(tampered_file, sig_bundle)
        assert ver_file_bad.valid is False
        assert ver_file_bad.size_ok is False

        # Stateless SLH-DSA in-memory signing check
        slh_bundle = sign_artifact_bytes(
            b"critical-firmware-image",
            client.identity,
            artifact_name="fw.bin",
            use_stateless_hash_sig=True,
        )
        assert verify_artifact_bytes(
            b"critical-firmware-image", slh_bundle, keyring=client.keyring
        ).valid

        # 3. Direct hybrid encryption + adaptive AI firewall protection
        secret_bytes = b"master-api-secret-key-2026"
        env = client.encrypt(secret_bytes, tier=ThreatTier.QUANTUM_CRITICAL)
        assert client.decrypt(env, use_local_keyring=True) == secret_bytes

        protected = await client.protect(
            b"satellite-nav-telemetry",
            protocol="satellite",
            sensitivity="top_secret",
            retention_years=15.0,
        )
        assert protected.envelope.tier == ThreatTier.QUANTUM_CRITICAL
        assert client.decrypt(protected.envelope, use_local_keyring=True) == (
            b"satellite-nav-telemetry"
        )

        # 4. Tensor -> OpenQASM 3.0 + PennyLane compilation
        angles, circuit, pl = await client.compile_tensor([0.3, -0.5, 0.8, 0.1], run_pennylane=True)
        assert angles.num_qubits == client.config.qubit_compiler.default_num_qubits
        assert "OPENQASM 3.0" in circuit.openqasm3
        assert pl is not None

        # 5. QAOA Max-Cut + Quantum Random Bytes
        sol = await client.solve_maxcut(
            3,
            [(0, 1, 1.0), (1, 2, 1.0), (0, 2, 1.0)],
            backend="aer_statevector",
        )
        assert sol.approximation_ratio is not None and sol.approximation_ratio >= 0.99

        batch = await client.harvest_entropy(num_qubits=4, shots=128)
        assert batch.pool_bytes >= 32
        rnd = await client.random_bytes(48)
        assert len(rnd) == 48


@pytest.mark.integration
def test_cli_init_config_sign_verify_encrypt_decrypt_and_cbom(tmp_path: Path) -> None:
    """Verify CLI `init-config`, `cbom`, `sign-file`, `verify-file`, `encrypt`, and `decrypt`."""
    runner = CliRunner()

    # 1. init-config profiles + overwrite guard
    for profile in ("developer", "edge", "fleet", "airgap"):
        out_cfg = tmp_path / f"cfg_{profile}.yaml"
        r = runner.invoke(app, ["init-config", "--profile", profile, "-o", str(out_cfg)])
        assert r.exit_code == 0, r.stdout
        assert out_cfg.is_file()

    dup = runner.invoke(app, ["init-config", "-o", str(tmp_path / "cfg_developer.yaml")])
    assert dup.exit_code == 2
    bad_prof = runner.invoke(
        app, ["init-config", "--profile", "nonexistent", "-o", str(tmp_path / "bad.yaml")]
    )
    assert bad_prof.exit_code == 2

    # Prepare isolated node A and node B configs
    cfg_a = tmp_path / "node_a.yaml"
    cfg_b = tmp_path / "node_b.yaml"
    for path_cfg, nid, sub in ((cfg_a, "node-a", "a"), (cfg_b, "node-b", "b")):
        path_cfg.write_text(
            yaml.safe_dump(
                {
                    "node_id": nid,
                    "data_dir": str(tmp_path / sub / "data"),
                    "keys_dir": str(tmp_path / sub / "keys"),
                    "db_path": str(tmp_path / sub / "data" / "qaegis.db"),
                    "reality_stamp": {"strict_nist_checks": False},
                }
            ),
            encoding="utf-8",
        )

    # 2. Pure JSON stdout check on `qaegis cbom` (even when generating keys on first run)
    cbom_res = runner.invoke(app, ["cbom", "--format", "cyclonedx", "-c", str(cfg_a)])
    assert cbom_res.exit_code == 0, cbom_res.stdout
    cbom_json = json.loads(cbom_res.stdout)
    assert cbom_json["bomFormat"] == "CycloneDX"
    assert cbom_json["specVersion"] == "1.6"

    assert runner.invoke(app, ["init-identity", "-c", str(cfg_b)]).exit_code == 0

    # 3. sign-file -> rotate-keys -> verify-file against historical keyring + tamper failure
    artifact = tmp_path / "release_archive.bin"
    artifact.write_bytes(b"post-quantum-signed-release-v0.7.0\n" * 64)
    sig_path = tmp_path / "release_archive.bin.sig.json"

    r_sign = runner.invoke(app, ["sign-file", str(artifact), "-o", str(sig_path), "-c", str(cfg_a)])
    assert r_sign.exit_code == 0, r_sign.stdout

    # Rotate keys on node A from v1 -> v2; v1 signature must still verify via keyring.json
    assert runner.invoke(app, ["rotate-keys", "-c", str(cfg_a)]).exit_code == 0
    keyring_a = tmp_path / "a" / "keys" / "keyring.json"
    r_ver = runner.invoke(
        app,
        ["verify-file", str(artifact), str(sig_path), "--keyring", str(keyring_a)],
    )
    assert r_ver.exit_code == 0, r_ver.stdout

    tampered = tmp_path / "tampered_archive.bin"
    tampered.write_bytes(artifact.read_bytes()[:-1] + b"X")
    r_ver_bad = runner.invoke(
        app,
        ["verify-file", str(tampered), str(sig_path), "--keyring", str(keyring_a)],
    )
    assert r_ver_bad.exit_code == 1

    # 4. Cross-node hybrid post-quantum file encryption (Node A -> Node B) & decryption
    pub_b = tmp_path / "b" / "keys" / "device_identity.public.json"
    enc_file = tmp_path / "secret.enc.json"
    dec_file = tmp_path / "secret.dec.bin"

    r_enc = runner.invoke(
        app,
        [
            "encrypt",
            str(artifact),
            "-o",
            str(enc_file),
            "--recipient",
            str(pub_b),
            "--tier",
            "QUANTUM_CRITICAL",
            "-c",
            str(cfg_a),
        ],
    )
    assert r_enc.exit_code == 0, r_enc.stdout

    r_dec = runner.invoke(
        app,
        [
            "decrypt",
            str(enc_file),
            "-o",
            str(dec_file),
            "--keyring",
            str(keyring_a),
            "-c",
            str(cfg_b),
        ],
    )
    assert r_dec.exit_code == 0, r_dec.stdout
    assert dec_file.read_bytes() == artifact.read_bytes()

    # 5. CLI defensive error-handling paths
    assert runner.invoke(app, ["sign-file", str(tmp_path / "missing.bin")]).exit_code == 2
    assert (
        runner.invoke(app, ["verify-file", str(tmp_path / "missing.bin"), str(sig_path)]).exit_code
        == 2
    )
    assert (
        runner.invoke(app, ["verify-file", str(artifact), str(tmp_path / "missing.sig")]).exit_code
        == 2
    )
    assert (
        runner.invoke(
            app,
            [
                "verify-file",
                str(artifact),
                str(sig_path),
                "--keyring",
                str(tmp_path / "missing_kr.json"),
            ],
        ).exit_code
        == 2
    )
    assert (
        runner.invoke(
            app, ["encrypt", str(tmp_path / "missing.bin"), "-o", str(enc_file)]
        ).exit_code
        == 2
    )
    assert (
        runner.invoke(
            app, ["encrypt", str(artifact), "-o", str(enc_file), "--tier", "INVALID_TIER"]
        ).exit_code
        == 2
    )
    assert (
        runner.invoke(
            app,
            [
                "encrypt",
                str(artifact),
                "-o",
                str(enc_file),
                "--recipient",
                str(tmp_path / "missing_pub.json"),
                "-c",
                str(cfg_a),
            ],
        ).exit_code
        == 2
    )
    assert (
        runner.invoke(
            app, ["decrypt", str(tmp_path / "missing.enc"), "-o", str(dec_file)]
        ).exit_code
        == 2
    )


@pytest.mark.unit
async def test_lazy_exports_and_sdk_guard_branches(tmp_path: Path) -> None:
    """Cover PEP 562 package exports, unstarted SDK guards, and artifact edge-case checks."""
    import qaegis
    import qaegis.modules.chameleon_fw as cham_pkg
    import qaegis.modules.reality_stamp as rs_pkg
    from qaegis.core.config import QAegisConfig, RealityStampConfig
    from qaegis.core.identity import TrustKeyring

    # PEP 562 lazy exports + AttributeError paths
    assert qaegis.QAegisClient is QAegisClient
    with pytest.raises(AttributeError):
        _ = qaegis.NonExistentSymbol  # type: ignore[attr-defined]

    assert cham_pkg.AdaptiveThreatDetector is not None
    assert cham_pkg.ChameleonFirewallService is not None
    with pytest.raises(AttributeError):
        _ = cham_pkg.NonExistentSymbol  # type: ignore[attr-defined]

    assert rs_pkg.validate_entropy_batch is not None
    assert rs_pkg.MultiSourceQrng is not None
    assert rs_pkg.RealityStampService is not None
    with pytest.raises(AttributeError):
        _ = rs_pkg.NonExistentSymbol  # type: ignore[attr-defined]

    # Unstarted SDK guard checks
    unstarted = QAegisClient(tmp_path / "guards")
    await unstarted.close()  # idempotent when unstarted
    with pytest.raises(RuntimeError, match="not started"):
        await unstarted.stamp("s", "lbl")
    with pytest.raises(RuntimeError, match="not started"):
        await unstarted.sign_file(tmp_path / "f")
    with pytest.raises(RuntimeError, match="not started"):
        unstarted.encrypt(b"x")
    with pytest.raises(RuntimeError, match="not started"):
        await unstarted.protect(b"x")
    with pytest.raises(RuntimeError, match="not started"):
        await unstarted.compile_tensor([0.1])
    with pytest.raises(RuntimeError, match="not started"):
        await unstarted.random_bytes(8)
    with pytest.raises(RuntimeError, match="not started"):
        await unstarted.harvest_entropy()

    # Explicit config & config_path constructors + auto-harvest on random_bytes()
    explicit_cfg = QAegisConfig(
        data_dir=tmp_path / "exp" / "data",
        keys_dir=tmp_path / "exp" / "keys",
        db_path=tmp_path / "exp" / "data" / "q.db",
        reality_stamp=RealityStampConfig(strict_nist_checks=False),
    )
    cfg_file = tmp_path / "sdk_cfg.yaml"
    cfg_file.write_text(
        yaml.safe_dump(
            {
                "data_dir": str(tmp_path / "from_file" / "data"),
                "keys_dir": str(tmp_path / "from_file" / "keys"),
                "db_path": str(tmp_path / "from_file" / "data" / "q.db"),
                "reality_stamp": {"strict_nist_checks": False},
            }
        ),
        encoding="utf-8",
    )
    _from_file = QAegisClient(config_path=cfg_file)
    assert _from_file.config.data_dir == tmp_path / "from_file" / "data"

    async with QAegisClient(config=explicit_cfg) as started:
        await started.start()  # idempotent second start
        # Triggers lazy pool harvest inside random_bytes() when _pool is None
        rb = await started.random_bytes(16)
        assert len(rb) == 16

        # Artifact verification edge cases: expected fingerprint mismatch, empty keyring, bad base64
        bundle = sign_artifact_bytes(b"payload", started.identity, artifact_name="p.bin")
        bad_fp = verify_artifact_bytes(b"payload", bundle, expected_public_key_fingerprint="0" * 64)
        assert bad_fp.valid is False
        assert bad_fp.fingerprint_ok is False

        empty_kr = TrustKeyring(node_id="other", current_version=99, current_key_id="kid-other")
        missing_kr = verify_artifact_bytes(b"payload", bundle, keyring=empty_kr)
        assert missing_kr.valid is False
        assert missing_kr.error is not None and "not found in TrustKeyring" in missing_kr.error

        bad_b64_bundle = bundle.model_copy(update={"public_key_b64": "%%%not-base64%%%"})
        bad_b64 = verify_artifact_bytes(b"payload", bad_b64_bundle)
        assert bad_b64.valid is False
        assert bad_b64.error is not None and "base64" in bad_b64.error.lower()
