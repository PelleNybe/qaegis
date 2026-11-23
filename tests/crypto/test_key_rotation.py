"""Tests for zero-downtime PQC key rotation, historical keyring verification, and CycloneDX CBOM."""

from __future__ import annotations

import json
import os
from pathlib import Path

import orjson
import pytest
from typer.testing import CliRunner

from qaegis.cli import app
from qaegis.core.bus import EventBus
from qaegis.core.config import QAegisConfig, RealityStampConfig
from qaegis.core.identity import IdentityManager, TrustKeyring
from qaegis.core.storage import StorageEngine
from qaegis.core.telemetry import QAegisMetrics
from qaegis.modules.reality_stamp.service import RealityStampService
from qaegis.modules.reality_stamp.signer import RealityStamp, verify_reality_stamp


@pytest.mark.crypto
async def test_zero_downtime_key_rotation_and_historical_stamp_verification(
    tmp_path: Path,
) -> None:
    cfg = QAegisConfig(
        node_id="edge-rotate-01",
        data_dir=tmp_path / "data",
        keys_dir=tmp_path / "keys",
        db_path=tmp_path / "data" / "rot.db",
        reality_stamp=RealityStampConfig(strict_nist_checks=False),
    )
    cfg.ensure_directories()
    metrics = QAegisMetrics()
    bus = EventBus(config=cfg.bus, metrics=metrics)
    storage = StorageEngine(cfg.db_path)
    await bus.start()
    await storage.initialize()

    mgr = IdentityManager(cfg.keys_dir, cfg.node_id, cfg.identity)
    id_v1 = mgr.generate()
    assert id_v1.key_version == 1

    try:
        # 1. Stamp telemetry using v1 key
        svc_v1 = RealityStampService(bus, id_v1, storage, cfg.reality_stamp, metrics=metrics)
        await svc_v1.start()
        stamp_v1 = await svc_v1.stamp_perception("cam0", "lane_clear", 0.96)
        assert stamp_v1.key_version == 1
        assert stamp_v1.key_id == id_v1.key_id
        await svc_v1.stop()

        # 2. Rotate keys -> v2, archiving v1 public key in keyring.json (0o600)
        id_v2, keyring = mgr.rotate_keys(metrics=metrics)
        assert id_v2.key_version == 2
        assert id_v2.key_id != id_v1.key_id
        assert (mgr.keyring_path.stat().st_mode & 0o777) == 0o600
        assert keyring.current_version == 2
        assert keyring.get_by_key_id(id_v1.key_id) is not None
        assert keyring.get_by_version(1) is not None
        assert keyring.get_by_version(2) is not None
        retired_v1 = keyring.get_by_key_id(id_v1.key_id)
        assert retired_v1 is not None and retired_v1.retired_at_utc is not None

        # Verify retired in-memory zeroization helper works cleanly
        id_v1.zeroize_secrets()
        assert id_v1.primary_sig_secret == b"\x00" * len(id_v1.primary_sig_secret)

        # 3. Stamp new telemetry using v2 key
        svc_v2 = RealityStampService(bus, id_v2, storage, cfg.reality_stamp, metrics=metrics)
        await svc_v2.start()
        stamp_v2 = await svc_v2.stamp_perception("cam0", "cyclist_ahead", 0.99)
        assert stamp_v2.key_version == 2
        await svc_v2.stop()

        # 4. Both v1 (pre-rotation) and v2 (post-rotation) stamps verify cleanly against keyring!
        loaded_keyring = mgr.load_keyring()
        ver_v1 = verify_reality_stamp(stamp_v1, keyring=loaded_keyring)
        ver_v2 = verify_reality_stamp(stamp_v2, keyring=loaded_keyring)
        assert ver_v1.valid is True
        assert ver_v2.valid is True

        # 5. Tampered v1 stamp fails verification
        bad_payload = stamp_v1.payload.model_copy(update={"perception_label": "spoofed"})
        bad_stamp = stamp_v1.model_copy(update={"payload": bad_payload})
        assert verify_reality_stamp(bad_stamp, keyring=loaded_keyring).valid is False

        # 6. Unknown key_id is rejected by keyring check
        unknown_stamp = stamp_v2.model_copy(update={"key_id": "kid-unknown", "key_version": 99})
        ver_unk = verify_reality_stamp(unknown_stamp, keyring=loaded_keyring)
        assert ver_unk.valid is False
        assert ver_unk.error is not None and "not found in keyring" in ver_unk.error

        # 7. Insecure keyring permissions rejected
        os.chmod(mgr.keyring_path, 0o644)
        with pytest.raises(PermissionError):
            mgr.load_keyring()
        os.chmod(mgr.keyring_path, 0o600)

        assert "qaegis_identity_key_rotations_total" in metrics.render_prometheus_text().decode(
            "utf-8"
        )
    finally:
        await storage.close()
        await bus.stop()


@pytest.mark.crypto
def test_cli_rotate_keys_verify_keyring_and_cyclonedx_cbom(tmp_path: Path) -> None:
    cfg_file = tmp_path / "rot_cli.yaml"
    cfg_file.write_text(
        (
            f"node_id: cli-rot-node\n"
            f"data_dir: {tmp_path}/data\n"
            f"keys_dir: {tmp_path}/keys\n"
            f"db_path: {tmp_path}/data/q.db\n"
            f"reality_stamp:\n"
            f"  strict_nist_checks: false\n"
        ),
        encoding="utf-8",
    )
    runner = CliRunner()
    stamp_v1 = tmp_path / "stamp_v1.json"
    stamp_v2 = tmp_path / "stamp_v2.json"

    res_init = runner.invoke(app, ["init-identity", "--config", str(cfg_file)])
    assert res_init.exit_code == 0, res_init.output

    res_s1 = runner.invoke(
        app,
        [
            "stamp",
            "--sensor",
            "cam0",
            "--label",
            "clear",
            "--confidence",
            "0.95",
            "--output",
            str(stamp_v1),
            "--config",
            str(cfg_file),
        ],
    )
    assert res_s1.exit_code == 0, res_s1.output

    res_rot = runner.invoke(app, ["rotate-keys", "--config", str(cfg_file)])
    assert res_rot.exit_code == 0, res_rot.output
    assert "v2" in res_rot.output

    res_s2 = runner.invoke(
        app,
        [
            "stamp",
            "--sensor",
            "cam0",
            "--label",
            "hazard",
            "--confidence",
            "0.97",
            "--output",
            str(stamp_v2),
            "--config",
            str(cfg_file),
        ],
    )
    assert res_s2.exit_code == 0, res_s2.output

    keyring_path = tmp_path / "keys" / "keyring.json"
    assert keyring_path.is_file()
    kr = TrustKeyring.model_validate(orjson.loads(keyring_path.read_bytes()))
    assert len(kr.keys) == 2

    # Verify BOTH stamps offline using the historical keyring via CLI
    for sf in (stamp_v1, stamp_v2):
        rv = runner.invoke(app, ["verify-stamp", str(sf), "--keyring", str(keyring_path)])
        assert rv.exit_code == 0, rv.output
        assert "Overall Valid" in rv.output

    # Verify CycloneDX 1.6 CBOM export via CLI
    cdx_file = tmp_path / "cbom_cyclonedx.json"
    res_cdx = runner.invoke(
        app,
        ["cbom", "--format", "cyclonedx", "--output", str(cdx_file), "--config", str(cfg_file)],
    )
    assert res_cdx.exit_code == 0, res_cdx.output
    cdx_doc = json.loads(cdx_file.read_text(encoding="utf-8"))
    assert cdx_doc["bomFormat"] == "CycloneDX"
    assert cdx_doc["specVersion"] == "1.6"
    assert len(cdx_doc["components"]) == 6
    assert any(
        c["cryptoProperties"]["oid"] == "2.16.840.1.101.3.4.3.18" for c in cdx_doc["components"]
    )

    # Also test JSON CBOM to stdout and invalid format exit code
    res_json = runner.invoke(app, ["cbom", "--format", "json", "--config", str(cfg_file)])
    assert res_json.exit_code == 0
    assert "ML-DSA-65" in res_json.output

    res_bad_fmt = runner.invoke(app, ["cbom", "--format", "xml", "--config", str(cfg_file)])
    assert res_bad_fmt.exit_code == 2

    # Sanity check RealityStamp preserves key_version across JSON roundtrip
    parsed_s2 = RealityStamp.model_validate(orjson.loads(stamp_v2.read_bytes()))
    assert parsed_s2.key_version == 2
