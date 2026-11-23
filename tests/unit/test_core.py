"""Unit and integration tests for the Q-Aegis microkernel core."""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import oqs
import pytest
from typer.testing import CliRunner

from qaegis.cli import app
from qaegis.core.bus import BackpressureError, EventBus, EventEnvelope
from qaegis.core.config import BusConfig, QAegisConfig, load_config
from qaegis.core.identity import DeviceIdentity, IdentityManager, constant_time_equal
from qaegis.core.lifecycle import LifecycleManager, ModeTransitionRecord, OperatingMode
from qaegis.core.storage import StorageEngine
from qaegis.core.telemetry import QAegisMetrics, configure_logging


@pytest.mark.unit
def test_config_yaml_and_env_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    yaml_file = tmp_path / "qaegis.yaml"
    yaml_file.write_text(
        "node_id: yaml-node\n"
        "lifecycle:\n"
        "  night_window_start_hour: 2\n"
        "  night_window_end_hour: 6\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("QAEGIS_NODE_ID", "env-node")
    cfg = load_config(yaml_file)
    assert cfg.node_id == "env-node"
    assert cfg.lifecycle.night_window_start_hour == 2
    assert cfg.lifecycle.night_window_end_hour == 6

    cfg_override = load_config(yaml_file, overrides={"node_id": "explicit-node"})
    assert cfg_override.node_id == "explicit-node"


@pytest.mark.unit
def test_event_envelope_integrity_rejects_tampering() -> None:
    env = EventEnvelope(topic="sensor.imu", source="imu0", payload={"ax": 1.23})
    wire = env.to_wire_bytes()
    restored = EventEnvelope.from_wire_bytes(wire)
    assert restored.event_id == env.event_id
    assert restored.payload_sha256 == env.payload_sha256

    with pytest.raises(ValueError, match="integrity check failed"):
        EventEnvelope(
            topic="sensor.imu",
            source="imu0",
            payload={"ax": 9.99},
            payload_sha256=env.payload_sha256,
        )


@pytest.mark.unit
async def test_event_bus_pubsub_and_request_reply(event_bus: EventBus) -> None:
    received: list[EventEnvelope] = []
    done = asyncio.Event()

    async def on_sensor(env: EventEnvelope) -> None:
        received.append(env)
        done.set()

    sub = event_bus.subscribe("sensor.*", handler=on_sensor)
    await event_bus.publish("sensor.lidar", {"points": 512}, source="lidar0")
    await asyncio.wait_for(done.wait(), timeout=2.0)
    assert len(received) == 1
    assert received[0].payload["points"] == 512
    await event_bus.unsubscribe(sub)

    async def echo_responder(req: EventEnvelope) -> dict[str, int]:
        return {"doubled": int(req.payload["value"]) * 2}

    event_bus.register_responder("rpc.double", echo_responder)
    reply = await event_bus.request("rpc.double", {"value": 21}, source="test")
    assert reply.payload["doubled"] == 42


@pytest.mark.unit
async def test_event_bus_backpressure_policies(metrics: QAegisMetrics) -> None:
    bus_reject = EventBus(
        config=BusConfig(max_queue_size=1, backpressure_policy="reject"),
        metrics=metrics,
    )
    await bus_reject.start()
    sub = bus_reject.subscribe("telemetry.raw")
    await bus_reject.publish("telemetry.raw", {"seq": 1})
    with pytest.raises(BackpressureError):
        await bus_reject.publish("telemetry.raw", {"seq": 2})
    await bus_reject.unsubscribe(sub)
    await bus_reject.stop()

    bus_drop = EventBus(
        config=BusConfig(max_queue_size=1, backpressure_policy="drop_oldest"),
        metrics=metrics,
    )
    await bus_drop.start()
    sub2 = bus_drop.subscribe("telemetry.raw")
    await bus_drop.publish("telemetry.raw", {"seq": 1})
    await bus_drop.publish("telemetry.raw", {"seq": 2})
    latest = sub2.queue.get_nowait()
    assert latest.payload["seq"] == 2
    await bus_drop.stop()


@pytest.mark.crypto
def test_pqc_identity_lifecycle_and_permissions(qaegis_config: QAegisConfig) -> None:
    mgr = IdentityManager(
        keys_dir=qaegis_config.keys_dir,
        node_id=qaegis_config.node_id,
        config=qaegis_config.identity,
    )
    identity = mgr.generate()
    assert (mgr.secret_path.stat().st_mode & 0o777) == 0o600

    loaded = mgr.load()
    assert loaded.key_id == identity.key_id
    assert constant_time_equal(loaded.primary_sig_public, identity.primary_sig_public)

    # Verify ML-DSA-65 primary signature
    msg = b"Q-Aegis authenticated telemetry payload"
    alg, sig = loaded.sign(msg, use_fallback=False)
    assert DeviceIdentity.verify(msg, sig, loaded.primary_sig_public, alg)
    assert not DeviceIdentity.verify(b"tampered", sig, loaded.primary_sig_public, alg)

    # Verify SLH-DSA stateless hash-based fallback signature
    fb_alg, fb_sig = loaded.sign(msg, use_fallback=True)
    assert DeviceIdentity.verify(msg, fb_sig, loaded.fallback_sig_public, fb_alg)

    # Verify ML-KEM-768 encapsulation / decapsulation roundtrip
    with oqs.KeyEncapsulation(loaded.kem_alg) as sender_kem:
        ct, ss_sender = sender_kem.encap_secret(loaded.kem_public)
    ss_receiver = loaded.decap_kem(ct)
    assert constant_time_equal(ss_sender, ss_receiver)

    # Verify insecure permission rejection
    os.chmod(mgr.secret_path, 0o644)
    with pytest.raises(PermissionError):
        mgr.load()
    os.chmod(mgr.secret_path, 0o600)

    # Verify rotation + CBOM
    rotated = mgr.rotate()
    assert rotated.key_id != identity.key_id
    cbom = mgr.generate_cbom(rotated)
    assert len(cbom.algorithms) == 6
    assert any(a["standard"] == "NIST FIPS 203" for a in cbom.algorithms)


@pytest.mark.unit
async def test_storage_wal_audit_chain_and_dream_queue(storage: StorageEngine) -> None:
    assert await storage.get_schema_version() == 2
    r1 = await storage.append_audit_event("boot", "core", {"version": "0.1.0"})
    r2 = await storage.append_audit_event("stamp", "reality_stamp", {"id": "s-1"})
    assert r2.prev_hash == r1.entry_hash

    valid, count = await storage.verify_audit_chain()
    assert valid is True
    assert count == 2

    # Queue and fetch prioritized dream problems
    await storage.enqueue_dream_problem("p-low", 10, "routing", {"q": [[1.0]]})
    await storage.enqueue_dream_problem("p-high", 90, "routing", {"q": [[2.0]]})
    pending = await storage.fetch_pending_dream_problems(limit=2)
    assert [p.problem_id for p in pending] == ["p-high", "p-low"]

    # Policy snapshot versioning
    snap1 = await storage.save_policy_snapshot("nav_policy", {"w0": 0.5}, 0.80, 0.75, active=True)
    snap2 = await storage.save_policy_snapshot("nav_policy", {"w0": 0.9}, 0.92, 0.80, active=True)
    active = await storage.get_active_policy("nav_policy")
    assert active is not None
    assert active.version == snap2.version
    assert active.version > snap1.version


@pytest.mark.unit
async def test_lifecycle_day_night_transitions(
    lifecycle: LifecycleManager,
    event_bus: EventBus,
) -> None:
    transitions: list[ModeTransitionRecord] = []

    async def on_night(rec: ModeTransitionRecord) -> None:
        transitions.append(rec)

    lifecycle.register_night_hook(on_night)
    sub = event_bus.subscribe("lifecycle.mode_changed")

    assert lifecycle.mode == OperatingMode.DAY
    night_rec = await lifecycle.enter_night_mode(reason="test_trigger")
    assert night_rec.new_mode == OperatingMode.NIGHT
    assert lifecycle.mode == OperatingMode.NIGHT
    assert len(transitions) == 1

    env = await asyncio.wait_for(sub.queue.get(), timeout=2.0)
    assert env.payload["new_mode"] == "NIGHT"

    day_rec = await lifecycle.enter_day_mode(reason="resume")
    assert day_rec.new_mode == OperatingMode.DAY

    # Auto transition via idle threshold
    t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
    assert await lifecycle.evaluate_auto_transition(now=t0, cpu_percent=5.0) is None
    t1 = t0 + timedelta(seconds=400)
    auto_rec = await lifecycle.evaluate_auto_transition(now=t1, cpu_percent=5.0)
    assert auto_rec is not None
    assert auto_rec.new_mode == OperatingMode.NIGHT
    await event_bus.unsubscribe(sub)


@pytest.mark.unit
def test_telemetry_and_cli_commands(qaegis_config: QAegisConfig, tmp_path: Path) -> None:
    configure_logging(qaegis_config.telemetry)
    m = QAegisMetrics()
    m.bus_events_published.labels(topic="test", source="unit").inc()
    text = m.render_prometheus_text().decode("utf-8")
    assert "qaegis_bus_events_published_total" in text

    cfg_file = tmp_path / "cli.yaml"
    cfg_file.write_text(
        (
            f"node_id: cli-node\n"
            f"data_dir: {tmp_path}/data\n"
            f"keys_dir: {tmp_path}/keys\n"
            f"db_path: {tmp_path}/data/cli.db\n"
        ),
        encoding="utf-8",
    )
    runner = CliRunner()
    res_ver = runner.invoke(app, ["version"])
    assert res_ver.exit_code == 0
    assert "Q-Aegis" in res_ver.output

    res_id = runner.invoke(app, ["init-identity", "--config", str(cfg_file)])
    assert res_id.exit_code == 0
    assert "ML-DSA-65" in res_id.output

    res_doc = runner.invoke(app, ["doctor", "--config", str(cfg_file)])
    assert res_doc.exit_code == 0
    assert "Audit Hash Chain Valid" in res_doc.output
