"""Full end-to-end integration test exercising all five Q-Aegis subsystems simultaneously."""

from __future__ import annotations

import asyncio
from pathlib import Path

import orjson
import pytest
from typer.testing import CliRunner

from qaegis.cli import app
from qaegis.core.bus import EventBus
from qaegis.core.config import QAegisConfig, QuantumDreamerConfig, RealityStampConfig
from qaegis.core.identity import IdentityManager
from qaegis.core.lifecycle import LifecycleManager, OperatingMode
from qaegis.core.storage import StorageEngine
from qaegis.core.telemetry import QAegisMetrics
from qaegis.modules.chameleon_fw.detector import ThreatTier
from qaegis.modules.chameleon_fw.features import TrafficObservation
from qaegis.modules.chameleon_fw.service import ChameleonFirewallService
from qaegis.modules.quantum_dreamer.service import QuantumDreamerService
from qaegis.modules.quantum_entropy.sampler import QuantumMCTS
from qaegis.modules.quantum_entropy.service import QuantumEntropyService
from qaegis.modules.qubit_compiler.qubo_mapper import build_maxcut_qubo
from qaegis.modules.qubit_compiler.service import QubitCompilerService
from qaegis.modules.reality_stamp.service import RealityStampService
from qaegis.modules.reality_stamp.signer import RealityStamp, verify_reality_stamp


@pytest.mark.integration
async def test_full_five_module_qaegis_pipeline(tmp_path: Path) -> None:
    """Exercise all 5 Q-Aegis modules end-to-end across Day Mode and Night Mode."""
    cfg = QAegisConfig(
        node_id="qaegis-e2e-drone-01",
        data_dir=tmp_path / "data",
        keys_dir=tmp_path / "keys",
        db_path=tmp_path / "data" / "e2e.db",
        reality_stamp=RealityStampConfig(strict_nist_checks=False),
        quantum_dreamer=QuantumDreamerConfig(
            backend_type="aer_statevector",
            qaoa_reps=2,
            max_optimizer_iters=35,
            min_policy_improvement=0.01,
        ),
    )
    cfg.ensure_directories()

    metrics = QAegisMetrics()
    bus = EventBus(config=cfg.bus, metrics=metrics)
    storage = StorageEngine(cfg.db_path)
    lifecycle = LifecycleManager(bus=bus, config=cfg.lifecycle, metrics=metrics)

    edge_identity = IdentityManager(cfg.keys_dir, cfg.node_id, cfg.identity).generate()
    ground_identity = IdentityManager(
        tmp_path / "ground_keys",
        "qaegis-ground-station",
        cfg.identity,
    ).generate()

    await bus.start()
    await storage.initialize()

    # Boot all five subsystems over the shared microkernel
    reality_svc = RealityStampService(
        bus=bus,
        identity=edge_identity,
        storage=storage,
        config=cfg.reality_stamp,
        metrics=metrics,
    )
    chameleon_edge = ChameleonFirewallService(
        bus=bus,
        identity=edge_identity,
        config=cfg.chameleon_fw,
        metrics=metrics,
        onnx_model_path=tmp_path / "hndl_edge.onnx",
    )
    chameleon_ground = ChameleonFirewallService(
        bus=bus,
        identity=ground_identity,
        config=cfg.chameleon_fw,
        metrics=metrics,
    )
    compiler_svc = QubitCompilerService(bus=bus, input_dim=8, config=cfg.qubit_compiler)
    dreamer_svc = QuantumDreamerService(
        bus=bus,
        storage=storage,
        lifecycle=lifecycle,
        config=cfg.quantum_dreamer,
        metrics=metrics,
    )
    entropy_svc = QuantumEntropyService(bus=bus, config=cfg.quantum_entropy, metrics=metrics)

    await reality_svc.start()
    await chameleon_edge.start()
    await compiler_svc.start()
    await dreamer_svc.start()
    await entropy_svc.start()

    try:
        # --- DAY MODE ---
        assert lifecycle.mode == OperatingMode.DAY

        # 1. Sensor perception event -> Module 1 (Proof of Reality) signs & anchors in Merkle log
        stamp_sub = bus.subscribe("reality_stamp.created")
        await bus.publish(
            topic="perception.lidar",
            source="lidar-front",
            payload={
                "sensor_id": "lidar-front",
                "label": "corridor_blocked",
                "confidence": 0.96,
                "metadata": {"range_m": 4.2, "bearing_deg": 18.5},
            },
        )
        stamp_env = await asyncio.wait_for(stamp_sub.queue.get(), timeout=5.0)
        stamp = RealityStamp.model_validate(stamp_env.payload)
        assert verify_reality_stamp(stamp).valid is True
        assert stamp.merkle_proof is not None
        await bus.unsubscribe(stamp_sub)

        # 2. Module 2 (Quantum Chameleon) encrypts the RealityStamp over satellite link -> PQC
        stamped_bytes = orjson.dumps(stamp.model_dump(mode="json"))
        obs = TrafficObservation(
            source=edge_identity.node_id,
            destination=ground_identity.node_id,
            topic="reality_stamp.uplink",
            protocol="satellite",
            sensitivity="top_secret",
            payload_bytes=stamped_bytes,
            long_term_retention_years=15.0,
        )
        protected = await chameleon_edge.protect(obs, recipient=ground_identity.public_bundle())
        assert protected.envelope.tier == ThreatTier.QUANTUM_CRITICAL
        decrypted = chameleon_ground.unprotect(
            protected.envelope,
            expected_sender=edge_identity.public_bundle(),
        )
        recovered_stamp = RealityStamp.model_validate(orjson.loads(decrypted))
        assert recovered_stamp.payload.stamp_id == stamp.payload.stamp_id
        assert verify_reality_stamp(recovered_stamp).valid is True

        # 3. Module 3 (AI-to-Qubit Compiler) compresses sensor telemetry -> OpenQASM 3.0 + QUBO
        angles, circuit_art, pl_res = await compiler_svc.compile_sensor_vector(
            [4.2, 18.5, 0.96, -0.3, 1.1, 0.4, -0.8, 0.2]
        )
        assert len(angles.angles_rad) == cfg.qubit_compiler.default_num_qubits
        assert "OPENQASM 3.0;" in circuit_art.openqasm3
        assert pl_res is not None

        routing_qubo = build_maxcut_qubo(
            num_nodes=4,
            weighted_edges=[(0, 1, 2.0), (1, 2, 1.5), (2, 3, 2.0), (3, 0, 1.5)],
        )
        await dreamer_svc.enqueue_day_problem(
            routing_qubo,
            priority=99,
            policy_name="drone_reroute_policy",
        )

        # --- NIGHT MODE ---
        # 4. Module 4 (Quantum Dreaming) solves queued QUBO via QAOA and updates local policy
        night_sub = bus.subscribe("dreamer.night_cycle_completed")
        await lifecycle.enter_night_mode(reason="docked_charging")
        night_env = await asyncio.wait_for(night_sub.queue.get(), timeout=15.0)
        assert night_env.payload["problems_processed"] == 1
        assert night_env.payload["policy_updates"][0]["applied"] is True
        await bus.unsubscribe(night_sub)

        active_policy = await storage.get_active_policy("drone_reroute_policy")
        assert active_policy is not None
        assert active_policy.active is True

        # Return to Day Mode
        await lifecycle.enter_day_mode(reason="mission_resume")
        assert lifecycle.mode == OperatingMode.DAY

        # 5. Module 5 (Quantum Entropy) harvests entangled distribution & drives MCTS exploration
        dist_batch, qpool = await entropy_svc.harvest(num_qubits=5, shots=256)
        assert dist_batch.shannon_entropy_bits > 2.0
        mcts: QuantumMCTS[int, str] = QuantumMCTS(
            pool=qpool,
            actions_fn=lambda s: ["detour_north", "detour_south"] if s == 0 else [],
            step_fn=lambda s, a: 1 if a == "detour_north" else 2,
            is_terminal_fn=lambda s: s != 0,
            reward_fn=lambda s: 1.0 if s == 1 else 0.1,
        )
        best_route, _val = mcts.search(0, iterations=60)
        assert best_route == "detour_north"

        # Verify persistent audit hash chain & Prometheus metrics across all subsystems
        chain_ok, record_count = await storage.verify_audit_chain()
        assert chain_ok is True
        assert record_count >= 2

        prom_text = metrics.render_prometheus_text().decode("utf-8")
        assert "qaegis_reality_stamps_signed_total" in prom_text
        assert "qaegis_chameleon_tier_transitions_total" in prom_text
        assert "qaegis_dreamer_qaoa_solves_total" in prom_text
        assert "qaegis_entropy_bytes_harvested_total" in prom_text
    finally:
        await reality_svc.stop()
        await storage.close()
        await bus.stop()


@pytest.mark.integration
def test_cli_run_daemon_lifecycle(tmp_path: Path) -> None:
    cfg_file = tmp_path / "daemon.yaml"
    cfg_file.write_text(
        (
            f"node_id: daemon-test\n"
            f"data_dir: {tmp_path}/d\n"
            f"keys_dir: {tmp_path}/k\n"
            f"db_path: {tmp_path}/d/q.db\n"
            f"telemetry:\n"
            f"  enabled: false\n"
            f"reality_stamp:\n"
            f"  strict_nist_checks: false\n"
        ),
        encoding="utf-8",
    )
    runner = CliRunner()
    res = runner.invoke(
        app,
        ["run", "--config", str(cfg_file), "--max-ticks", "1", "--tick-interval", "0.05"],
    )
    assert res.exit_code == 0, res.output
    assert "Q-Aegis microkernel online" in res.output
