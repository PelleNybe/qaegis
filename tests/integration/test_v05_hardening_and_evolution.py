"""Comprehensive verification tests for Q-Aegis v0.5.0 hardening, concurrency & evolution."""

from __future__ import annotations

import asyncio
import concurrent.futures
from pathlib import Path
from typing import Any

import httpx
import numpy as np
import pytest
from pydantic import ValidationError
from qiskit import QuantumCircuit

from qaegis import __version__
from qaegis.core.bus import EventBus
from qaegis.core.config import (
    BusConfig,
    ChameleonConfig,
    IdentityConfig,
    QuantumDreamerConfig,
    RealityStampConfig,
    load_config,
)
from qaegis.core.hardware_seal import PKCS11Sealer, TPM2Sealer, create_sealer_from_config
from qaegis.core.identity import IdentityManager
from qaegis.core.lifecycle import LifecycleManager, ModeTransitionRecord
from qaegis.core.storage import StorageEngine
from qaegis.modules.chameleon_fw.crypto_agility import CryptoAgilityEngine
from qaegis.modules.chameleon_fw.detector import ThreatTier
from qaegis.modules.chameleon_fw.features import TrafficFeatureExtractor, TrafficObservation
from qaegis.modules.quantum_dreamer.backends.ionq_backend import qiskit_to_ionq_circuit
from qaegis.modules.quantum_dreamer.federated import (
    FederatedJobSubmission,
    FederatedScheduler,
    apply_federated_broadcast,
    verify_federated_broadcast,
)
from qaegis.modules.quantum_dreamer.mitigation import extrapolate_zero_noise
from qaegis.modules.quantum_dreamer.policy_updater import PolicyUpdater
from qaegis.modules.quantum_dreamer.solvers import AerStatevectorBackend, QaoaSolver
from qaegis.modules.quantum_entropy.harvester import QuantumEntropyPool
from qaegis.modules.quantum_entropy.ollama_bridge import OllamaQuantumBridge
from qaegis.modules.quantum_entropy.sampler import QuantumEvolutionaryMutator, QuantumMCTS
from qaegis.modules.qubit_compiler.autoencoder import AngleEncoderPipeline
from qaegis.modules.qubit_compiler.qubo_mapper import (
    build_maxcut_qubo,
    build_task_scheduling_qubo,
)
from qaegis.modules.qubit_compiler.service import QubitCompilerService
from qaegis.modules.reality_stamp.gossip import MerkleGossipNode
from qaegis.modules.reality_stamp.qrng import HttpQrngSource
from qaegis.modules.reality_stamp.service import RealityStampService
from qaegis.modules.reality_stamp.signer import verify_reality_stamp


@pytest.mark.crypto
async def test_merkle_proof_grafting_attack_is_rejected(tmp_path: Path) -> None:
    """Grafting a valid Merkle proof from Stamp A onto Stamp B must fail verification."""
    identity = IdentityManager(tmp_path / "keys", "graft-node").generate()
    async with EventBus() as bus, StorageEngine(tmp_path / "graft.db") as storage:
        svc = RealityStampService(
            bus=bus,
            identity=identity,
            storage=storage,
            config=RealityStampConfig(strict_nist_checks=False),
        )
        await svc.start()
        try:
            stamp_a = await svc.stamp_perception("cam-0", "truck", 0.91)
            stamp_b = await svc.stamp_perception("cam-0", "cyclist", 0.96)
            assert verify_reality_stamp(stamp_a).valid is True
            assert verify_reality_stamp(stamp_b).valid is True

            # Graft Stamp A's valid inclusion proof onto Stamp B
            grafted = stamp_b.model_copy(update={"merkle_proof": stamp_a.merkle_proof})
            res = verify_reality_stamp(grafted)
            assert res.valid is False
            assert res.signature_ok is True
            assert res.merkle_proof_ok is False
            assert res.error is not None and "leaf_hash" in res.error
        finally:
            await svc.stop()


@pytest.mark.integration
async def test_concurrent_stamping_and_storage_integrity_checks(tmp_path: Path) -> None:
    """Concurrent perception stamping must serialize cleanly with valid Merkle & DB hashes."""
    identity = IdentityManager(tmp_path / "keys", "conc-node").generate()
    async with EventBus() as bus, StorageEngine(tmp_path / "conc.db") as storage:
        svc = RealityStampService(
            bus=bus,
            identity=identity,
            storage=storage,
            config=RealityStampConfig(strict_nist_checks=False),
        )
        await svc.start()
        try:
            stamps = await asyncio.gather(
                *[svc.stamp_perception(f"cam-{i}", f"obj-{i}", 0.8 + 0.01 * i) for i in range(6)]
            )
            assert len(stamps) == 6
            indices = sorted(
                s.merkle_proof.leaf_index for s in stamps if s.merkle_proof is not None
            )
            assert indices == [0, 1, 2, 3, 4, 5]
            for st in stamps:
                assert svc.verify(st).valid is True

            audit_ok, audit_count = await storage.verify_audit_chain()
            assert audit_ok is True
            assert audit_count == 6

            # Enqueue dream problem & save policy snapshot, verify integrity, then tamper both
            qubo = build_maxcut_qubo(3, [(0, 1, 1.0), (1, 2, 1.0)])
            await storage.enqueue_dream_problem(
                problem_id=qubo.problem_id,
                priority=80,
                problem_type=qubo.problem_type,
                qubo=qubo.model_dump(mode="json"),
            )
            await storage.save_policy_snapshot(
                policy_name="nav_policy",
                weights={"w_0": 0.6, "w_1": 0.4},
                validation_score=0.92,
                baseline_score=0.80,
                active=True,
                source_problem_id=qubo.problem_id,
            )
            assert (await storage.verify_dream_problem_integrity()) == (True, 1)
            assert (await storage.verify_policy_snapshots()) == (True, 1)

            # Tamper directly in SQLite and verify both integrity checks catch it
            conn = storage._require_conn()
            await conn.execute(
                "UPDATE dream_problems SET priority = 1 WHERE problem_id = ?;",
                (qubo.problem_id,),
            )
            await conn.execute(
                "UPDATE policy_snapshots SET validation_score = 0.1 WHERE policy_name = ?;",
                ("nav_policy",),
            )
            await conn.commit()
            assert (await storage.verify_dream_problem_integrity())[0] is False
            assert (await storage.verify_policy_snapshots())[0] is False
        finally:
            await svc.stop()


@pytest.mark.integration
async def test_event_bus_zmq_loopback_deduplication() -> None:
    """Single-node ZMQ bus with PUB+SUB connected must deliver each published event once."""
    cfg = BusConfig(
        transport="zmq",
        zmq_pub_endpoint="tcp://127.0.0.1:0",
        zmq_sub_endpoint="tcp://127.0.0.1:0",
        zmq_bind_pub=True,
        zmq_connect_sub=True,
        zmq_security="none",
    )
    async with EventBus(config=cfg) as bus:
        sub = bus.subscribe("loopback.test")
        await asyncio.sleep(0.15)
        for idx in range(5):
            await bus.publish("loopback.test", {"seq": idx})
        await asyncio.sleep(0.2)
        received: list[int] = []
        while not sub.queue.empty():
            env = sub.queue.get_nowait()
            received.append(int(env.payload["seq"]))
        assert received == [0, 1, 2, 3, 4]


@pytest.mark.unit
def test_config_cross_field_validators_and_json_env_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify Pydantic cross-field validators and JSON list parsing in QAEGIS_* env vars."""
    with pytest.raises(ValidationError):
        ChameleonConfig(elevated_risk_threshold=0.80, critical_risk_threshold=0.50)

    with pytest.raises(ValidationError):
        QuantumDreamerConfig(mitigation_mode="zne", zne_scale_factors=[1, 2, 3])

    with pytest.raises(ValidationError):
        QuantumDreamerConfig(mitigation_mode="zne", zne_scale_factors=[1, 1])

    with pytest.raises(ValidationError):
        QuantumDreamerConfig(mitigation_mode="both", zne_scale_factors=[1])

    yaml_path = tmp_path / "qaegis.yaml"
    yaml_path.write_text("node_id: env-json-node\n", encoding="utf-8")
    monkeypatch.setenv("QAEGIS_QUANTUM_DREAMER__ZNE_SCALE_FACTORS", "[1, 3, 7]")
    cfg = load_config(yaml_path)
    assert cfg.quantum_dreamer.zne_scale_factors == [1, 3, 7]


@pytest.mark.crypto
def test_zeroized_identity_blocks_crypto_and_cbom_uses_package_version(tmp_path: Path) -> None:
    """Zeroized identities must refuse signing/decapsulation, and CBOM embeds __version__."""
    mgr = IdentityManager(tmp_path / "keys", "zero-node")
    ident = mgr.generate()
    cdx = mgr.generate_cyclonedx_cbom(ident)
    assert cdx["metadata"]["tools"]["components"][0]["version"] == __version__

    ident.zeroize_secrets()
    assert ident.is_zeroized is True
    with pytest.raises(RuntimeError, match="zeroized"):
        ident.sign(b"should-fail")
    with pytest.raises(RuntimeError, match="zeroized"):
        ident.decap_kem(b"x" * 32)
    with pytest.raises(RuntimeError, match="zeroized"):
        _ = ident.x25519_private


@pytest.mark.unit
async def test_lifecycle_hook_fault_isolation() -> None:
    """A failing Night-Mode hook must not prevent subsequent hooks or corrupt mode state."""
    async with EventBus() as bus:
        lc = LifecycleManager(bus=bus)
        err_sub = bus.subscribe("lifecycle.hook_error")
        ran_second = False

        async def _broken_hook(_rec: ModeTransitionRecord) -> None:
            raise RuntimeError("simulated-plugin-failure")

        async def _healthy_hook(_rec: ModeTransitionRecord) -> None:
            nonlocal ran_second
            ran_second = True

        lc.register_night_hook(_broken_hook)
        lc.register_night_hook(_healthy_hook)

        rec = await lc.enter_night_mode(reason="test_isolation")
        assert rec.new_mode.value == "NIGHT"
        assert ran_second is True
        err_env = await asyncio.wait_for(err_sub.queue.get(), timeout=2.0)
        assert err_env.payload["phase"] == "night"
        assert "simulated-plugin-failure" in err_env.payload["error"]


@pytest.mark.crypto
def test_chameleon_replay_protection_recipient_binding_and_keyring_rotation(
    tmp_path: Path,
) -> None:
    """Verify Chameleon replay rejection, cipher-suite validation, recipient check, and keyring."""
    alice_mgr = IdentityManager(tmp_path / "alice", "alice-node")
    bob_mgr = IdentityManager(tmp_path / "bob", "bob-node")
    carol_mgr = IdentityManager(tmp_path / "carol", "carol-node")
    alice_v1 = alice_mgr.generate()
    bob = bob_mgr.generate()
    carol = carol_mgr.generate()

    alice_eng = CryptoAgilityEngine(alice_v1)
    bob_eng = CryptoAgilityEngine(bob)
    carol_eng = CryptoAgilityEngine(carol)

    env = alice_eng.encrypt(
        b"quantum-protected-orders",
        recipient=bob.public_bundle(),
        tier=ThreatTier.QUANTUM_CRITICAL,
    )

    # Rotate Alice's keys so alice_v1 is historical inside keyring
    _alice_v2, alice_keyring = alice_mgr.rotate_keys()

    # Wrong recipient must fail
    with pytest.raises(ValueError, match="not local node"):
        carol_eng.decrypt(env)

    # Cipher-suite tampering must fail
    bad_suite = env.model_copy(update={"cipher_suite": "TAMPERED-SUITE"})
    with pytest.raises(ValueError, match="Cipher suite mismatch"):
        bob_eng.decrypt(bad_suite, expected_sender_keyring=alice_keyring)

    # First decrypt succeeds with historical keyring
    pt = bob_eng.decrypt(env, expected_sender_keyring=alice_keyring)
    assert pt == b"quantum-protected-orders"

    # Replaying the identical authenticated envelope must be rejected
    with pytest.raises(ValueError, match="Replay attack detected"):
        bob_eng.decrypt(env, expected_sender_keyring=alice_keyring)


@pytest.mark.quantum
async def test_self_contained_onnx_normalization_and_resource_allocation_rpc(
    tmp_path: Path,
) -> None:
    """Fresh AngleEncoderPipeline loading ONNX must match trained PyTorch angles identically."""
    rng = np.random.default_rng(7)
    # Deliberately shifted & scaled distribution (mean ~ 50, std ~ 20)
    samples = (rng.normal(loc=50.0, scale=20.0, size=(64, 12))).astype(np.float32)
    trained = AngleEncoderPipeline(input_dim=12, num_qubits=4, hidden_dim=24)
    trained.train(samples, epochs=15)
    sample_vec = samples[0]
    pt_angles = trained.encode_to_angles(sample_vec)

    onnx_path = tmp_path / "self_contained_encoder.onnx"
    trained.export_onnx(onnx_path)

    # Fresh instance with uninitialized mean=0, std=1
    deployed = AngleEncoderPipeline(input_dim=12, num_qubits=4, hidden_dim=24)
    deployed.load_onnx(onnx_path)
    onnx_angles = deployed.encode_to_angles(sample_vec)

    assert onnx_angles.encoder_backend == "onnxruntime_cpu"
    assert np.allclose(pt_angles.angles_rad, onnx_angles.angles_rad, atol=1e-4)

    # Also verify scheduling conflict validation and resource_allocation RPC
    with pytest.raises(ValueError, match="Invalid conflict pair"):
        build_task_scheduling_qubo([1.0, 2.0], conflicts=[(0, 5)], target_active_tasks=1)

    async with EventBus() as bus:
        svc = QubitCompilerService(bus=bus, input_dim=12)
        await svc.start()
        resp = await bus.request(
            "compiler.build_qubo",
            {
                "problem_type": "resource_allocation",
                "utilities": [5.0, 3.0, 4.0],
                "costs": [1.0, 2.0, 1.5],
                "budget_penalty": 1.2,
            },
        )
        assert resp.payload["problem_type"] == "resource_allocation"
        assert resp.payload["num_variables"] == 3


@pytest.mark.quantum
async def test_federated_keyring_target_binding_mitigation_and_ionq_gates(tmp_path: Path) -> None:
    """Verify federated target binding, keyring verification, ZNE validation, and IonQ gates."""
    coord_mgr = IdentityManager(tmp_path / "coord", "fleet-coord")
    coord_v1 = coord_mgr.generate()

    solver = QaoaSolver(
        config=QuantumDreamerConfig(qaoa_reps=1, max_optimizer_iters=15),
        backend=AerStatevectorBackend(),
    )
    sched = FederatedScheduler(coord_v1, solver, max_qpu_seconds_per_night=60.0)
    qubo = build_maxcut_qubo(3, [(0, 1, 1.0), (1, 2, 1.5), (2, 0, 1.0)])
    sched.submit(
        FederatedJobSubmission(
            node_id="drone-alpha",
            policy_name="route_policy",
            priority=90,
            estimated_qpu_seconds=2.0,
            qubo=qubo,
        )
    )
    report = sched.run_federated_cycle()
    assert report.unique_problems_solved == 1
    assert report.failed_groups_count == 0
    bcast = report.broadcasts[0]

    # Rotate coordinator keys -> broadcast must still verify against historical TrustKeyring
    _coord_v2, coord_keyring = coord_mgr.rotate_keys()
    assert verify_federated_broadcast(bcast, coord_keyring) is True

    # Target node mismatch must raise ValueError
    async with StorageEngine(tmp_path / "drone.db") as store:
        updater = PolicyUpdater(store, min_improvement=0.0)
        with pytest.raises(ValueError, match="not local node"):
            await apply_federated_broadcast(
                bcast,
                coord_keyring,
                updater,
                lambda _w: 1.0,
                expected_target_node_id="drone-beta",
            )

    # Distinct scale factor guard in ZNE extrapolation
    with pytest.raises(ValueError, match="distinct scale_factors"):
        extrapolate_zero_noise([1, 1], [-1.0, -0.8], method="richardson")

    # Extended IonQ QIS gate translations (sdg, tdg, cz, swap)
    qc = QuantumCircuit(2)
    qc.sdg(0)
    qc.tdg(1)
    qc.cz(0, 1)
    qc.swap(0, 1)
    ionq_doc = qiskit_to_ionq_circuit(qc)
    gate_names = [g["gate"] for g in ionq_doc["circuit"]]
    assert "si" in gate_names
    assert "ti" in gate_names
    assert "cnot" in gate_names
    assert "swap" in gate_names


@pytest.mark.integration
async def test_entropy_pool_thread_safety_and_gossip_hydration_with_keyring(
    tmp_path: Path,
) -> None:
    """Verify thread-safe QuantumEntropyPool + vectorized Gaussians and gossip restart hydration."""
    pool = QuantumEntropyPool(bytes(range(64)))
    with pytest.raises(ValueError):
        pool.next_bytes(-1)
    assert pool.next_bytes(0) == b""
    assert pool.next_gaussians(0).size == 0

    def _draw_worker(_idx: int) -> Any:
        return pool.next_gaussians(64)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        draws = list(ex.map(_draw_worker, range(8)))
    all_vals = np.concatenate(draws)
    assert all_vals.shape == (512,)
    assert np.all(np.isfinite(all_vals))

    # Gossip restart hydration + keyring verification across peer rotation
    peer_mgr = IdentityManager(tmp_path / "peer", "peer-01")
    local_mgr = IdentityManager(tmp_path / "local", "local-01")
    peer_v1 = peer_mgr.generate()
    local_id = local_mgr.generate()

    async with EventBus() as bus, StorageEngine(tmp_path / "gossip.db") as store:
        node_peer = MerkleGossipNode(peer_v1, store, bus)
        cp_v1 = node_peer.create_checkpoint("a" * 64, tree_size=3)
        _peer_v2, peer_keyring = peer_mgr.rotate_keys()

        node_local = MerkleGossipNode(local_id, store, bus)
        node_local.register_trusted_keyring(peer_keyring)
        out = await node_local.ingest_checkpoint(cp_v1, rebroadcast=False)
        assert out.accepted is True

        # Simulate node restart with fresh MerkleGossipNode hydrated from SQLite WAL
        restarted = MerkleGossipNode(local_id, store, bus)
        restarted.register_trusted_keyring(peer_keyring)
        loaded = await restarted.hydrate_from_storage()
        assert loaded >= 1
        assert restarted.latest_roots["peer-01"] == (3, "a" * 64)


@pytest.mark.unit
async def test_http_qrng_source_formats_sealer_factory_and_input_guards(tmp_path: Path) -> None:
    """Verify HttpQrngSource JSON/hex/binary decoding, sealer factory, and defensive guards."""

    def _handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/json-int":
            return httpx.Response(
                200,
                json={"data": list(range(64))},
                headers={"content-type": "application/json"},
            )
        if req.url.path == "/json-hex":
            return httpx.Response(
                200,
                json={"data": ["aa" * 32, "bb" * 32]},
                headers={"content-type": "application/json"},
            )
        if req.url.path == "/binary":
            return httpx.Response(200, content=bytes(range(64)))
        if req.url.path == "/short":
            return httpx.Response(200, content=b"short")
        return httpx.Response(200, json={"bad": True}, headers={"content-type": "application/json"})

    transport = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        s_int = HttpQrngSource("https://qrng.local/json-int", client=client)
        assert len(await s_int.fetch_bytes(32)) == 32
        s_hex = HttpQrngSource("https://qrng.local/json-hex", client=client)
        assert len(await s_hex.fetch_bytes(32)) == 32
        s_bin = HttpQrngSource("https://qrng.local/binary", client=client)
        assert len(await s_bin.fetch_bytes(32)) == 32
        s_short = HttpQrngSource("https://qrng.local/short", client=client)
        with pytest.raises(ValueError, match="expected at least"):
            await s_short.fetch_bytes(32)
        s_bad = HttpQrngSource("https://qrng.local/bad", client=client)
        with pytest.raises(ValueError, match="Unexpected JSON"):
            await s_bad.fetch_bytes(32)

    # Hardware sealer factory + IdentityManager.load_active
    id_cfg = IdentityConfig()
    assert isinstance(create_sealer_from_config(id_cfg, backend="pkcs11"), PKCS11Sealer)
    assert isinstance(create_sealer_from_config(id_cfg, backend="tpm2"), TPM2Sealer)
    with pytest.raises(ValueError, match="Unsupported hardware sealing backend"):
        create_sealer_from_config(id_cfg, backend="invalid")

    mgr = IdentityManager(tmp_path / "active_keys", "active-node")
    gen = mgr.generate()
    assert mgr.load_active().key_id == gen.key_id

    # TrafficFeatureExtractor rolling window mean & defensive sampler/bridge guards
    ext = TrafficFeatureExtractor()
    assert ext.mean_window_payload_bytes == 0.0
    ext.extract(TrafficObservation(source="a", destination="b", payload_bytes=b"12345678"))
    assert ext.mean_window_payload_bytes == 8.0

    pool = QuantumEntropyPool(bytes(range(64)))
    mcts: QuantumMCTS[int, int] = QuantumMCTS(
        pool,
        actions_fn=lambda _s: [0, 1],
        step_fn=lambda s, a: s + a,
        is_terminal_fn=lambda s: s >= 1,
        reward_fn=lambda s: float(s),
    )
    with pytest.raises(ValueError, match="iterations"):
        mcts.search(0, iterations=0)
    mut = QuantumEvolutionaryMutator(pool)
    with pytest.raises(ValueError, match="non-empty"):
        mut.evolve([], lambda g: sum(g))
    with pytest.raises(ValueError, match=">= 1"):
        mut.evolve([0.5], lambda g: sum(g), generations=0)

    bridge = OllamaQuantumBridge()
    with pytest.raises(ValueError, match="at least one chat turn"):
        await bridge.generate_openai_compatible([], pool)
