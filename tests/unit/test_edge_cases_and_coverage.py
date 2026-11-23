"""Adversarial edge-case, tamper-detection, and RPC handler coverage tests."""

from __future__ import annotations

import base64
import os
from datetime import UTC, datetime
from pathlib import Path

import aiosqlite
import httpx
import pytest

from qaegis.adapters.mqtt_bridge import AsyncMqttBridge, MqttBridgeConfig
from qaegis.core.bus import EventBus, EventEnvelope, load_or_create_curve_keypair
from qaegis.core.config import (
    LifecycleConfig,
    QuantumDreamerConfig,
    RealityStampConfig,
    load_config,
)
from qaegis.core.hardware_seal import PKCS11Sealer, SealedBlob
from qaegis.core.identity import (
    DeviceIdentity,
    IdentityManager,
    resolve_oqs_kem_algorithm,
    resolve_oqs_sig_algorithm,
)
from qaegis.core.lifecycle import LifecycleManager, OperatingMode
from qaegis.core.storage import StorageEngine
from qaegis.core.telemetry import QAegisMetrics
from qaegis.modules.chameleon_fw.crypto_agility import CryptoAgilityEngine
from qaegis.modules.chameleon_fw.detector import ThreatTier
from qaegis.modules.chameleon_fw.features import (
    TrafficObservation,
    printable_ascii_ratio,
    shannon_entropy_bytes,
)
from qaegis.modules.chameleon_fw.service import ChameleonFirewallService
from qaegis.modules.quantum_dreamer.federated import (
    FederatedJobSubmission,
    FederatedScheduler,
    apply_federated_broadcast,
    canonicalize_qubo,
)
from qaegis.modules.quantum_dreamer.mitigation import (
    ErrorMitigationPipeline,
    extrapolate_zero_noise,
    fold_circuit_unitary,
)
from qaegis.modules.quantum_dreamer.policy_updater import PolicyUpdater
from qaegis.modules.quantum_dreamer.service import QuantumDreamerService
from qaegis.modules.quantum_dreamer.solvers import (
    AerNoisyBackend,
    AerStatevectorBackend,
    QaoaSolver,
    build_qaoa_circuit,
)
from qaegis.modules.quantum_entropy.harvester import QuantumEntropyPool
from qaegis.modules.quantum_entropy.service import QuantumEntropyService
from qaegis.modules.qubit_compiler.qubo_mapper import (
    QuboProblem,
    build_maxcut_qubo,
    build_resource_allocation_qubo,
    evaluate_ising,
    evaluate_qubo,
    qubo_to_ising,
)
from qaegis.modules.qubit_compiler.service import QubitCompilerService
from qaegis.modules.reality_stamp.merkle import MerkleProof, MerkleTree, verify_merkle_proof
from qaegis.modules.reality_stamp.nist_tests import (
    adaptive_proportion_test,
    block_frequency_test,
    bytes_to_bits,
    frequency_monobit_test,
    longest_run_of_ones_test,
    repetition_count_test,
    runs_test,
)
from qaegis.modules.reality_stamp.qrng import (
    HttpQrngSource,
    QiskitHadamardQrngSource,
    xor_mix_streams,
)
from qaegis.modules.reality_stamp.service import RealityStampService
from qaegis.modules.reality_stamp.signer import RealityPayload, RealitySigner, verify_reality_stamp


@pytest.mark.unit
def test_config_and_algorithm_resolver_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "missing.yaml")

    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("- not-a-mapping\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must be a mapping"):
        load_config(bad_yaml)

    good_yaml = tmp_path / "good.yaml"
    good_yaml.write_text("node_id: from-yaml\n", encoding="utf-8")
    monkeypatch.setenv("QAEGIS_CONFIG", str(good_yaml))
    monkeypatch.setenv("QAEGIS_LIFECYCLE__NIGHT_WINDOW_START_HOUR", "3")
    cfg = load_config()
    assert cfg.lifecycle.night_window_start_hour == 3

    with pytest.raises(ValueError, match="not enabled"):
        resolve_oqs_sig_algorithm("NONEXISTENT-SIG-999")
    with pytest.raises(ValueError, match="not enabled"):
        resolve_oqs_kem_algorithm("NONEXISTENT-KEM-999")


@pytest.mark.unit
async def test_storage_tamper_detection_and_uninitialized_error(tmp_path: Path) -> None:
    uninit = StorageEngine(tmp_path / "uninit.db")
    with pytest.raises(RuntimeError, match="not initialized"):
        await uninit.get_schema_version()

    db_path = tmp_path / "tamper.db"
    store = StorageEngine(db_path)
    await store.initialize()
    await store.append_audit_event("boot", "core", {"ok": True})
    await store.append_audit_event("stamp", "rs", {"id": "1"})
    ok, count = await store.verify_audit_chain()
    assert ok is True and count == 2

    # Tamper directly with SQLite audit row payload -> verify_audit_chain MUST catch it!
    async with aiosqlite.connect(db_path) as raw_conn:
        await raw_conn.execute(
            "UPDATE audit_events SET payload_json = '{\"tampered\":true}' WHERE seq = 2;"
        )
        await raw_conn.commit()
    ok_after, bad_seq = await store.verify_audit_chain()
    assert ok_after is False
    assert bad_seq == 2

    # Tamper prev_hash on seq 1 -> also detected
    async with aiosqlite.connect(db_path) as raw_conn:
        await raw_conn.execute("UPDATE audit_events SET prev_hash = 'deadbeef' WHERE seq = 1;")
        await raw_conn.commit()
    ok_prev, bad_seq1 = await store.verify_audit_chain()
    assert ok_prev is False and bad_seq1 == 1
    await store.close()


@pytest.mark.unit
async def test_lifecycle_wraparound_shutdown_and_telemetry_http(
    event_bus: EventBus,
    metrics: QAegisMetrics,
) -> None:
    cfg = LifecycleConfig(
        night_window_start_hour=22,
        night_window_end_hour=4,
        idle_cpu_threshold_pct=20.0,
        idle_duration_seconds=10.0,
    )
    lc = LifecycleManager(bus=event_bus, config=cfg, metrics=metrics)
    assert lc.is_within_night_window(datetime(2026, 6, 1, 23, 0, tzinfo=UTC)) is True
    assert lc.is_within_night_window(datetime(2026, 6, 1, 2, 0, tzinfo=UTC)) is True
    assert lc.is_within_night_window(datetime(2026, 6, 1, 12, 0, tzinfo=UTC)) is False

    # Idempotent day mode & activity resume from night mode
    same_day = await lc.enter_day_mode()
    assert same_day.reason == "already_in_day_mode"
    await lc.enter_night_mode(reason="test")
    same_night = await lc.enter_night_mode()
    assert same_night.reason == "already_in_night_mode"
    resumed = await lc.evaluate_auto_transition(
        now=datetime(2026, 6, 1, 12, 0, tzinfo=UTC),
        cpu_percent=80.0,
    )
    assert resumed is not None and resumed.new_mode == OperatingMode.DAY

    # Shutdown blocks further mode changes
    await lc.shutdown()
    assert len(lc.history) >= 3
    with pytest.raises(RuntimeError, match="SHUTDOWN"):
        await lc.enter_night_mode()
    with pytest.raises(RuntimeError, match="SHUTDOWN"):
        await lc.enter_day_mode()

    # Prometheus HTTP exporter start/stop on ephemeral port 0
    host, port = metrics.start_http_exporter(host="127.0.0.1", port=0)
    assert host == "127.0.0.1" and port > 0
    # Calling start again returns same address cleanly
    assert metrics.start_http_exporter(host="127.0.0.1", port=0) == (host, port)
    metrics.stop_http_exporter()


@pytest.mark.crypto
def test_malformed_pqc_envelopes_merkle_and_nist_edge_cases(
    device_identity: DeviceIdentity,
    tmp_path: Path,
) -> None:
    # Merkle invalid proofs & out-of-bounds
    tree = MerkleTree()
    assert len(tree.root_hex) == 64
    tree.append_raw(b"one")
    with pytest.raises(IndexError):
        tree.generate_proof(5)
    assert (
        verify_merkle_proof(
            MerkleProof(
                leaf_index=-1,
                tree_size=1,
                leaf_hash="00" * 32,
                root_hash="00" * 32,
                steps=[],
            )
        )
        is False
    )
    assert (
        verify_merkle_proof(
            MerkleProof(
                leaf_index=0,
                tree_size=1,
                leaf_hash="not-hex",
                root_hash="00" * 32,
                steps=[],
            )
        )
        is False
    )

    # Malformed base64 signature & invalid algorithm on RealityStamp
    signer = RealitySigner(device_identity)
    payload = RealityPayload(
        node_id=device_identity.node_id,
        sensor_id="s0",
        perception_label="ok",
        confidence=0.9,
        qrng_nonce_hex="ab" * 32,
        qrng_sources=["test"],
    )
    stamp = signer.sign_payload(payload)
    bad_b64 = stamp.model_copy(update={"signature_b64": "!!!not-base64!!!"})
    assert verify_reality_stamp(bad_b64).valid is False
    bad_alg = stamp.model_copy(update={"algorithm": "BOGUS-ALG"})
    assert verify_reality_stamp(bad_alg).valid is False

    # Chameleon envelope missing fields & wrong sender
    other = IdentityManager(tmp_path / "other", "other-node").generate()
    crypto = CryptoAgilityEngine(device_identity)
    crit_env = crypto.encrypt(
        b"secret", device_identity.public_bundle(), ThreatTier.QUANTUM_CRITICAL
    )
    with pytest.raises(ValueError, match="missing mandatory PQC signature"):
        crypto.decrypt(crit_env.model_copy(update={"signature_b64": None}))
    with pytest.raises(ValueError, match="expected sender"):
        crypto.decrypt(crit_env, expected_sender=other.public_bundle())

    elev_env = crypto.encrypt(b"secret", device_identity.public_bundle(), ThreatTier.ELEVATED)
    with pytest.raises(ValueError, match="requires ML-KEM ciphertext"):
        crypto.decrypt(elev_env.model_copy(update={"kem_ciphertext_b64": None}))

    # Features empty byte helpers
    assert shannon_entropy_bytes(b"") == 0.0
    assert printable_ascii_ratio(b"") == 1.0

    # NIST test edge cases + M=128 longest run branch (>= 6272 bits = 800 bytes)
    big_bits = bytes_to_bits(os.urandom(800))
    res_m128 = longest_run_of_ones_test(big_bits)
    assert res_m128.detail.endswith("M=128")
    with pytest.raises(ValueError, match="100 bits"):
        frequency_monobit_test(bytes_to_bits(b"\x01"))
    with pytest.raises(ValueError, match="Insufficient bits"):
        block_frequency_test(bytes_to_bits(b"\x01"), block_size=16)
    with pytest.raises(ValueError, match="100 bits"):
        runs_test(bytes_to_bits(b"\x01"))
    with pytest.raises(ValueError, match="128 bits"):
        longest_run_of_ones_test(bytes_to_bits(b"\x01" * 4))
    with pytest.raises(ValueError, match="2 bytes"):
        repetition_count_test(b"\x00")
    with pytest.raises(ValueError, match="16 bytes"):
        adaptive_proportion_test(b"\x00" * 4)

    # QRNG validation errors
    with pytest.raises(ValueError, match="between 4 and 16"):
        QiskitHadamardQrngSource(num_qubits=2)
    with pytest.raises(ValueError, match="At least one"):
        xor_mix_streams([])
    with pytest.raises(ValueError, match="cannot be empty"):
        xor_mix_streams([b""])
    with pytest.raises(ValueError, match="identical byte lengths"):
        xor_mix_streams([b"\x01", b"\x01\x02"])

    # PKCS11Sealer mismatch backend check
    sealer = PKCS11Sealer(library_path=tmp_path / "missing.so")
    assert sealer.is_available() is False
    assert sealer.list_slots() == []
    with pytest.raises(ValueError, match="Expected pkcs11"):
        sealer.unseal(
            SealedBlob(
                backend="tpm2",
                key_label="k",
                wrapped_dek_b64="AA==",
                kek_iv_b64="AA==",
                gcm_nonce_b64="AA==",
                ciphertext_b64="AA==",
            )
        )


@pytest.mark.quantum
async def test_qubo_edge_cases_and_large_canonicalization(tmp_path: Path) -> None:
    # Single-node QUBO (n=1)
    single = QuboProblem(problem_type="single", num_variables=1, matrix=[[-2.0]])
    h_single, perm_single = canonicalize_qubo(single)
    assert len(h_single) == 64 and perm_single == (0,)
    assert evaluate_qubo(single, "1") == pytest.approx(-2.0)
    assert evaluate_ising(qubo_to_ising(single), "1") == pytest.approx(-2.0)

    # Disconnected 4-node graph (only edge 0-1; nodes 2 and 3 isolated)
    disc_a = build_maxcut_qubo(4, [(0, 1, 2.0)])
    disc_b = build_maxcut_qubo(4, [(2, 3, 2.0)])
    assert canonicalize_qubo(disc_a)[0] == canonicalize_qubo(disc_b)[0]

    # Empty graph (zero edges)
    empty_g = build_maxcut_qubo(3, [])
    assert len(canonicalize_qubo(empty_g)[0]) == 64

    # Large QUBO (n=8 -> spectral degree sorting branch)
    large_edges = [(i, (i + 1) % 8, 1.0 + 0.1 * i) for i in range(8)]
    large_qubo = build_maxcut_qubo(8, large_edges)
    large_hash, large_perm = canonicalize_qubo(large_qubo)
    assert len(large_hash) == 64 and len(large_perm) == 8

    # Validation error branches
    with pytest.raises(ValueError, match="row count"):
        QuboProblem(problem_type="bad", num_variables=2, matrix=[[1.0, 0.0]])
    with pytest.raises(ValueError, match="square"):
        QuboProblem(problem_type="bad", num_variables=2, matrix=[[1.0], [2.0]])
    with pytest.raises(ValueError, match="bitstring"):
        evaluate_qubo(single, "01")
    with pytest.raises(ValueError, match="bitstring"):
        evaluate_ising(qubo_to_ising(single), "01")
    with pytest.raises(ValueError, match="Invalid edge"):
        build_maxcut_qubo(2, [(0, 0, 1.0)])
    with pytest.raises(ValueError, match="equal length"):
        build_resource_allocation_qubo([1.0, 2.0], [1.0])

    # Mitigation error branches
    ham = qubo_to_ising(disc_a)
    qc = build_qaoa_circuit(ham, [0.3], [0.2], measure=True)
    with pytest.raises(ValueError, match="odd positive"):
        fold_circuit_unitary(qc, 2)
    with pytest.raises(ValueError, match="at least 2"):
        extrapolate_zero_noise([1], [-1.0])
    assert extrapolate_zero_noise([1, 3], [-2.0, -1.0], method="exponential") == pytest.approx(-2.5)
    none_res = ErrorMitigationPipeline(
        AerNoisyBackend().simulator, mode="none"
    ).evaluate_expectation(qc, ham, shots=128)
    assert none_res.mitigated_energy == none_res.unmitigated_energy

    # Tampered federated broadcast rejected by apply_federated_broadcast
    coord = IdentityManager(tmp_path / "c", "coord").generate()
    sched = FederatedScheduler(coord, QaoaSolver(backend=AerStatevectorBackend()))
    sched.submit(FederatedJobSubmission(node_id="n1", policy_name="p", qubo=disc_a))
    rep = sched.run_federated_cycle()
    bad_bcast = rep.broadcasts[0].model_copy(update={"optimal_bitstring": "1111"})
    store = StorageEngine(tmp_path / "fed.db")
    await store.initialize()
    try:
        with pytest.raises(ValueError, match="signature verification failed"):
            await apply_federated_broadcast(
                bad_bcast,
                coord.public_bundle(),
                PolicyUpdater(store),
                lambda _w: 1.0,
            )
    finally:
        await store.close()


@pytest.mark.integration
async def test_all_module_rpc_handlers_bus_errors_and_mqtt_paths(
    event_bus: EventBus,
    device_identity: DeviceIdentity,
    storage: StorageEngine,
    lifecycle: LifecycleManager,
    metrics: QAegisMetrics,
    tmp_path: Path,
) -> None:
    # EventBus error paths
    with pytest.raises(KeyError, match="No request responder"):
        await event_bus.request("missing.topic", {})

    async def failing_responder(_env: EventEnvelope) -> dict[str, str]:
        raise RuntimeError("boom")

    event_bus.register_responder("rpc.fail", failing_responder)
    with pytest.raises(RuntimeError, match="boom"):
        await event_bus.request("rpc.fail", {})

    # Curve keypair reload & permission error
    kp1 = load_or_create_curve_keypair(tmp_path / "ck", name="n")
    kp2 = load_or_create_curve_keypair(tmp_path / "ck", name="n")
    assert kp1.public_key == kp2.public_key
    sec_f = tmp_path / "ck" / "n.curve.secret.json"
    os.chmod(sec_f, 0o644)
    with pytest.raises(PermissionError):
        load_or_create_curve_keypair(tmp_path / "ck", name="n")
    os.chmod(sec_f, 0o600)

    # Module 1 RPC: reality_stamp.create & reality_stamp.verify
    rs_svc = RealityStampService(
        event_bus,
        device_identity,
        storage,
        RealityStampConfig(strict_nist_checks=False),
        metrics=metrics,
    )
    await rs_svc.start()
    created = await event_bus.request(
        "reality_stamp.create",
        {"sensor_id": "s1", "perception_label": "ok", "confidence": 0.91},
    )
    verified = await event_bus.request("reality_stamp.verify", created.payload)
    assert verified.payload["valid"] is True
    await rs_svc.stop()

    # Module 2 RPC: chameleon.protect & chameleon.unprotect + minimum_tier floor
    fw = ChameleonFirewallService(event_bus, device_identity, metrics=metrics)
    await fw.start()
    assert fw.detector is not None and fw.crypto_engine is not None
    floor_pkt = await fw.protect(
        TrafficObservation(
            source="a",
            destination="b",
            protocol="lan",
            sensitivity="public",
            payload_bytes=b"hello",
        ),
        recipient=device_identity.public_bundle(),
        minimum_tier=ThreatTier.ELEVATED,
    )
    assert floor_pkt.envelope.tier == ThreatTier.ELEVATED

    prot_reply = await event_bus.request(
        "chameleon.protect",
        {
            "payload_b64": base64.b64encode(b"rpc-secret").decode("ascii"),
            "recipient": device_identity.public_bundle().model_dump(mode="json"),
            "sensitivity": "confidential",
        },
    )
    unprot_reply = await event_bus.request(
        "chameleon.unprotect",
        {
            "envelope": prot_reply.payload["envelope"],
            "expected_sender": device_identity.public_bundle().model_dump(mode="json"),
        },
    )
    assert base64.b64decode(unprot_reply.payload["plaintext_b64"]) == b"rpc-secret"

    # Module 3 RPC: compiler.build_qubo (maxcut, scheduling, invalid)
    comp = QubitCompilerService(event_bus, input_dim=4)
    await comp.start()
    assert comp.pipeline is not None and comp.builder is not None
    q_mc = await event_bus.request(
        "compiler.build_qubo",
        {"problem_type": "maxcut", "num_nodes": 3, "edges": [[0, 1, 1.0], [1, 2, 1.0]]},
    )
    assert q_mc.payload["num_variables"] == 3
    q_sc = await event_bus.request(
        "compiler.build_qubo",
        {
            "problem_type": "scheduling",
            "task_costs": [1.0, 2.0, 3.0],
            "conflicts": [[0, 1]],
            "target_active_tasks": 2,
        },
    )
    assert q_sc.payload["problem_type"] == "edge_task_scheduling"
    with pytest.raises(ValueError, match="Unsupported QUBO"):
        await event_bus.request("compiler.build_qubo", {"problem_type": "invalid"})

    # Module 4 RPC: dreamer.enqueue & dreamer.run_night_cycle + mark_failed
    dreamer = QuantumDreamerService(
        event_bus,
        storage,
        lifecycle,
        config=QuantumDreamerConfig(qaoa_reps=1, max_optimizer_iters=15),
        metrics=metrics,
    )
    await dreamer.start()
    assert dreamer.queue is not None and dreamer.updater is not None
    enq = await event_bus.request(
        "dreamer.enqueue",
        {"qubo": q_mc.payload, "priority": 80, "policy_name": "rpc_policy"},
    )
    assert enq.payload["status"] == "PENDING"
    night_rep = await event_bus.request(
        "dreamer.run_night_cycle",
        {"max_problems": 2},
        timeout_s=30.0,
    )
    assert night_rep.payload["problems_processed"] == 1
    await dreamer.queue.mark_failed("nonexistent-id", "test-err")

    # Module 5 RPC: entropy.harvest & entropy.sample_logits + pool stretch
    ent_svc = QuantumEntropyService(event_bus, metrics=metrics)
    await ent_svc.start()
    assert ent_svc.harvester is not None and ent_svc.ollama is not None
    harv = await event_bus.request("entropy.harvest", {"num_qubits": 4, "shots": 128})
    assert harv.payload["pool_bytes"] >= 256
    samp = await event_bus.request(
        "entropy.sample_logits",
        {"logits": [0.1, 2.0, 0.5], "temperature": 0.7, "top_k": 2, "top_p": 0.9},
    )
    assert samp.payload["token_index"] in (0, 1, 2)
    with pytest.raises(ValueError, match="at least 32"):
        QuantumEntropyPool(b"\x01" * 8)

    # MQTT Bridge non-JSON text ingest, encode, and callbacks
    mqtt_b = AsyncMqttBridge(
        event_bus,
        MqttBridgeConfig(username="u", password="p", topic_prefix="qaegis"),
    )
    assert mqtt_b.is_connected is False
    env = EventEnvelope(topic="reality_stamp.created", source="test", payload={"id": "1"})
    t_out, b_out = mqtt_b.encode_envelope_for_mqtt(env)
    assert t_out == "qaegis/reality_stamp/created" and len(b_out) > 10
    sub_txt = event_bus.subscribe("raw.line")
    await mqtt_b.ingest_mqtt_payload("qaegis/raw/line", b"plain-text-not-json")
    rec_txt = sub_txt.queue.get_nowait()
    assert rec_txt.payload["raw_text"] == "plain-text-not-json"
    await event_bus.unsubscribe(sub_txt)
    mqtt_b._on_disconnect(mqtt_b._client, None, None, None, None)

    # HttpQrngSource error path (unreachable URL handled cleanly)
    http_src = HttpQrngSource("http://127.0.0.1:1/unreachable", timeout_s=0.1)
    assert "http_qrng:" in http_src.name
    with pytest.raises(httpx.HTTPError):
        await http_src.fetch_bytes(32)
