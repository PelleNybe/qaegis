"""Reproducible benchmark suite for Q-Aegis (PQC, HSM, CurveZMQ, Gossip, QAOA, ZNE/TREX)."""

from __future__ import annotations

import asyncio
import json
import os
import platform
import shutil
import statistics
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import oqs
import psutil
import qiskit
import torch
from qiskit_aer import AerSimulator
from qiskit_aer.noise import NoiseModel, ReadoutError, depolarizing_error
from rich.console import Console
from rich.table import Table

from qaegis import __version__
from qaegis.core.bus import EventBus, generate_curve_keypair
from qaegis.core.config import BusConfig, QAegisConfig, QuantumDreamerConfig, RealityStampConfig
from qaegis.core.hardware_seal import PKCS11Sealer, detect_pkcs11_library
from qaegis.core.identity import IdentityManager
from qaegis.core.storage import StorageEngine
from qaegis.modules.chameleon_fw.crypto_agility import CryptoAgilityEngine
from qaegis.modules.chameleon_fw.detector import ThreatTier
from qaegis.modules.quantum_dreamer.mitigation import ErrorMitigationPipeline
from qaegis.modules.quantum_dreamer.solvers import (
    AerNoisyBackend,
    AerStatevectorBackend,
    QaoaSolver,
    build_qaoa_circuit,
)
from qaegis.modules.quantum_entropy.harvester import QuantumDistributionHarvester
from qaegis.modules.qubit_compiler.autoencoder import AngleEncoderPipeline
from qaegis.modules.qubit_compiler.circuit_builder import (
    BackendNoiseProfile,
    NoiseAwareCircuitBuilder,
)
from qaegis.modules.qubit_compiler.qubo_mapper import (
    build_maxcut_qubo,
    evaluate_ising,
    qubo_to_ising,
)
from qaegis.modules.reality_stamp.gossip import MerkleGossipNode
from qaegis.modules.reality_stamp.merkle import MerkleTree
from qaegis.modules.reality_stamp.service import RealityStampService

console = Console()


def _bench_fn(fn: Any, iterations: int) -> dict[str, float]:
    times_ms: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        times_ms.append((time.perf_counter() - t0) * 1000.0)
    times_ms.sort()
    p95_idx = min(len(times_ms) - 1, int(0.95 * len(times_ms)))
    mean_ms = statistics.mean(times_ms)
    return {
        "mean_ms": round(mean_ms, 3),
        "p95_ms": round(times_ms[p95_idx], 3),
        "ops_per_sec": round(1000.0 / mean_ms, 1) if mean_ms > 0 else 0.0,
    }


async def _bench_curvezmq() -> dict[str, float]:
    srv_kp = generate_curve_keypair()
    cli_kp = generate_curve_keypair()
    srv = EventBus(
        config=BusConfig(
            transport="zmq",
            zmq_pub_endpoint="tcp://127.0.0.1:0",
            zmq_bind_pub=True,
            zmq_connect_sub=False,
            zmq_security="curve",
            zmq_allowed_peer_keys=[cli_kp.public_key],
        ),
        curve_keypair=srv_kp,
    )
    await srv.start()
    assert srv.bound_pub_endpoint is not None
    cli = EventBus(
        config=BusConfig(
            transport="zmq",
            zmq_sub_endpoint=srv.bound_pub_endpoint,
            zmq_bind_pub=False,
            zmq_connect_sub=True,
            zmq_security="curve",
            zmq_server_public_key=srv_kp.public_key,
        ),
        curve_keypair=cli_kp,
    )
    await cli.start()
    sub = cli.subscribe("bench.curve")
    try:
        await asyncio.sleep(0.35)
        # Warm-up message to confirm subscription handshake
        for _ in range(5):
            await srv.publish("bench.curve", {"warmup": True})
            await asyncio.sleep(0.02)
            if not sub.queue.empty():
                while not sub.queue.empty():
                    sub.queue.get_nowait()
                break

        n_msgs = 200
        t0 = time.perf_counter()
        for idx in range(n_msgs):
            await srv.publish("bench.curve", {"seq": idx})
        received = 0
        while received < n_msgs:
            await asyncio.wait_for(sub.queue.get(), timeout=5.0)
            received += 1
        elapsed = time.perf_counter() - t0
        return {
            "messages": float(n_msgs),
            "total_ms": round(elapsed * 1000.0, 2),
            "mean_ms_per_msg": round((elapsed * 1000.0) / n_msgs, 3),
            "throughput_msgs_per_sec": round(n_msgs / elapsed, 1),
        }
    finally:
        await cli.stop()
        await srv.stop()


async def _bench_gossip_3node(tmp: Path) -> dict[str, float]:
    names = ("g-alpha", "g-beta", "g-gamma")
    buses: list[EventBus] = []
    stores: list[StorageEngine] = []
    nodes: list[MerkleGossipNode] = []
    for name in names:
        bus = EventBus()
        store = StorageEngine(tmp / f"{name}.db")
        ident = IdentityManager(tmp / f"{name}_k", name).generate()
        await bus.start()
        await store.initialize()
        buses.append(bus)
        stores.append(store)
        nodes.append(MerkleGossipNode(ident, store, bus))

    curve_keys = [n.curve_public_key for n in nodes]
    endpoints = [
        await n.start_mesh("tcp://127.0.0.1:0", allowed_curve_keys=curve_keys) for n in nodes
    ]
    for i, ni in enumerate(nodes):
        for j, nj in enumerate(nodes):
            if i != j:
                ni.register_trusted_peer(nj._identity.public_bundle(), nj.curve_public_key)
                await ni.connect_peer(endpoints[j], nj.curve_public_key)
    try:
        await asyncio.sleep(0.4)
        tree = MerkleTree()
        for k in range(5):
            tree.append_raw(f"gossip-bench-{k}".encode())
        t0 = time.perf_counter()
        cp = nodes[0].create_checkpoint(tree.root_hex, tree.size)
        await nodes[0].broadcast_checkpoint(cp)
        deadline = asyncio.get_running_loop().time() + 4.0
        while asyncio.get_running_loop().time() < deadline:
            if all("g-alpha" in n.latest_roots for n in nodes):
                break
            await asyncio.sleep(0.005)
        conv_ms = (time.perf_counter() - t0) * 1000.0
        return {
            "nodes": 3.0,
            "convergence_ms": round(conv_ms, 2),
        }
    finally:
        for n in nodes:
            await n.stop_mesh()
        for s in stores:
            await s.close()
        for b in buses:
            await b.stop()


async def run_all_benchmarks(output_json: Path | None = None) -> dict[str, Any]:
    """Execute the full Q-Aegis benchmark suite and return structured results."""
    proc = psutil.Process(os.getpid())
    results: dict[str, Any] = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "environment": {
            "platform": f"{platform.system()} {platform.machine()}",
            "python": platform.python_version(),
            "cpu_count_logical": psutil.cpu_count(logical=True),
            "ram_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "liboqs": str(oqs.oqs_version()),
            "qiskit": qiskit.__version__,
            "torch": torch.__version__,
        },
        "pqc_primitives": {},
        "chameleon_tiers": {},
        "reality_stamp": {},
        "qubit_compiler": {},
        "quantum_dreamer": {},
        "quantum_entropy": {},
        "v02_v03_platform": {},
    }

    with tempfile.TemporaryDirectory(prefix="qaegis-bench-") as tmp_str:
        tmp = Path(tmp_str)
        cfg = QAegisConfig(
            node_id="bench-node",
            data_dir=tmp / "data",
            keys_dir=tmp / "keys",
            db_path=tmp / "data" / "bench.db",
            reality_stamp=RealityStampConfig(strict_nist_checks=False),
        )
        cfg.ensure_directories()
        alice = IdentityManager(tmp / "alice", "alice", cfg.identity).generate()
        bob = IdentityManager(tmp / "bob", "bob", cfg.identity).generate()
        payload = os.urandom(1024)

        # 1. PQC Primitives
        mldsa_alg, mldsa_sig = alice.sign(payload, use_fallback=False)
        slh_alg, slh_sig = alice.sign(payload, use_fallback=True)

        results["pqc_primitives"]["ml_dsa_65_sign"] = {
            **_bench_fn(lambda: alice.sign(payload, use_fallback=False), 50),
            "public_key_bytes": len(alice.primary_sig_public),
            "signature_bytes": len(mldsa_sig),
        }
        results["pqc_primitives"]["ml_dsa_65_verify"] = _bench_fn(
            lambda: alice.verify(payload, mldsa_sig, alice.primary_sig_public, mldsa_alg),
            50,
        )
        results["pqc_primitives"]["slh_dsa_128f_sign"] = {
            **_bench_fn(lambda: alice.sign(payload, use_fallback=True), 10),
            "public_key_bytes": len(alice.fallback_sig_public),
            "signature_bytes": len(slh_sig),
        }
        results["pqc_primitives"]["slh_dsa_128f_verify"] = _bench_fn(
            lambda: alice.verify(payload, slh_sig, alice.fallback_sig_public, slh_alg),
            20,
        )

        with oqs.KeyEncapsulation(bob.kem_alg) as sender_kem:
            ct_sample, _ = sender_kem.encap_secret(bob.kem_public)

            def _kem_roundtrip() -> None:
                ct, _ss = sender_kem.encap_secret(bob.kem_public)
                _ = bob.decap_kem(ct)

            results["pqc_primitives"]["ml_kem_768_encap_decap"] = {
                **_bench_fn(_kem_roundtrip, 100),
                "public_key_bytes": len(bob.kem_public),
                "ciphertext_bytes": len(ct_sample),
            }

        # 2. Chameleon Adaptive Encryption Tiers
        alice_crypto = CryptoAgilityEngine(alice, cfg.chameleon_fw)
        bob_crypto = CryptoAgilityEngine(bob, cfg.chameleon_fw)
        bob_pub = bob.public_bundle()
        alice_pub = alice.public_bundle()

        for tier in (ThreatTier.STANDARD, ThreatTier.ELEVATED, ThreatTier.QUANTUM_CRITICAL):
            sample_env = alice_crypto.encrypt(payload, bob_pub, tier)
            wire_bytes = len(sample_env.model_dump_json().encode("utf-8"))

            def _roundtrip(t: ThreatTier = tier) -> None:
                env = alice_crypto.encrypt(payload, bob_pub, t)
                bob_crypto.decrypt(env, expected_sender=alice_pub)

            results["chameleon_tiers"][tier.value] = {
                **_bench_fn(_roundtrip, 30),
                "envelope_json_bytes": wire_bytes,
            }

        # 3. Proof-of-Reality End-to-End Stamp
        bus = EventBus(config=cfg.bus)
        storage = StorageEngine(cfg.db_path)
        await bus.start()
        await storage.initialize()
        stamp_svc = RealityStampService(
            bus=bus,
            identity=alice,
            storage=storage,
            config=cfg.reality_stamp,
        )
        await stamp_svc.start()
        stamp_times: list[float] = []
        for i in range(10):
            t0 = time.perf_counter()
            await stamp_svc.stamp_perception("cam0", "vehicle", 0.94, metadata={"frame": i})
            stamp_times.append((time.perf_counter() - t0) * 1000.0)
        await stamp_svc.stop()
        await storage.close()
        await bus.stop()
        stamp_times.sort()
        results["reality_stamp"]["e2e_stamp_mldsa65"] = {
            "mean_ms": round(statistics.mean(stamp_times), 3),
            "p95_ms": round(
                stamp_times[min(len(stamp_times) - 1, int(0.95 * len(stamp_times)))], 3
            ),
            "ops_per_sec": round(1000.0 / statistics.mean(stamp_times), 1),
        }

        # 4. AI-to-Qubit Compiler
        rng = np.random.default_rng(42)
        samples = rng.normal(0.0, 1.0, size=(64, 16)).astype(np.float32)
        pipe = AngleEncoderPipeline(input_dim=16, num_qubits=4, hidden_dim=32)
        pipe.train(samples, epochs=25)
        vec = samples[0]
        results["qubit_compiler"]["pytorch_encode_4q"] = _bench_fn(
            lambda: pipe.encode_to_angles(vec),
            100,
        )
        onnx_path = tmp / "encoder.onnx"
        pipe.export_onnx(onnx_path)
        pipe.load_onnx(onnx_path)
        results["qubit_compiler"]["onnxruntime_encode_4q"] = _bench_fn(
            lambda: pipe.encode_to_angles(vec),
            100,
        )
        angles_sample = pipe.encode_to_angles(vec)
        builder = NoiseAwareCircuitBuilder(BackendNoiseProfile())
        results["qubit_compiler"]["qiskit_transpile_qasm3_4q"] = _bench_fn(
            lambda: builder.build_qiskit_circuit(angles_sample),
            20,
        )

        # 5. Quantum Dreaming QAOA Convergence
        qubo_4 = build_maxcut_qubo(4, [(0, 1, 1.5), (1, 2, 1.5), (2, 3, 1.5), (3, 0, 1.5)])
        qubo_6 = build_maxcut_qubo(
            6,
            [
                (0, 1, 1.0),
                (1, 2, 1.5),
                (2, 3, 1.0),
                (3, 4, 1.5),
                (4, 5, 1.0),
                (5, 0, 1.5),
                (0, 3, 1.0),
            ],
        )
        sol_4_sv = QaoaSolver(
            QuantumDreamerConfig(qaoa_reps=2, max_optimizer_iters=40),
            AerStatevectorBackend(),
        ).solve(qubo_4)
        sol_6_sv = QaoaSolver(
            QuantumDreamerConfig(qaoa_reps=2, max_optimizer_iters=45),
            AerStatevectorBackend(),
        ).solve(qubo_6)
        sol_4_noisy = QaoaSolver(
            QuantumDreamerConfig(qaoa_reps=1, qaoa_shots=512, max_optimizer_iters=25),
            AerNoisyBackend(),
        ).solve(qubo_4)

        results["quantum_dreamer"]["qaoa_4q_statevector"] = {
            "solve_time_ms": round(sol_4_sv.solve_time_s * 1000.0, 2),
            "optimal_energy": round(sol_4_sv.optimal_energy, 3),
            "exact_ground_energy": sol_4_sv.exact_ground_energy,
            "approximation_ratio": round(sol_4_sv.approximation_ratio or 0.0, 4),
        }
        results["quantum_dreamer"]["qaoa_6q_statevector"] = {
            "solve_time_ms": round(sol_6_sv.solve_time_s * 1000.0, 2),
            "optimal_energy": round(sol_6_sv.optimal_energy, 3),
            "exact_ground_energy": sol_6_sv.exact_ground_energy,
            "approximation_ratio": round(sol_6_sv.approximation_ratio or 0.0, 4),
        }
        results["quantum_dreamer"]["qaoa_4q_noisy_aer"] = {
            "solve_time_ms": round(sol_4_noisy.solve_time_s * 1000.0, 2),
            "optimal_energy": round(sol_4_noisy.optimal_energy, 3),
            "exact_ground_energy": sol_4_noisy.exact_ground_energy,
            "approximation_ratio": round(sol_4_noisy.approximation_ratio or 0.0, 4),
        }

        # 6. Quantum Entropy Harvester
        harvester = QuantumDistributionHarvester()
        t0 = time.perf_counter()
        batch, _pool = await harvester.harvest_batch(num_qubits=6, shots=512)
        harvest_ms = (time.perf_counter() - t0) * 1000.0
        results["quantum_entropy"]["harvest_6q_512shots"] = {
            "latency_ms": round(harvest_ms, 2),
            "shannon_entropy_bits": round(batch.shannon_entropy_bits, 4),
            "pool_bytes": batch.pool_bytes,
        }

        # 7. v0.2 PKCS#11 SoftHSM2 Key Seal / Unseal Latency
        lib_path = detect_pkcs11_library()
        softhsm_bin = shutil.which("softhsm2-util")
        if lib_path is not None and softhsm_bin is not None:

            def _bench_softhsm() -> tuple[dict[str, float], dict[str, float]]:
                tok_dir = tmp / "softhsm_tokens"
                tok_dir.mkdir(mode=0o700)
                conf_path = tmp / "softhsm2.conf"
                conf_path.write_text(
                    (
                        f"directories.tokendir = {tok_dir}\n"
                        "objectstore.backend = file\n"
                        "log.level = ERROR\n"
                    ),
                    encoding="utf-8",
                )
                env = {**os.environ, "SOFTHSM2_CONF": str(conf_path)}
                subprocess.run(  # noqa: S603
                    [
                        softhsm_bin,
                        "--init-token",
                        "--free",
                        "--label",
                        "qaegis-bench-hsm",
                        "--so-pin",
                        "1234",
                        "--pin",
                        "5678",
                    ],
                    env=env,
                    check=True,
                    capture_output=True,
                )
                prev_conf = os.environ.get("SOFTHSM2_CONF")
                os.environ["SOFTHSM2_CONF"] = str(conf_path)
                try:
                    sealer = PKCS11Sealer(
                        token_label="qaegis-bench-hsm",
                        user_pin="5678",
                        library_path=lib_path,
                    )
                    secret_blob = os.urandom(6144)
                    sample_sealed = sealer.seal(secret_blob)
                    return (
                        _bench_fn(lambda: sealer.seal(secret_blob), 20),
                        _bench_fn(lambda: sealer.unseal(sample_sealed), 20),
                    )
                finally:
                    if prev_conf is None:
                        os.environ.pop("SOFTHSM2_CONF", None)
                    else:
                        os.environ["SOFTHSM2_CONF"] = prev_conf

            seal_stats, unseal_stats = await asyncio.to_thread(_bench_softhsm)
            results["v02_v03_platform"]["pkcs11_softhsm2_seal"] = seal_stats
            results["v02_v03_platform"]["pkcs11_softhsm2_unseal"] = unseal_stats

        # 8. v0.2 CurveZMQ Authenticated Event Bus Throughput
        results["v02_v03_platform"]["curvezmq_authenticated_bus"] = await _bench_curvezmq()

        # 9. v0.3 3-Node ML-DSA-65 Merkle Root Gossip Convergence
        results["v02_v03_platform"]["merkle_gossip_3node"] = await _bench_gossip_3node(tmp)

        # 10. v0.3 Error Mitigation (Unmitigated vs ZNE vs TREX vs ZNE+TREX on noisy Aer)
        ham_4 = qubo_to_ising(qubo_4)
        g_opt = [0.45, 0.70]
        b_opt = [0.55, 0.25]
        qc_mit = build_qaoa_circuit(ham_4, g_opt, b_opt, measure=True)
        sv_dist = AerStatevectorBackend().sample_distribution(ham_4, g_opt, b_opt, shots=1)
        exact_e = sum(p * evaluate_ising(ham_4, bs) for bs, p in sv_dist.items())

        nm = NoiseModel()
        nm.add_all_qubit_quantum_error(depolarizing_error(0.005, 1), ["h", "rx", "ry", "rz", "x"])
        nm.add_all_qubit_quantum_error(depolarizing_error(0.025, 2), ["cx", "rzz"])
        nm.add_all_qubit_readout_error(ReadoutError([[0.96, 0.04], [0.14, 0.86]]))
        noisy_sim = AerSimulator(noise_model=nm)

        trex_res = ErrorMitigationPipeline(
            noisy_sim, mode="trex", num_twirls=16, seed=42
        ).evaluate_expectation(qc_mit, ham_4, shots=4096)
        zne_res = ErrorMitigationPipeline(
            noisy_sim, mode="zne", scale_factors=[1, 3, 5], extrapolation="linear", seed=42
        ).evaluate_expectation(qc_mit, ham_4, shots=4096)
        both_res = ErrorMitigationPipeline(
            noisy_sim,
            mode="both",
            scale_factors=[1, 3, 5],
            extrapolation="linear",
            num_twirls=16,
            seed=42,
        ).evaluate_expectation(qc_mit, ham_4, shots=4096)

        raw_err = abs(both_res.unmitigated_energy - exact_e)
        trex_err = abs(trex_res.mitigated_energy - exact_e)
        zne_err = abs(zne_res.mitigated_energy - exact_e)
        both_err = abs(both_res.mitigated_energy - exact_e)
        results["v02_v03_platform"]["error_mitigation_noisy_aer"] = {
            "exact_statevector_energy": round(exact_e, 4),
            "unmitigated_energy": round(both_res.unmitigated_energy, 4),
            "unmitigated_abs_error": round(raw_err, 4),
            "trex_energy": round(trex_res.mitigated_energy, 4),
            "trex_abs_error": round(trex_err, 4),
            "zne_energy": round(zne_res.mitigated_energy, 4),
            "zne_abs_error": round(zne_err, 4),
            "zne_trex_energy": round(both_res.mitigated_energy, 4),
            "zne_trex_abs_error": round(both_err, 4),
            "error_reduction_pct": round((1.0 - both_err / max(raw_err, 1e-9)) * 100.0, 1),
        }

    results["environment"]["process_rss_mb"] = round(proc.memory_info().rss / (1024**2), 1)

    if output_json is not None:
        rendered = json.dumps(results, indent=2)

        def _write() -> None:
            output_json.parent.mkdir(parents=True, exist_ok=True)
            output_json.write_text(rendered, encoding="utf-8")

        await asyncio.to_thread(_write)

    return results


def _print_summary(results: dict[str, Any]) -> None:
    table = Table(title=f"Q-Aegis v{__version__} Real Hardware Benchmark Summary")
    table.add_column("Subsystem / Operation", style="cyan")
    table.add_column("Metric", style="green")
    for name, stats in results["pqc_primitives"].items():
        table.add_row(f"PQC: {name}", f"{stats['mean_ms']} ms (p95 {stats['p95_ms']} ms)")
    for tier, stats in results["chameleon_tiers"].items():
        table.add_row(
            f"Chameleon: {tier}",
            f"{stats['mean_ms']} ms ({stats['envelope_json_bytes']} B JSON)",
        )
    rs = results["reality_stamp"]["e2e_stamp_mldsa65"]
    table.add_row("RealityStamp: E2E ML-DSA-65", f"{rs['mean_ms']} ms ({rs['ops_per_sec']} ops/s)")
    v = results["v02_v03_platform"]
    if "pkcs11_softhsm2_seal" in v:
        seal_ms = v["pkcs11_softhsm2_seal"]["mean_ms"]
        unseal_ms = v["pkcs11_softhsm2_unseal"]["mean_ms"]
        table.add_row("PKCS#11 SoftHSM2 Seal / Unseal", f"{seal_ms} ms / {unseal_ms} ms")
    cz = v["curvezmq_authenticated_bus"]
    table.add_row(
        "CurveZMQ Authenticated Bus",
        f"{cz['throughput_msgs_per_sec']} msgs/s ({cz['mean_ms_per_msg']} ms/msg)",
    )
    gs = v["merkle_gossip_3node"]
    table.add_row("3-Node ML-DSA-65 Merkle Gossip", f"{gs['convergence_ms']} ms convergence")
    em = v["error_mitigation_noisy_aer"]
    mit_summary = (
        f"err {em['unmitigated_abs_error']} -> {em['zne_trex_abs_error']} "
        f"(-{em['error_reduction_pct']}%)"
    )
    table.add_row("Error Mitigation (Raw -> ZNE+TREX)", mit_summary)
    table.add_row("Process RSS Memory", f"{results['environment']['process_rss_mb']} MB")
    console.print(table)


if __name__ == "__main__":
    out_path = Path(__file__).resolve().parent / "results.json"
    summary = asyncio.run(run_all_benchmarks(output_json=out_path))
    _print_summary(summary)
