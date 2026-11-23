"""Reproducible benchmark suite for Q-Aegis (PQC, Chameleon, Compiler, QAOA, Entropy)."""

from __future__ import annotations

import asyncio
import json
import os
import platform
import statistics
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
from rich.console import Console
from rich.table import Table

from qaegis.core.bus import EventBus
from qaegis.core.config import QAegisConfig, QuantumDreamerConfig, RealityStampConfig
from qaegis.core.identity import IdentityManager
from qaegis.core.storage import StorageEngine
from qaegis.modules.chameleon_fw.crypto_agility import CryptoAgilityEngine
from qaegis.modules.chameleon_fw.detector import ThreatTier
from qaegis.modules.quantum_dreamer.solvers import (
    AerNoisyBackend,
    AerStatevectorBackend,
    QaoaSolver,
)
from qaegis.modules.quantum_entropy.harvester import QuantumDistributionHarvester
from qaegis.modules.qubit_compiler.autoencoder import AngleEncoderPipeline
from qaegis.modules.qubit_compiler.circuit_builder import (
    BackendNoiseProfile,
    NoiseAwareCircuitBuilder,
)
from qaegis.modules.qubit_compiler.qubo_mapper import build_maxcut_qubo
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
                bob.decap_secret_val = bob.decap_kem(ct)  # type: ignore[attr-defined]

            results["pqc_primitives"]["ml_kem_768_encap_decap"] = {
                **_bench_fn(_kem_roundtrip, 100),
                "public_key_bytes": len(bob.kem_public),
                "ciphertext_bytes": len(ct_sample),
            }

        # 2. Chameleon Adaptive Encryption Tiers (1 KB payload)
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

        # 3. Proof-of-Reality End-to-End Stamp (QRNG + ML-DSA-65 + Merkle + SQLite WAL)
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

        # 4. AI-to-Qubit Compiler (PyTorch vs ONNX Runtime + Qiskit OpenQASM 3.0)
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

    results["environment"]["process_rss_mb"] = round(proc.memory_info().rss / (1024**2), 1)

    if output_json is not None:
        rendered = json.dumps(results, indent=2)

        def _write() -> None:
            output_json.parent.mkdir(parents=True, exist_ok=True)
            output_json.write_text(rendered, encoding="utf-8")

        await asyncio.to_thread(_write)

    return results


def _print_summary(results: dict[str, Any]) -> None:
    table = Table(title="Q-Aegis Real Hardware Benchmark Summary")
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
    for name, stats in results["qubit_compiler"].items():
        table.add_row(f"Compiler: {name}", f"{stats['mean_ms']} ms")
    for name, stats in results["quantum_dreamer"].items():
        table.add_row(
            f"Dreamer: {name}",
            f"{stats['solve_time_ms']} ms (ratio={stats['approximation_ratio']})",
        )
    qe = results["quantum_entropy"]["harvest_6q_512shots"]
    table.add_row(
        "Entropy: 6q/512 shots",
        f"{qe['latency_ms']} ms (H={qe['shannon_entropy_bits']} bits)",
    )
    table.add_row("Process RSS Memory", f"{results['environment']['process_rss_mb']} MB")
    console.print(table)


if __name__ == "__main__":
    out_path = Path(__file__).resolve().parent / "results.json"
    summary = asyncio.run(run_all_benchmarks(output_json=out_path))
    _print_summary(summary)
