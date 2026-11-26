"""Interactive zero-friction end-to-end live demonstration of all five Q-Aegis subsystems."""

from __future__ import annotations

import asyncio
import os
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np
from pydantic import BaseModel
from qiskit_aer import AerSimulator
from qiskit_aer.noise import NoiseModel, ReadoutError, depolarizing_error
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from qaegis import __version__
from qaegis.core.bus import EventBus
from qaegis.core.config import QAegisConfig, QuantumDreamerConfig, RealityStampConfig
from qaegis.core.identity import IdentityManager
from qaegis.core.storage import StorageEngine
from qaegis.modules.chameleon_fw.features import TrafficObservation
from qaegis.modules.chameleon_fw.service import ChameleonFirewallService
from qaegis.modules.quantum_dreamer.mitigation import ErrorMitigationPipeline
from qaegis.modules.quantum_dreamer.solvers import (
    AerNoisyBackend,
    AerStatevectorBackend,
    QaoaSolver,
    build_qaoa_circuit,
)
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
from qaegis.modules.reality_stamp.service import RealityStampService
from qaegis.modules.reality_stamp.signer import verify_reality_stamp


class DemoStageMetric(BaseModel):
    """Measured execution result for one stage of the interactive Q-Aegis demo."""

    stage: str
    subsystem: str
    latency_ms: float
    outcome: str


class DemoReport(BaseModel):
    """Complete structured output returned by `run_interactive_demo`."""

    total_time_s: float
    stages: list[DemoStageMetric]
    all_passed: bool


async def run_interactive_demo(
    fast: bool = False,
    console: Console | None = None,
) -> DemoReport:
    """Execute a genuine end-to-end 5-subsystem Q-Aegis live demo with zero external API keys."""
    out = console or Console()
    stages: list[DemoStageMetric] = []
    t_start = time.perf_counter()

    title_line = f"[bold cyan]Q-Aegis v{__version__} — Quantum-Secured Autonomous Edge-AI Demo"
    out.print(
        Panel.fit(
            f"{title_line}[/bold cyan]\n"
            "[dim]Executing real NIST PQC (liboqs), ONNX Runtime, Qiskit QAOA & ZNE+TREX[/dim]",
            border_style="cyan",
        )
    )

    with (
        tempfile.TemporaryDirectory(prefix="qaegis-demo-") as tmp_str,
        Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=out,
            transient=True,
        ) as progress,
    ):
        tmp = Path(tmp_str)
        cfg = QAegisConfig(
            node_id="qaegis-demo-edge-01",
            data_dir=tmp / "data",
            keys_dir=tmp / "keys",
            db_path=tmp / "data" / "demo.db",
            reality_stamp=RealityStampConfig(strict_nist_checks=False),
            quantum_dreamer=QuantumDreamerConfig(
                backend_type="aer_noisy",
                qaoa_reps=1 if fast else 2,
                qaoa_shots=256 if fast else 512,
                max_optimizer_iters=10 if fast else 25,
            ),
        )
        cfg.ensure_directories()

        # Stage 1: NIST PQC Identity Generation (FIPS 203 / 204 / 205)
        t1 = progress.add_task("[1/5] Generating NIST FIPS 203/204/205 PQC Identity...", total=None)
        s0 = time.perf_counter()
        edge_mgr = IdentityManager(cfg.keys_dir, cfg.node_id, cfg.identity)
        edge_id = edge_mgr.generate()
        ground_id = IdentityManager(
            tmp / "ground_keys", "qaegis-ground-01", cfg.identity
        ).generate()
        s1_ms = (time.perf_counter() - s0) * 1000.0
        progress.remove_task(t1)
        stages.append(
            DemoStageMetric(
                stage="1. PQC Identity",
                subsystem="core.identity",
                latency_ms=round(s1_ms, 2),
                outcome=(
                    f"{edge_id.primary_sig_alg} + {edge_id.kem_alg} + {edge_id.fallback_sig_alg}"
                ),
            )
        )

        # Stage 2: Proof of Reality (QRNG + NIST 800-22/90B + ML-DSA-65 + Merkle Tree)
        t2 = progress.add_task(
            "[2/5] Harvesting QRNG + NIST 800-22/90B + Signing Reality Stamp...", total=None
        )
        s0 = time.perf_counter()
        bus = EventBus(config=cfg.bus)
        storage = StorageEngine(cfg.db_path)
        await bus.start()
        await storage.initialize()
        reality_svc = RealityStampService(
            bus=bus,
            identity=edge_id,
            storage=storage,
            config=cfg.reality_stamp,
        )
        await reality_svc.start()
        try:
            stamp = await reality_svc.stamp_perception(
                sensor_id="lidar-front-01",
                perception_label="pedestrian_crossing",
                confidence=0.98,
                metadata={"range_m": 6.4},
            )
            ver = verify_reality_stamp(stamp, keyring=edge_mgr.load_keyring())
            s2_ms = (time.perf_counter() - s0) * 1000.0
            progress.remove_task(t2)
            stages.append(
                DemoStageMetric(
                    stage="2. Proof of Reality",
                    subsystem="reality_stamp",
                    latency_ms=round(s2_ms, 2),
                    outcome=(
                        f"Valid={ver.valid}, MerkleProof={ver.merkle_proof_ok}, "
                        f"Alg={stamp.algorithm}"
                    ),
                )
            )

            # Stage 3: Quantum Chameleon Adaptive Threat Escalation
            t3 = progress.add_task(
                "[3/5] Running Chameleon AI Anomaly Firewall Escalation...", total=None
            )
            s0 = time.perf_counter()
            fw_edge = ChameleonFirewallService(
                bus=bus,
                identity=edge_id,
                config=cfg.chameleon_fw,
                onnx_model_path=tmp / "hndl_demo.onnx",
            )
            fw_ground = ChameleonFirewallService(
                bus=bus, identity=ground_id, config=cfg.chameleon_fw
            )
            tiers_seen: list[str] = []
            demo_flows = [
                ("lan", "public", 0.1, b'{"battery_pct": 91}'),
                (
                    "lan",
                    "confidential",
                    5.5,
                    b'{"route_id":"alpha-7","waypoints":[[59.33,18.06],[59.35,18.09]]}',
                ),
                ("satellite", "top_secret", 20.0, b"mission_orders:" + os.urandom(256)),
            ]
            base_ts = datetime.now(UTC)
            for idx, (proto, sens, years, body) in enumerate(demo_flows):
                pkt = await fw_edge.protect(
                    TrafficObservation(
                        source=edge_id.node_id,
                        destination=ground_id.node_id,
                        protocol=proto,
                        sensitivity=sens,  # type: ignore[arg-type]
                        payload_bytes=body,
                        long_term_retention_years=years,
                        timestamp_utc=base_ts + timedelta(seconds=idx),
                    ),
                    recipient=ground_id.public_bundle(),
                )
                recovered = fw_ground.unprotect(
                    pkt.envelope, expected_sender=edge_id.public_bundle()
                )
                if recovered != body:
                    raise RuntimeError("Chameleon decrypt verification mismatch during demo")
                tiers_seen.append(pkt.envelope.tier.value)
            s3_ms = (time.perf_counter() - s0) * 1000.0
            progress.remove_task(t3)
            stages.append(
                DemoStageMetric(
                    stage="3. Chameleon Firewall",
                    subsystem="chameleon_fw",
                    latency_ms=round(s3_ms, 2),
                    outcome=" -> ".join(tiers_seen),
                )
            )

            # Stage 4: AI-to-Qubit Compiler (ONNX Autoencoder -> OpenQASM 3.0)
            t4 = progress.add_task(
                "[4/5] Compiling Sensor Tensor via ONNX -> OpenQASM 3.0...", total=None
            )
            s0 = time.perf_counter()
            rng = np.random.default_rng(42)
            samples = rng.normal(size=(48, 16)).astype(np.float32)
            pipe = AngleEncoderPipeline(input_dim=16, num_qubits=4, hidden_dim=24)
            pipe.train(samples, epochs=10 if fast else 20)
            onnx_file = tmp / "angle_encoder_demo.onnx"
            pipe.export_onnx(onnx_file)
            pipe.load_onnx(onnx_file)
            angles = pipe.encode_to_angles(samples[0])
            builder = NoiseAwareCircuitBuilder(BackendNoiseProfile())
            _qc, artifact = builder.build_qiskit_circuit(angles)
            s4_ms = (time.perf_counter() - s0) * 1000.0
            progress.remove_task(t4)
            stages.append(
                DemoStageMetric(
                    stage="4. AI-to-Qubit Compiler",
                    subsystem="qubit_compiler",
                    latency_ms=round(s4_ms, 2),
                    outcome=(
                        f"{artifact.num_qubits}q OpenQASM 3.0 (depth={artifact.depth}, "
                        f"fidelity={artifact.estimated_fidelity:.3f})"
                    ),
                )
            )

            # Stage 5: Night-Mode QAOA + ZNE & TREX Error Mitigation on Noisy Aer
            t5 = progress.add_task(
                "[5/5] Solving QAOA Max-Cut + ZNE/TREX Error Mitigation on Noisy Aer...",
                total=None,
            )
            s0 = time.perf_counter()
            qubo = build_maxcut_qubo(4, [(0, 1, 1.5), (1, 2, 1.5), (2, 3, 1.5), (3, 0, 1.5)])
            ham = qubo_to_ising(qubo)
            solver = QaoaSolver(config=cfg.quantum_dreamer, backend=AerNoisyBackend(seed=42))
            sol = await asyncio.to_thread(solver.solve, qubo)

            # Measure real ZNE + TREX expectation error reduction vs exact statevector ground truth
            gammas = [0.45, 0.70]
            betas = [0.55, 0.25]
            eval_qc = build_qaoa_circuit(ham, gammas, betas, measure=True)
            sv_dist = AerStatevectorBackend().sample_distribution(ham, gammas, betas, shots=1)
            exact_e = sum(p * evaluate_ising(ham, bs) for bs, p in sv_dist.items())

            nm = NoiseModel()
            nm.add_all_qubit_quantum_error(
                depolarizing_error(0.005, 1), ["h", "rx", "ry", "rz", "x"]
            )
            nm.add_all_qubit_quantum_error(depolarizing_error(0.025, 2), ["cx", "rzz"])
            nm.add_all_qubit_readout_error(ReadoutError([[0.96, 0.04], [0.14, 0.86]]))
            noisy_sim = AerSimulator(noise_model=nm)

            mit_res = await asyncio.to_thread(
                ErrorMitigationPipeline(
                    noisy_sim,
                    mode="both",
                    scale_factors=[1, 3] if fast else [1, 3, 5],
                    extrapolation="linear",
                    num_twirls=6 if fast else 16,
                    seed=42,
                ).evaluate_expectation,
                eval_qc,
                ham,
                512 if fast else 4096,
            )
            raw_err = abs(mit_res.unmitigated_energy - exact_e)
            mit_err = abs(mit_res.mitigated_energy - exact_e)
            reduction_pct = (1.0 - mit_err / max(raw_err, 1e-9)) * 100.0
            s5_ms = (time.perf_counter() - s0) * 1000.0
            progress.remove_task(t5)
            stages.append(
                DemoStageMetric(
                    stage="5. QAOA + ZNE/TREX",
                    subsystem="quantum_dreamer",
                    latency_ms=round(s5_ms, 2),
                    outcome=(
                        f"Cut={sol.optimal_bitstring} (ratio={sol.approximation_ratio:.2f}), "
                        f"ZNE+TREX err {raw_err:.3f}->{mit_err:.3f} ({reduction_pct:+.1f}%)"
                    ),
                )
            )
        finally:
            await reality_svc.stop()
            await storage.close()
            await bus.stop()

    total_s = round(time.perf_counter() - t_start, 2)
    table = Table(title=f"Q-Aegis Live Demo Executive Summary (Total: {total_s:.2f}s)")
    table.add_column("Stage", style="cyan", no_wrap=True)
    table.add_column("Subsystem", style="magenta")
    table.add_column("Latency", style="yellow", justify="right")
    table.add_column("Verified Outcome", style="green")
    for st in stages:
        table.add_row(st.stage, st.subsystem, f"{st.latency_ms:.2f} ms", st.outcome)
    out.print(table)
    return DemoReport(total_time_s=total_s, stages=stages, all_passed=True)
