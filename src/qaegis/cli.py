"""Unified Typer + Rich production CLI for the Q-Aegis platform."""

from __future__ import annotations

import asyncio
import platform
import sys
from pathlib import Path
from typing import Annotated

import oqs
import orjson
import pennylane as qml
import qiskit
import torch
import typer
from rich.console import Console
from rich.table import Table

from qaegis import __version__
from qaegis.core.bus import EventBus
from qaegis.core.config import load_config
from qaegis.core.identity import IdentityManager
from qaegis.core.lifecycle import LifecycleManager
from qaegis.core.storage import StorageEngine
from qaegis.core.telemetry import QAegisMetrics, configure_logging
from qaegis.modules.quantum_dreamer.service import QuantumDreamerService
from qaegis.modules.quantum_entropy.harvester import (
    QuantumDistributionBatch,
    QuantumDistributionHarvester,
)
from qaegis.modules.qubit_compiler.autoencoder import AngleEncoderPipeline
from qaegis.modules.qubit_compiler.circuit_builder import (
    BackendNoiseProfile,
    NoiseAwareCircuitBuilder,
)
from qaegis.modules.qubit_compiler.qubo_mapper import build_maxcut_qubo
from qaegis.modules.reality_stamp.service import RealityStampService
from qaegis.modules.reality_stamp.signer import RealityStamp, verify_reality_stamp

app = typer.Typer(
    name="qaegis",
    help="Q-Aegis: Quantum-Secured Autonomous Edge-AI Platform CLI.",
    no_args_is_help=True,
)
console = Console()


@app.command("version")
def version_cmd() -> None:
    """Display Q-Aegis version and runtime library inventory."""
    table = Table(title="Q-Aegis Runtime Environment")
    table.add_column("Component", style="cyan", no_wrap=True)
    table.add_column("Version / Status", style="green")
    table.add_row("Q-Aegis", __version__)
    table.add_row("Python", sys.version.split()[0])
    table.add_row("Platform", f"{platform.system()} {platform.machine()}")
    table.add_row("liboqs", str(oqs.oqs_version()))
    table.add_row("Qiskit", qiskit.__version__)
    table.add_row("PennyLane", qml.__version__)
    table.add_row("PyTorch", f"{torch.__version__} (CUDA={torch.cuda.is_available()})")
    console.print(table)


@app.command("init-identity")
def init_identity_cmd(
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Optional YAML configuration file."),
    ] = None,
    rotate: Annotated[
        bool,
        typer.Option("--rotate", help="Rotate existing device PQC keys."),
    ] = False,
) -> None:
    """Generate or rotate the node's NIST PQC (ML-DSA / SLH-DSA / ML-KEM) + X25519 identity."""
    cfg = load_config(config_file)
    configure_logging(cfg.telemetry)
    cfg.ensure_directories()

    mgr = IdentityManager(keys_dir=cfg.keys_dir, node_id=cfg.node_id, config=cfg.identity)
    identity = mgr.rotate() if rotate else mgr.load_or_create()
    bundle = identity.public_bundle()

    table = Table(title=f"Q-Aegis Device Identity ({bundle.node_id})")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Key ID", bundle.key_id)
    table.add_row(
        "Primary Signature", f"{bundle.primary_sig_alg} ({bundle.primary_sig_fingerprint[:16]}...)"
    )
    table.add_row(
        "Fallback Signature",
        f"{bundle.fallback_sig_alg} ({bundle.fallback_sig_fingerprint[:16]}...)",
    )
    table.add_row("Post-Quantum KEM", f"{bundle.kem_alg} ({bundle.kem_fingerprint[:16]}...)")
    table.add_row("Classical KEX", f"X25519 ({bundle.x25519_fingerprint[:16]}...)")
    table.add_row("Secret Key File", str(mgr.secret_path))
    table.add_row("Public Bundle File", str(mgr.public_path))
    console.print(table)


@app.command("cbom")
def cbom_cmd(
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Optional YAML configuration file."),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write CBOM JSON to a file instead of stdout."),
    ] = None,
) -> None:
    """Export a Cryptographic Bill of Materials (CBOM) for PQC compliance auditing."""
    cfg = load_config(config_file)
    cfg.ensure_directories()
    mgr = IdentityManager(keys_dir=cfg.keys_dir, node_id=cfg.node_id, config=cfg.identity)
    identity = mgr.load_or_create()
    cbom = mgr.generate_cbom(identity)
    rendered = orjson.dumps(
        cbom.model_dump(mode="json"),
        option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS,
    ).decode("utf-8")
    if output is not None:
        output.write_text(rendered, encoding="utf-8")
        console.print(f"[green]CBOM written to {output}[/green]")
    else:
        typer.echo(rendered)


@app.command("doctor")
def doctor_cmd(
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Optional YAML configuration file."),
    ] = None,
) -> None:
    """Run health diagnostics on PQC algorithms, storage integrity, and quantum simulators."""
    cfg = load_config(config_file)
    cfg.ensure_directories()

    async def _check_storage() -> tuple[int, bool, int]:
        store = StorageEngine(cfg.db_path)
        await store.initialize()
        try:
            schema_v = await store.get_schema_version()
            ok, count = await store.verify_audit_chain()
            return schema_v, ok, count
        finally:
            await store.close()

    schema_v, audit_ok, audit_count = asyncio.run(_check_storage())

    enabled_kems = set(oqs.get_enabled_kem_mechanisms())
    enabled_sigs = set(oqs.get_enabled_sig_mechanisms())

    table = Table(title="Q-Aegis System Diagnostics")
    table.add_column("Check", style="cyan")
    table.add_column("Result", style="green")
    table.add_row("ML-KEM-768 Available", str("ML-KEM-768" in enabled_kems))
    table.add_row("ML-DSA-65 Available", str("ML-DSA-65" in enabled_sigs))
    table.add_row(
        "SLH-DSA Available",
        str(any("SLH" in s and "128F" in s.upper() for s in enabled_sigs)),
    )
    table.add_row("SQLite WAL Schema Version", str(schema_v))
    table.add_row("Audit Hash Chain Valid", f"{audit_ok} ({audit_count} records)")
    console.print(table)
    if not audit_ok:
        raise typer.Exit(code=1)


@app.command("stamp")
def stamp_cmd(
    sensor_id: Annotated[str, typer.Option("--sensor", "-s", help="Sensor identifier.")],
    label: Annotated[str, typer.Option("--label", "-l", help="Edge-AI perception label.")],
    confidence: Annotated[float, typer.Option("--confidence", help="Inference confidence [0,1].")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Output JSON file for the stamp.")],
    stateless: Annotated[
        bool,
        typer.Option("--stateless", help="Use NIST FIPS 205 SLH-DSA instead of ML-DSA-65."),
    ] = False,
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Optional YAML configuration file."),
    ] = None,
) -> None:
    """Create a quantum-seeded, PQC-signed, Merkle-anchored Proof-of-Reality stamp."""
    cfg = load_config(config_file)
    cfg.ensure_directories()

    async def _run() -> RealityStamp:
        metrics = QAegisMetrics()
        bus = EventBus(config=cfg.bus, metrics=metrics)
        storage = StorageEngine(cfg.db_path)
        mgr = IdentityManager(keys_dir=cfg.keys_dir, node_id=cfg.node_id, config=cfg.identity)
        identity = mgr.load_or_create()
        await bus.start()
        await storage.initialize()
        svc = RealityStampService(
            bus=bus,
            identity=identity,
            storage=storage,
            config=cfg.reality_stamp,
            metrics=metrics,
        )
        await svc.start()
        try:
            return await svc.stamp_perception(
                sensor_id=sensor_id,
                perception_label=label,
                confidence=confidence,
                use_stateless_hash_sig=stateless,
            )
        finally:
            await svc.stop()
            await storage.close()
            await bus.stop()

    stamp = asyncio.run(_run())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(
        orjson.dumps(
            stamp.model_dump(mode="json"), option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS
        )
    )
    console.print(
        f"[green]Stamp {stamp.payload.stamp_id} signed with {stamp.algorithm} "
        f"and written to {output}[/green]"
    )


@app.command("verify-stamp")
def verify_stamp_cmd(
    stamp_file: Annotated[Path, typer.Argument(help="Path to a RealityStamp JSON file.")],
    expected_fingerprint: Annotated[
        str | None,
        typer.Option("--fingerprint", help="Optional expected SHA3-256 public key fingerprint."),
    ] = None,
) -> None:
    """Offline cryptographic verifier for a Proof-of-Reality stamp and Merkle inclusion proof."""
    if not stamp_file.is_file():
        console.print(f"[red]Stamp file not found: {stamp_file}[/red]")
        raise typer.Exit(code=2)

    stamp = RealityStamp.model_validate(orjson.loads(stamp_file.read_bytes()))
    result = verify_reality_stamp(stamp, expected_public_key_fingerprint=expected_fingerprint)

    table = Table(title=f"Reality Stamp Verification ({result.stamp_id})")
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="green" if result.valid else "red")
    table.add_row("Overall Valid", str(result.valid))
    table.add_row("Algorithm", result.algorithm)
    table.add_row("Payload SHA-256", str(result.payload_hash_ok))
    table.add_row("Key Fingerprint", str(result.fingerprint_ok))
    table.add_row("PQC Signature", str(result.signature_ok))
    table.add_row("Merkle Inclusion Proof", str(result.merkle_proof_ok))
    console.print(table)
    if not result.valid:
        raise typer.Exit(code=1)


@app.command("compile-circuit")
def compile_circuit_cmd(
    vector: Annotated[
        str,
        typer.Option("--vector", "-v", help="Comma-separated numeric sensor feature values."),
    ] = "0.5,-0.2,0.8,0.1,0.4,-0.7,0.9,0.2",
    qubits: Annotated[int, typer.Option("--qubits", "-q", help="Target qubit count.")] = 4,
    output_qasm: Annotated[
        Path | None,
        typer.Option("--output-qasm", "-o", help="Optional path to save OpenQASM 3.0 output."),
    ] = None,
) -> None:
    """Compile a numeric edge sensor vector into bounded qubit angles and OpenQASM 3.0."""
    values = [float(item.strip()) for item in vector.split(",") if item.strip()]
    pipeline = AngleEncoderPipeline(input_dim=len(values), num_qubits=qubits)
    angles = pipeline.encode_to_angles(values)
    builder = NoiseAwareCircuitBuilder(BackendNoiseProfile())
    _qc, artifact = builder.build_qiskit_circuit(angles)

    table = Table(title="AI-to-Qubit Compiled Circuit")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Input Dimensions", str(len(values)))
    table.add_row("Qubits", str(artifact.num_qubits))
    table.add_row("Transpiled Depth", str(artifact.depth))
    table.add_row("2-Qubit Gates (CX)", str(artifact.two_qubit_gate_count))
    table.add_row("Estimated Fidelity", f"{artifact.estimated_fidelity:.4f}")
    table.add_row("Entanglement Pattern", artifact.entanglement_pattern)
    console.print(table)

    if output_qasm is not None:
        output_qasm.write_text(artifact.openqasm3, encoding="utf-8")
        console.print(f"[green]OpenQASM 3.0 written to {output_qasm}[/green]")


@app.command("dream")
def dream_cmd(
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Optional YAML configuration file."),
    ] = None,
    nodes: Annotated[int, typer.Option("--nodes", help="Demo Max-Cut graph node count.")] = 4,
    backend: Annotated[
        str,
        typer.Option("--backend", help="Backend: aer_statevector, aer_noisy, or ibm_runtime."),
    ] = "aer_statevector",
) -> None:
    """Trigger a Night-Mode Quantum Dreaming QAOA cycle and display optimal solution metrics."""
    cfg = load_config(
        config_file,
        overrides={"quantum_dreamer": {"backend_type": backend}},
    )
    cfg.ensure_directories()

    async def _run() -> dict[str, object]:
        metrics = QAegisMetrics()
        bus = EventBus(config=cfg.bus, metrics=metrics)
        storage = StorageEngine(cfg.db_path)
        lifecycle = LifecycleManager(bus=bus, config=cfg.lifecycle, metrics=metrics)
        await bus.start()
        await storage.initialize()
        dreamer = QuantumDreamerService(
            bus=bus,
            storage=storage,
            lifecycle=lifecycle,
            config=cfg.quantum_dreamer,
            metrics=metrics,
        )
        await dreamer.start()
        try:
            edges = [(i, (i + 1) % nodes, 1.0 + 0.5 * (i % 2)) for i in range(nodes)]
            qubo = build_maxcut_qubo(num_nodes=nodes, weighted_edges=edges)
            await dreamer.enqueue_day_problem(qubo, priority=90, policy_name="cli_demo_policy")
            report = await dreamer.run_night_cycle(max_problems=4)
            return report.model_dump(mode="json")
        finally:
            await storage.close()
            await bus.stop()

    report_dict = asyncio.run(_run())
    solutions = report_dict["solutions"]
    assert isinstance(solutions, list)
    table = Table(title="Quantum Dreaming Night-Mode Results")
    table.add_column("Problem ID", style="cyan")
    table.add_column("Backend", style="magenta")
    table.add_column("Best Bitstring", style="green")
    table.add_column("Energy", style="yellow")
    table.add_column("Approx Ratio", style="green")
    for sol in solutions:
        assert isinstance(sol, dict)
        ratio = sol.get("approximation_ratio")
        table.add_row(
            str(sol["problem_id"]),
            str(sol["backend_name"]),
            str(sol["optimal_bitstring"]),
            f"{float(sol['optimal_energy']):.3f}",
            f"{float(ratio):.4f}" if ratio is not None else "n/a",
        )
    console.print(table)


@app.command("entropy")
def entropy_cmd(
    qubits: Annotated[int, typer.Option("--qubits", "-q", help="Entangled circuit qubits.")] = 6,
    shots: Annotated[int, typer.Option("--shots", "-s", help="Quantum measurement shots.")] = 512,
) -> None:
    """Harvest a verified quantum probability distribution and display Shannon entropy."""

    async def _run() -> QuantumDistributionBatch:
        harvester = QuantumDistributionHarvester()
        batch, _pool = await harvester.harvest_batch(num_qubits=qubits, shots=shots)
        return batch

    batch = asyncio.run(_run())
    table = Table(title="Quantum Entropy Harvest")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Qubits", str(batch.num_qubits))
    table.add_row("Shots", str(batch.shots))
    table.add_row("Shannon Entropy (bits)", f"{batch.shannon_entropy_bits:.4f}")
    table.add_row("Pool Bytes", str(batch.pool_bytes))
    table.add_row("Sources", ", ".join(batch.sources))
    console.print(table)
