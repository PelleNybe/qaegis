"""Unified Typer + Rich production CLI for the Q-Aegis platform."""

from __future__ import annotations

import asyncio
import platform
import signal
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
from qaegis.core.hardware_seal import (
    HardwareSealer,
    PKCS11Sealer,
    TPM2Sealer,
    detect_pkcs11_library,
)
from qaegis.core.identity import IdentityManager, PublicIdentityBundle
from qaegis.core.lifecycle import LifecycleManager
from qaegis.core.storage import StorageEngine
from qaegis.core.telemetry import QAegisMetrics, configure_logging
from qaegis.modules.chameleon_fw.service import ChameleonFirewallService
from qaegis.modules.quantum_dreamer.service import QuantumDreamerService
from qaegis.modules.quantum_entropy.harvester import (
    QuantumDistributionBatch,
    QuantumDistributionHarvester,
)
from qaegis.modules.quantum_entropy.service import QuantumEntropyService
from qaegis.modules.qubit_compiler.autoencoder import AngleEncoderPipeline
from qaegis.modules.qubit_compiler.circuit_builder import (
    BackendNoiseProfile,
    NoiseAwareCircuitBuilder,
)
from qaegis.modules.qubit_compiler.qubo_mapper import build_maxcut_qubo
from qaegis.modules.qubit_compiler.service import QubitCompilerService
from qaegis.modules.reality_stamp.gossip import MerkleGossipEnvelope, MerkleGossipNode
from qaegis.modules.reality_stamp.service import RealityStampService
from qaegis.modules.reality_stamp.signer import RealityStamp, verify_reality_stamp

app = typer.Typer(
    name="qaegis",
    help="Q-Aegis: Quantum-Secured Autonomous Edge-AI Platform CLI.",
    no_args_is_help=True,
)
gossip_app = typer.Typer(
    name="gossip",
    help="Distributed multi-node Merkle root gossip inspection and peer verification.",
    no_args_is_help=True,
)
app.add_typer(gossip_app, name="gossip")
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

    tpm_sealer = TPM2Sealer(device_path=Path(cfg.identity.tpm2_device))
    table.add_row(
        "TPM 2.0 Device (/dev/tpmrm0)",
        f"device={tpm_sealer.device_path.exists()}, tools={tpm_sealer.tools_installed()}",
    )
    pkcs11_lib = detect_pkcs11_library(cfg.identity.pkcs11_library)
    if pkcs11_lib is not None:
        try:
            slots = PKCS11Sealer(library_path=pkcs11_lib).list_slots()
            slot_summary = f"{pkcs11_lib.name} ({len(slots)} token slot(s))"
        except Exception as exc:
            slot_summary = f"{pkcs11_lib.name} (unavailable: {exc})"
    else:
        slot_summary = "not installed"
    table.add_row("PKCS#11 HSM / SoftHSM2", slot_summary)

    console.print(table)
    if not audit_ok:
        raise typer.Exit(code=1)


@app.command("seal-identity")
def seal_identity_cmd(
    backend: Annotated[
        str,
        typer.Option("--backend", "-b", help="Hardware sealing backend: pkcs11 or tpm2."),
    ] = "pkcs11",
    token_label: Annotated[
        str | None,
        typer.Option("--token-label", help="PKCS#11 token label (for pkcs11 backend)."),
    ] = None,
    user_pin: Annotated[
        str,
        typer.Option("--pin", help="PKCS#11 user PIN (for pkcs11 backend)."),
    ] = "1234",
    library_path: Annotated[
        Path | None,
        typer.Option("--pkcs11-lib", help="Optional explicit PKCS#11 shared library path."),
    ] = None,
    pcr_spec: Annotated[
        str | None,
        typer.Option("--pcr-spec", help="TPM 2.0 PCR selection (e.g. sha256:0,7)."),
    ] = None,
    remove_plaintext: Annotated[
        bool,
        typer.Option("--remove-plaintext", help="Delete unsealed secret JSON after sealing."),
    ] = False,
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Optional YAML configuration file."),
    ] = None,
) -> None:
    """Seal the node's PQC identity private keys using PKCS#11 (HSM/SoftHSM2) or TPM 2.0."""
    cfg = load_config(config_file)
    cfg.ensure_directories()
    mgr = IdentityManager(keys_dir=cfg.keys_dir, node_id=cfg.node_id, config=cfg.identity)
    identity = mgr.load_or_create()

    sealer: HardwareSealer
    if backend == "pkcs11":
        sealer = PKCS11Sealer(
            token_label=token_label or cfg.identity.pkcs11_token_label,
            user_pin=user_pin,
            key_label=cfg.identity.pkcs11_key_label,
            library_path=library_path or cfg.identity.pkcs11_library,
        )
    elif backend == "tpm2":
        sealer = TPM2Sealer(
            device_path=Path(cfg.identity.tpm2_device),
            pcr_spec=pcr_spec or cfg.identity.tpm2_pcr_spec,
        )
    else:
        console.print(f"[red]Unsupported sealing backend '{backend}'. Use pkcs11 or tpm2.[/red]")
        raise typer.Exit(code=2)

    blob = mgr.seal_identity(identity, sealer, remove_plaintext_secret=remove_plaintext)
    console.print(
        f"[green]Sealed identity {identity.key_id} with {blob.backend} "
        f"(key_label={blob.key_label}) to {mgr.sealed_path}[/green]"
    )


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
        typer.Option(
            "--backend",
            help="Backend: aer_statevector, aer_noisy, ibm_runtime, aws_braket, or ionq.",
        ),
    ] = "aer_statevector",
    mitigation: Annotated[
        str,
        typer.Option(
            "--mitigation",
            help="Quantum error mitigation pipeline: none, zne, trex, or both.",
        ),
    ] = "none",
) -> None:
    """Trigger a Night-Mode Quantum Dreaming QAOA cycle and display optimal solution metrics."""
    cfg = load_config(
        config_file,
        overrides={
            "quantum_dreamer": {
                "backend_type": backend,
                "mitigation_mode": mitigation,
            }
        },
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


@app.command("run")
def run_cmd(
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Optional YAML configuration file."),
    ] = None,
    max_ticks: Annotated[
        int | None,
        typer.Option(
            "--max-ticks", help="Optional tick limit before clean shutdown (for testing)."
        ),
    ] = None,
    tick_interval_s: Annotated[
        float,
        typer.Option("--tick-interval", help="Lifecycle evaluation interval in seconds."),
    ] = 15.0,
) -> None:
    """Run the full Q-Aegis microkernel daemon with all five subsystems and Prometheus metrics."""
    cfg = load_config(config_file)
    configure_logging(cfg.telemetry)
    cfg.ensure_directories()

    async def _serve() -> None:
        metrics = QAegisMetrics()
        bus = EventBus(config=cfg.bus, metrics=metrics)
        storage = StorageEngine(cfg.db_path)
        lifecycle = LifecycleManager(bus=bus, config=cfg.lifecycle, metrics=metrics)
        identity = IdentityManager(cfg.keys_dir, cfg.node_id, cfg.identity).load_or_create()

        if cfg.telemetry.enabled:
            host, port = metrics.start_http_exporter(
                host=cfg.telemetry.metrics_host,
                port=cfg.telemetry.metrics_port,
            )
            console.print(
                f"[cyan]Prometheus metrics serving on http://{host}:{port}/metrics[/cyan]"
            )

        await bus.start()
        await storage.initialize()
        reality_svc = RealityStampService(
            bus=bus,
            identity=identity,
            storage=storage,
            config=cfg.reality_stamp,
            metrics=metrics,
        )
        chameleon_svc = ChameleonFirewallService(
            bus=bus,
            identity=identity,
            config=cfg.chameleon_fw,
            metrics=metrics,
        )
        compiler_svc = QubitCompilerService(bus=bus, config=cfg.qubit_compiler)
        dreamer_svc = QuantumDreamerService(
            bus=bus,
            storage=storage,
            lifecycle=lifecycle,
            config=cfg.quantum_dreamer,
            metrics=metrics,
        )
        entropy_svc = QuantumEntropyService(
            bus=bus,
            config=cfg.quantum_entropy,
            metrics=metrics,
        )

        await reality_svc.start()
        await chameleon_svc.start()
        await compiler_svc.start()
        await dreamer_svc.start()
        await entropy_svc.start()

        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        if sys.platform != "win32":
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, stop_event.set)

        console.print(
            f"[green]Q-Aegis microkernel online "
            f"(node={cfg.node_id}, mode={lifecycle.mode.value})[/green]"
        )
        ticks = 0
        try:
            while not stop_event.is_set():
                await lifecycle.evaluate_auto_transition()
                ticks += 1
                if max_ticks is not None and ticks >= max_ticks:
                    break
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=tick_interval_s)
                except TimeoutError:
                    continue
        finally:
            await lifecycle.shutdown()
            await reality_svc.stop()
            await storage.close()
            await bus.stop()
            metrics.stop_http_exporter()

    asyncio.run(_serve())


@gossip_app.command("status")
def gossip_status_cmd(
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Optional YAML configuration file."),
    ] = None,
) -> None:
    """Display persisted verified peer Merkle root checkpoints witnessed by this node."""
    cfg = load_config(config_file)
    cfg.ensure_directories()

    async def _fetch() -> list[dict[str, object]]:
        storage = StorageEngine(cfg.db_path)
        await storage.initialize()
        try:
            return await storage.list_gossip_checkpoints()
        finally:
            await storage.close()

    rows = asyncio.run(_fetch())
    table = Table(title=f"Q-Aegis Merkle Gossip Checkpoints ({len(rows)} total)")
    table.add_column("Peer Node", style="cyan")
    table.add_column("Tree Size", style="magenta")
    table.add_column("Merkle Root", style="green")
    table.add_column("Status", style="yellow")
    for r in rows[:20]:
        table.add_row(
            str(r["peer_node_id"]),
            str(r["tree_size"]),
            str(r["merkle_root"])[:20] + "...",
            str(r["status"]),
        )
    console.print(table)


@gossip_app.command("verify-peer")
def gossip_verify_peer_cmd(
    checkpoint_file: Annotated[Path, typer.Argument(help="Signed MerkleGossipEnvelope JSON file.")],
    peer_public_file: Annotated[
        Path,
        typer.Argument(help="Peer's trusted PublicIdentityBundle JSON file."),
    ],
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Optional YAML configuration file."),
    ] = None,
) -> None:
    """Verify a peer's ML-DSA-65 signed Merkle checkpoint and check for split-view equivocation."""
    cfg = load_config(config_file)
    cfg.ensure_directories()
    envelope = MerkleGossipEnvelope.model_validate(orjson.loads(checkpoint_file.read_bytes()))
    peer_bundle = PublicIdentityBundle.model_validate(orjson.loads(peer_public_file.read_bytes()))

    async def _verify() -> tuple[bool, str]:
        bus = EventBus(config=cfg.bus)
        storage = StorageEngine(cfg.db_path)
        identity = IdentityManager(cfg.keys_dir, cfg.node_id, cfg.identity).load_or_create()
        await bus.start()
        await storage.initialize()
        try:
            node = MerkleGossipNode(
                identity=identity,
                storage=storage,
                bus=bus,
                trusted_peers={peer_bundle.node_id: peer_bundle},
            )
            outcome = await node.ingest_checkpoint(envelope, rebroadcast=False)
            return outcome.accepted, outcome.reason
        finally:
            await storage.close()
            await bus.stop()

    accepted, reason = asyncio.run(_verify())
    color = "green" if accepted else "red"
    console.print(
        f"[{color}]Peer checkpoint verification: accepted={accepted} ({reason})[/{color}]"
    )
    if not accepted:
        raise typer.Exit(code=1)
