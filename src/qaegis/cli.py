"""Unified Typer + Rich production CLI for the Q-Aegis platform."""

from __future__ import annotations

import asyncio
import contextlib
import platform
import signal
import sys
from pathlib import Path
from typing import Annotated, Any

import oqs
import orjson
import typer
import yaml
from rich.console import Console
from rich.table import Table

from qaegis import __version__
from qaegis.core.bus import EventBus
from qaegis.core.config import QAegisConfig, load_config
from qaegis.core.hardware_seal import (
    HardwareSealer,
    PKCS11Sealer,
    TPM2Sealer,
    create_sealer_from_config,
    detect_pkcs11_library,
)
from qaegis.core.identity import IdentityManager, PublicIdentityBundle, TrustKeyring
from qaegis.core.lifecycle import LifecycleManager
from qaegis.core.storage import StorageEngine
from qaegis.core.telemetry import QAegisMetrics, configure_logging
from qaegis.modules.chameleon_fw.crypto_agility import CryptoAgilityEngine, EncryptedEnvelope
from qaegis.modules.chameleon_fw.features import ThreatTier
from qaegis.modules.reality_stamp.gossip import MerkleGossipEnvelope, MerkleGossipNode
from qaegis.modules.reality_stamp.signer import (
    ArtifactSignatureBundle,
    RealityStamp,
    sign_artifact_file,
    verify_artifact_file,
    verify_reality_stamp,
)

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
    from importlib.metadata import version as pkg_version

    table = Table(title="Q-Aegis Runtime Environment")
    table.add_column("Component", style="cyan", no_wrap=True)
    table.add_column("Version / Status", style="green")
    table.add_row("Q-Aegis", __version__)
    table.add_row("Python", sys.version.split()[0])
    table.add_row("Platform", f"{platform.system()} {platform.machine()}")
    table.add_row("liboqs", str(oqs.oqs_version()))
    table.add_row("Qiskit", pkg_version("qiskit"))
    table.add_row("PennyLane", pkg_version("pennylane"))
    table.add_row("PyTorch", pkg_version("torch"))
    console.print(table)


@app.command("init-config")
def init_config_cmd(
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Destination YAML configuration file."),
    ] = Path("qaegis.yaml"),
    profile: Annotated[
        str,
        typer.Option(
            "--profile",
            "-p",
            help="Deployment preset: developer, edge, fleet, or airgap.",
        ),
    ] = "developer",
    force: Annotated[
        bool,
        typer.Option("--force", help="Overwrite destination file if it already exists."),
    ] = False,
) -> None:
    """Generate a ready-to-run Q-Aegis YAML configuration tailored to a deployment profile."""
    if output.exists() and not force:
        console.print(f"[red]File already exists: {output} (pass --force to overwrite)[/red]")
        raise typer.Exit(code=2)

    presets: dict[str, dict[str, Any]] = {
        "developer": {
            "node_id": "qaegis-dev-01",
            "telemetry": {"enabled": False, "log_json": False, "log_level": "INFO"},
            "dashboard": {"enabled": True, "host": "127.0.0.1", "port": 8080},
            "reality_stamp": {"strict_nist_checks": False},
        },
        "edge": {
            "node_id": "qaegis-edge-01",
            "telemetry": {"enabled": True, "log_json": True},
            "reality_stamp": {"strict_nist_checks": True},
            "chameleon_fw": {"elevated_risk_threshold": 0.40, "critical_risk_threshold": 0.70},
        },
        "fleet": {
            "node_id": "qaegis-fleet-node-01",
            "bus": {"transport": "zmq", "zmq_security": "curve"},
            "quantum_dreamer": {"backend_type": "aer_noisy", "mitigation_mode": "both"},
        },
        "airgap": {
            "node_id": "qaegis-airgap-01",
            "reality_stamp": {"qrng_http_url": None, "strict_nist_checks": True},
            "quantum_dreamer": {"backend_type": "aer_noisy", "mitigation_mode": "both"},
        },
    }
    if profile not in presets:
        console.print(
            f"[red]Unsupported profile '{profile}'. Use developer, edge, fleet, or airgap.[/red]"
        )
        raise typer.Exit(code=2)

    cfg = QAegisConfig.model_validate(presets[profile])
    doc: dict[str, Any] = orjson.loads(orjson.dumps(cfg.model_dump(mode="json"), default=str))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    console.print(f"[green]Initialized '{profile}' configuration at {output}[/green]")


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
    fmt: Annotated[
        str,
        typer.Option("--format", "-f", help="Export format: json or cyclonedx (CycloneDX 1.6)."),
    ] = "json",
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write CBOM JSON to a file instead of stdout."),
    ] = None,
) -> None:
    """Export a Cryptographic Bill of Materials (CBOM) in native JSON or CycloneDX 1.6 format."""
    cfg = load_config(config_file)
    cfg.ensure_directories()
    mgr = IdentityManager(keys_dir=cfg.keys_dir, node_id=cfg.node_id, config=cfg.identity)
    identity = mgr.load_or_create()

    if fmt == "json":
        doc: dict[str, object] = mgr.generate_cbom(identity).model_dump(mode="json")
    elif fmt == "cyclonedx":
        doc = mgr.generate_cyclonedx_cbom(identity)
    else:
        console.print(f"[red]Unsupported CBOM format '{fmt}'. Use json or cyclonedx.[/red]")
        raise typer.Exit(code=2)

    rendered = orjson.dumps(
        doc,
        option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS,
    ).decode("utf-8")
    if output is not None:
        output.write_text(rendered, encoding="utf-8")
        console.print(f"[green]CBOM ({fmt}) written to {output}[/green]")
    else:
        typer.echo(rendered)


@app.command("rotate-keys")
def rotate_keys_cmd(
    seal_backend: Annotated[
        str | None,
        typer.Option("--seal-backend", help="Optional hardware sealer: pkcs11 or tpm2."),
    ] = None,
    token_label: Annotated[
        str | None,
        typer.Option("--token-label", help="PKCS#11 token label (when --seal-backend pkcs11)."),
    ] = None,
    user_pin: Annotated[
        str | None,
        typer.Option("--pin", help="PKCS#11 user PIN (or set QAEGIS_PKCS11_PIN)."),
    ] = None,
    library_path: Annotated[
        Path | None,
        typer.Option("--pkcs11-lib", help="Optional explicit PKCS#11 shared library path."),
    ] = None,
    remove_plaintext: Annotated[
        bool,
        typer.Option(
            "--remove-plaintext",
            help="Delete unsealed secret JSON after sealing rotated keys.",
        ),
    ] = False,
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Optional YAML configuration file."),
    ] = None,
) -> None:
    """Rotate node PQC keys with zero downtime while preserving historical keyring verification."""
    cfg = load_config(config_file)
    cfg.ensure_directories()
    metrics = QAegisMetrics()
    mgr = IdentityManager(keys_dir=cfg.keys_dir, node_id=cfg.node_id, config=cfg.identity)

    sealer: HardwareSealer | None = None
    if seal_backend is not None:
        try:
            sealer = create_sealer_from_config(
                cfg.identity,
                backend=seal_backend,
                token_label=token_label,
                user_pin=user_pin,
                library_path=library_path,
            )
        except ValueError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=2) from exc

    new_id, keyring = mgr.rotate_keys(
        sealer=sealer,
        metrics=metrics,
        remove_plaintext_secret=remove_plaintext,
    )
    bundle = new_id.public_bundle()

    table = Table(title=f"Q-Aegis Zero-Downtime Key Rotation ({bundle.node_id})")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("New Key Version", f"v{bundle.key_version}")
    table.add_row("New Key ID", bundle.key_id)
    table.add_row("ML-DSA-65 Fingerprint", bundle.primary_sig_fingerprint[:24] + "...")
    table.add_row("Historical Keyring Entries", str(len(keyring.keys)))
    table.add_row("Keyring File", str(mgr.keyring_path))
    table.add_row("Hardware Sealed", seal_backend or "none")
    console.print(table)


@app.command("demo")
def demo_cmd(
    fast: Annotated[
        bool,
        typer.Option("--fast", help="Run reduced QAOA shots/iterations for quick CI demos."),
    ] = False,
) -> None:
    """Run an interactive end-to-end live demonstration of all five Q-Aegis subsystems."""
    from qaegis.demo import run_interactive_demo

    asyncio.run(run_interactive_demo(fast=fast, console=console))


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

    async def _check_storage() -> tuple[int, bool, int, bool, int, bool, int]:
        async with StorageEngine(cfg.db_path) as store:
            schema_v = await store.get_schema_version()
            audit_ok, audit_count = await store.verify_audit_chain()
            dream_ok, dream_count = await store.verify_dream_problem_integrity()
            policy_ok, policy_count = await store.verify_policy_snapshots()
            return (
                schema_v,
                audit_ok,
                audit_count,
                dream_ok,
                dream_count,
                policy_ok,
                policy_count,
            )

    (
        schema_v,
        audit_ok,
        audit_count,
        dream_ok,
        dream_count,
        policy_ok,
        policy_count,
    ) = asyncio.run(_check_storage())

    enabled_kems = set(oqs.get_enabled_kem_mechanisms())
    enabled_sigs = set(oqs.get_enabled_sig_mechanisms())
    mgr = IdentityManager(keys_dir=cfg.keys_dir, node_id=cfg.node_id, config=cfg.identity)
    keyring_status = "not initialized"
    if mgr.keyring_path.is_file():
        kr = mgr.load_keyring()
        keyring_status = f"v{kr.current_version} ({len(kr.keys)} key(s))"

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
    table.add_row("Dream Queue Integrity", f"{dream_ok} ({dream_count} problems)")
    table.add_row("Policy Snapshots Integrity", f"{policy_ok} ({policy_count} snapshots)")
    from qaegis.modules.quantum_dreamer.solvers import get_backend_registry

    table.add_row("Trust Keyring", keyring_status)
    table.add_row(
        "Registered Quantum Backends",
        ", ".join(get_backend_registry().available_backends()),
    )

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
    if not (audit_ok and dream_ok and policy_ok):
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
        str | None,
        typer.Option("--pin", help="PKCS#11 user PIN (or set QAEGIS_PKCS11_PIN env var)."),
    ] = None,
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

    try:
        sealer = create_sealer_from_config(
            cfg.identity,
            backend=backend,
            token_label=token_label,
            user_pin=user_pin,
            library_path=library_path,
            pcr_spec=pcr_spec,
        )
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc

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
        from qaegis.modules.reality_stamp.service import RealityStampService

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
    keyring_file: Annotated[
        Path | None,
        typer.Option("--keyring", "-k", help="Optional historical TrustKeyring JSON file."),
    ] = None,
) -> None:
    """Offline cryptographic verifier for a Proof-of-Reality stamp, keyring, and Merkle proof."""
    if not stamp_file.is_file():
        console.print(f"[red]Stamp file not found: {stamp_file}[/red]")
        raise typer.Exit(code=2)

    stamp = RealityStamp.model_validate(orjson.loads(stamp_file.read_bytes()))
    keyring: TrustKeyring | None = None
    if keyring_file is not None:
        if not keyring_file.is_file():
            console.print(f"[red]Keyring file not found: {keyring_file}[/red]")
            raise typer.Exit(code=2)
        keyring = TrustKeyring.model_validate(orjson.loads(keyring_file.read_bytes()))

    result = verify_reality_stamp(
        stamp,
        expected_public_key_fingerprint=expected_fingerprint,
        keyring=keyring,
    )

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


@app.command("sign-file")
def sign_file_cmd(
    file_path: Annotated[Path, typer.Argument(help="File, ML model, SBOM, or archive to sign.")],
    output: Annotated[
        Path | None,
        typer.Option(
            "--output", "-o", help="Detached signature JSON path (default: <file>.sig.json)."
        ),
    ] = None,
    stateless: Annotated[
        bool,
        typer.Option("--stateless", help="Sign with NIST FIPS 205 SLH-DSA instead of ML-DSA-65."),
    ] = False,
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Optional YAML configuration file."),
    ] = None,
) -> None:
    """Sign any file, ML model, firmware, or archive with NIST FIPS 204/205 PQC signatures."""
    if not file_path.is_file():
        console.print(f"[red]Target file not found: {file_path}[/red]")
        raise typer.Exit(code=2)

    cfg = load_config(config_file)
    cfg.ensure_directories()
    mgr = IdentityManager(keys_dir=cfg.keys_dir, node_id=cfg.node_id, config=cfg.identity)
    identity = mgr.load_or_create()

    sig_bundle = sign_artifact_file(
        file_path,
        identity=identity,
        use_stateless_hash_sig=stateless,
    )
    sig_out = output or Path(f"{file_path}.sig.json")
    sig_out.parent.mkdir(parents=True, exist_ok=True)
    sig_out.write_bytes(
        orjson.dumps(
            sig_bundle.model_dump(mode="json"),
            option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS,
        )
    )
    console.print(
        f"[green]Signed {file_path.name} ({sig_bundle.size_bytes} B) with {sig_bundle.algorithm} "
        f"-> {sig_out}[/green]"
    )


@app.command("verify-file")
def verify_file_cmd(
    file_path: Annotated[Path, typer.Argument(help="Target file to verify.")],
    sig_file: Annotated[Path, typer.Argument(help="Detached ArtifactSignatureBundle JSON file.")],
    keyring_file: Annotated[
        Path | None,
        typer.Option("--keyring", "-k", help="Optional historical TrustKeyring JSON file."),
    ] = None,
    expected_fingerprint: Annotated[
        str | None,
        typer.Option("--fingerprint", help="Optional expected SHA3-256 public key fingerprint."),
    ] = None,
) -> None:
    """Verify a file against its detached NIST FIPS 204/205 post-quantum signature bundle."""
    if not file_path.is_file():
        console.print(f"[red]Target file not found: {file_path}[/red]")
        raise typer.Exit(code=2)
    if not sig_file.is_file():
        console.print(f"[red]Signature file not found: {sig_file}[/red]")
        raise typer.Exit(code=2)

    bundle = ArtifactSignatureBundle.model_validate(orjson.loads(sig_file.read_bytes()))
    keyring: TrustKeyring | None = None
    if keyring_file is not None:
        if not keyring_file.is_file():
            console.print(f"[red]Keyring file not found: {keyring_file}[/red]")
            raise typer.Exit(code=2)
        keyring = TrustKeyring.model_validate(orjson.loads(keyring_file.read_bytes()))

    res = verify_artifact_file(
        file_path,
        bundle,
        expected_public_key_fingerprint=expected_fingerprint,
        keyring=keyring,
    )
    table = Table(title=f"Post-Quantum File Verification ({file_path.name})")
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="green" if res.valid else "red")
    table.add_row("Overall Valid", str(res.valid))
    table.add_row("Algorithm", res.algorithm)
    table.add_row("Key ID / Version", f"{res.key_id} (v{res.key_version})")
    table.add_row("SHA-256 & SHA3-256 Digest", str(res.digest_ok))
    table.add_row("Key Fingerprint / Keyring", str(res.fingerprint_ok))
    table.add_row("PQC Signature", str(res.signature_ok))
    console.print(table)
    if not res.valid:
        raise typer.Exit(code=1)


@app.command("encrypt")
def encrypt_cmd(
    input_file: Annotated[Path, typer.Argument(help="Plaintext file to encrypt.")],
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Output EncryptedEnvelope JSON file."),
    ],
    recipient_file: Annotated[
        Path | None,
        typer.Option(
            "--recipient",
            "-r",
            help="Recipient PublicIdentityBundle JSON (defaults to local node public key).",
        ),
    ] = None,
    tier: Annotated[
        str,
        typer.Option(
            "--tier",
            "-t",
            help="Security tier: STANDARD, ELEVATED (ML-KEM-768), or QUANTUM_CRITICAL.",
        ),
    ] = "QUANTUM_CRITICAL",
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Optional YAML configuration file."),
    ] = None,
) -> None:
    """Encrypt a file using hybrid X25519 + NIST ML-KEM-768 + AES-256-GCM (+ ML-DSA-65)."""
    if not input_file.is_file():
        console.print(f"[red]Input file not found: {input_file}[/red]")
        raise typer.Exit(code=2)

    try:
        tier_enum = ThreatTier(tier.upper())
    except ValueError as exc:
        console.print(
            f"[red]Invalid --tier '{tier}'. Use STANDARD, ELEVATED, or QUANTUM_CRITICAL.[/red]"
        )
        raise typer.Exit(code=2) from exc

    cfg = load_config(config_file)
    cfg.ensure_directories()
    mgr = IdentityManager(keys_dir=cfg.keys_dir, node_id=cfg.node_id, config=cfg.identity)
    identity = mgr.load_or_create()

    if recipient_file is not None:
        if not recipient_file.is_file():
            console.print(f"[red]Recipient public key file not found: {recipient_file}[/red]")
            raise typer.Exit(code=2)
        recipient = PublicIdentityBundle.model_validate(orjson.loads(recipient_file.read_bytes()))
    else:
        recipient = identity.public_bundle()

    engine = CryptoAgilityEngine(identity=identity, config=cfg.chameleon_fw)
    envelope = engine.encrypt(
        plaintext=input_file.read_bytes(),
        recipient=recipient,
        tier=tier_enum,
        associated_data=f"file:{input_file.name}".encode(),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(
        orjson.dumps(
            envelope.model_dump(mode="json"),
            option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS,
        )
    )
    console.print(
        f"[green]Encrypted {input_file.name} -> {output} "
        f"(tier={envelope.tier.value}, suite={envelope.cipher_suite})[/green]"
    )


@app.command("decrypt")
def decrypt_cmd(
    envelope_file: Annotated[Path, typer.Argument(help="EncryptedEnvelope JSON file.")],
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Destination path for decrypted plaintext."),
    ],
    sender_file: Annotated[
        Path | None,
        typer.Option("--sender", "-s", help="Optional expected sender PublicIdentityBundle JSON."),
    ] = None,
    keyring_file: Annotated[
        Path | None,
        typer.Option("--keyring", "-k", help="Optional sender TrustKeyring JSON file."),
    ] = None,
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Optional YAML configuration file."),
    ] = None,
) -> None:
    """Authenticate and decrypt a hybrid post-quantum Q-Aegis EncryptedEnvelope file."""
    if not envelope_file.is_file():
        console.print(f"[red]Encrypted file not found: {envelope_file}[/red]")
        raise typer.Exit(code=2)

    cfg = load_config(config_file)
    cfg.ensure_directories()
    mgr = IdentityManager(keys_dir=cfg.keys_dir, node_id=cfg.node_id, config=cfg.identity)
    identity = mgr.load_or_create()

    envelope = EncryptedEnvelope.model_validate(orjson.loads(envelope_file.read_bytes()))
    sender = (
        PublicIdentityBundle.model_validate(orjson.loads(sender_file.read_bytes()))
        if sender_file is not None
        else None
    )
    keyring = (
        TrustKeyring.model_validate(orjson.loads(keyring_file.read_bytes()))
        if keyring_file is not None
        else None
    )

    engine = CryptoAgilityEngine(identity=identity, config=cfg.chameleon_fw)
    plaintext = engine.decrypt(
        envelope,
        expected_sender=sender,
        expected_sender_keyring=keyring,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(plaintext)
    console.print(
        f"[green]Decrypted & verified {envelope_file.name} -> {output} ({len(plaintext)} B)[/green]"
    )


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
    from qaegis.modules.qubit_compiler.autoencoder import AngleEncoderPipeline
    from qaegis.modules.qubit_compiler.circuit_builder import (
        BackendNoiseProfile,
        NoiseAwareCircuitBuilder,
    )

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

    from qaegis.modules.quantum_dreamer.service import NightCycleReport, QuantumDreamerService
    from qaegis.modules.qubit_compiler.qubo_mapper import build_maxcut_qubo

    async def _run() -> NightCycleReport:
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
            return await dreamer.run_night_cycle(max_problems=4)
        finally:
            await storage.close()
            await bus.stop()

    report = asyncio.run(_run())
    table = Table(title="Quantum Dreaming Night-Mode Results")
    table.add_column("Problem ID", style="cyan")
    table.add_column("Backend", style="magenta")
    table.add_column("Best Bitstring", style="green")
    table.add_column("Energy", style="yellow")
    table.add_column("Approx Ratio", style="green")
    show_mitigated = mitigation != "none"
    if show_mitigated:
        table.add_column("Mitigated <E>", style="cyan")
    for sol in report.solutions:
        ratio = sol.approximation_ratio
        row_cells = [
            sol.problem_id,
            sol.backend_name,
            sol.optimal_bitstring,
            f"{sol.optimal_energy:.3f}",
            f"{ratio:.4f}" if ratio is not None else "n/a",
        ]
        if show_mitigated:
            mit_val = sol.mitigated_expected_energy
            row_cells.append(f"{mit_val:.4f}" if mit_val is not None else "n/a")
        table.add_row(*row_cells)
    console.print(table)


@app.command("entropy")
def entropy_cmd(
    qubits: Annotated[int, typer.Option("--qubits", "-q", help="Entangled circuit qubits.")] = 6,
    shots: Annotated[int, typer.Option("--shots", "-s", help="Quantum measurement shots.")] = 512,
) -> None:
    """Harvest a verified quantum probability distribution and display Shannon entropy."""

    from qaegis.modules.quantum_entropy.harvester import (
        QuantumDistributionBatch,
        QuantumDistributionHarvester,
    )

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


@app.command("dashboard")
def dashboard_cmd(
    host: Annotated[
        str | None,
        typer.Option("--host", help="HTTP bind address (default from config: 127.0.0.1)."),
    ] = None,
    port: Annotated[
        int | None,
        typer.Option("--port", "-p", help="HTTP listen port (default from config: 8080)."),
    ] = None,
    auth_token: Annotated[
        str | None,
        typer.Option(
            "--auth-token",
            help="Optional Bearer token protecting API/SSE routes (or QAEGIS_DASHBOARD_TOKEN).",
        ),
    ] = None,
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Optional YAML configuration file."),
    ] = None,
    max_seconds: Annotated[
        float | None,
        typer.Option("--max-seconds", help="Optional auto-exit duration in seconds (for tests)."),
    ] = None,
) -> None:
    """Launch the live Q-Aegis Web Mission-Control Dashboard with all 5 subsystems active."""
    cfg = load_config(config_file)
    configure_logging(cfg.telemetry)
    cfg.ensure_directories()

    async def _run_dashboard() -> None:
        from qaegis.dashboard import DashboardKernelRuntime, DashboardServer

        metrics = QAegisMetrics()
        runtime = DashboardKernelRuntime(
            config=cfg,
            config_file_path=config_file,
            metrics=metrics,
        )
        server = DashboardServer(
            runtime=runtime,
            host=host,
            port=port,
            auth_token=auth_token,
        )
        await server.start()
        console.print(
            f"[bold green]Q-Aegis Live Web Mission-Control Dashboard online at "
            f"{server.url}[/bold green]"
        )

        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        if sys.platform != "win32":
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, stop_event.set)
        try:
            if max_seconds is not None:
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop_event.wait(), timeout=max_seconds)
            else:
                await stop_event.wait()
        finally:
            if sys.platform != "win32":
                for sig in (signal.SIGINT, signal.SIGTERM):
                    loop.remove_signal_handler(sig)
            await server.stop()

    asyncio.run(_run_dashboard())


@app.command("run")
def run_cmd(
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Optional YAML configuration file."),
    ] = None,
    dashboard: Annotated[
        bool,
        typer.Option("--dashboard", help="Also serve the live Web Mission-Control Dashboard."),
    ] = False,
    dashboard_port: Annotated[
        int | None,
        typer.Option("--dashboard-port", help="Override HTTP port when --dashboard is enabled."),
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
        from qaegis.dashboard import DashboardKernelRuntime, DashboardServer
        from qaegis.modules.chameleon_fw.service import ChameleonFirewallService
        from qaegis.modules.quantum_dreamer.service import QuantumDreamerService
        from qaegis.modules.quantum_entropy.service import QuantumEntropyService
        from qaegis.modules.qubit_compiler.service import QubitCompilerService
        from qaegis.modules.reality_stamp.service import RealityStampService

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

        dash_server: DashboardServer | None = None
        if dashboard or cfg.dashboard.enabled:
            dash_runtime = DashboardKernelRuntime(
                config=cfg,
                config_file_path=config_file,
                metrics=metrics,
                bus=bus,
                storage=storage,
                lifecycle=lifecycle,
                identity=identity,
                reality_service=reality_svc,
                chameleon_service=chameleon_svc,
                compiler_service=compiler_svc,
                dreamer_service=dreamer_svc,
                entropy_service=entropy_svc,
            )
            dash_server = DashboardServer(
                runtime=dash_runtime,
                port=dashboard_port,
            )
            await dash_server.start()
            console.print(
                f"[bold cyan]Web Mission-Control Dashboard serving on {dash_server.url}[/bold cyan]"
            )

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
            if sys.platform != "win32":
                for sig in (signal.SIGINT, signal.SIGTERM):
                    loop.remove_signal_handler(sig)
            if dash_server is not None:
                await dash_server.stop()
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
