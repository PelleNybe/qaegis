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
from qaegis.core.config import load_config
from qaegis.core.identity import IdentityManager
from qaegis.core.storage import StorageEngine
from qaegis.core.telemetry import configure_logging

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
