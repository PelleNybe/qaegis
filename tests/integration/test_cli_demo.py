"""Integration test for interactive `qaegis demo --fast` and observability asset validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from qaegis.cli import app


@pytest.mark.integration
def test_cli_interactive_demo_fast() -> None:
    from rich.console import Console

    runner = CliRunner()
    res = runner.invoke(app, ["demo", "--fast"])
    assert res.exit_code == 0, res.output
    assert "1. PQC Identity" in res.output
    assert "2. Proof of Reality" in res.output
    assert "3. Chameleon Firewall" in res.output
    assert "4. AI-to-Qubit Compiler" in res.output
    assert "5. QAOA + ZNE/TREX" in res.output

    # Also verify structured DemoReport deterministic 3-tier Chameleon escalation
    import asyncio

    from qaegis.demo import run_interactive_demo

    report = asyncio.run(run_interactive_demo(fast=True, console=Console(quiet=True)))
    assert report.all_passed is True
    assert report.stages[2].outcome == "STANDARD -> ELEVATED -> QUANTUM_CRITICAL"


@pytest.mark.unit
def test_observability_grafana_and_prometheus_assets() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    dashboard_path = repo_root / "deploy" / "grafana" / "qaegis-dashboard.json"
    alerts_path = repo_root / "deploy" / "prometheus" / "alerts.yml"

    assert dashboard_path.is_file()
    dashboard = json.loads(dashboard_path.read_text(encoding="utf-8"))
    assert dashboard["schemaVersion"] >= 38
    assert len(dashboard["panels"]) >= 6

    assert alerts_path.is_file()
    alerts = yaml.safe_load(alerts_path.read_text(encoding="utf-8"))
    rule_names = {r["alert"] for r in alerts["groups"][0]["rules"]}
    for expected in (
        "QAegisGossipEquivocationDetected",
        "QAegisQRNGHealthFailure",
        "QAegisCurveZMQAuthSpike",
        "QAegisPolicyRollbackTriggered",
    ):
        assert expected in rule_names
