"""End-to-end integration tests for the Q-Aegis Live Web Mission-Control Dashboard."""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest
import yaml
from typer.testing import CliRunner

from qaegis.cli import app
from qaegis.core.config import (
    DashboardConfig,
    QAegisConfig,
    QuantumDreamerConfig,
    RealityStampConfig,
)
from qaegis.dashboard import DashboardKernelRuntime, DashboardServer


@pytest.mark.integration
async def test_web_dashboard_full_control_plane_config_and_sse(tmp_path: Path) -> None:
    """Verify static UI, SSE event streaming, hot-config YAML persistence, and all 5 modules."""
    cfg_file = tmp_path / "qaegis.yaml"
    cfg = QAegisConfig(
        node_id="qaegis-web-test-01",
        data_dir=tmp_path / "data",
        keys_dir=tmp_path / "keys",
        db_path=tmp_path / "data" / "web.db",
        dashboard=DashboardConfig(enabled=True, host="127.0.0.1", port=0, sse_heartbeat_s=5.0),
        reality_stamp=RealityStampConfig(strict_nist_checks=False),
        quantum_dreamer=QuantumDreamerConfig(
            backend_type="aer_statevector",
            qaoa_reps=1,
            qaoa_shots=128,
            max_optimizer_iters=10,
        ),
    )
    runtime = DashboardKernelRuntime(config=cfg, config_file_path=cfg_file)

    async with DashboardServer(runtime=runtime, host="127.0.0.1", port=0) as server:
        base_url = server.url
        async with httpx.AsyncClient(base_url=base_url, timeout=30.0) as client:
            # 1. Static UI & Security Headers
            r_html = await client.get("/")
            assert r_html.status_code == 200
            assert "Q-Aegis Mission Control" in r_html.text
            assert "https://coraxcolab.com" in r_html.text
            assert "https://github.com/PelleNybe" in r_html.text
            assert "https://buymeacoffee.com/pellenybe" in r_html.text
            assert r_html.headers["x-content-type-options"] == "nosniff"
            assert (await client.get("/assets/app.css")).status_code == 200
            assert (await client.get("/assets/app.js")).status_code == 200
            assert (await client.get("/healthz")).json()["status"] == "ok"

            # 2. Overview & Doctor Diagnostics
            ov = (await client.get("/api/overview")).json()
            assert ov["node_id"] == "qaegis-web-test-01"
            assert ov["subsystems"]["reality_stamp"]["status"] == "ONLINE"
            doc = (await client.get("/api/doctor")).json()
            assert doc["healthy"] is True

            # 3. Live SSE Stream (initial overview + real-time EventBus delivery)
            received_lines: list[str] = []

            async def _consume_sse() -> None:
                async with client.stream("GET", "/api/events/stream") as sse_resp:
                    assert sse_resp.status_code == 200
                    async for line in sse_resp.aiter_lines():
                        if line:
                            received_lines.append(line)
                        if any("sse.test_ping" in item for item in received_lines):
                            break

            sse_task = asyncio.create_task(_consume_sse())
            await asyncio.sleep(0.15)
            await runtime.bus.publish("sse.test_ping", {"hello": "mission_control"})
            await asyncio.wait_for(sse_task, timeout=5.0)
            assert any("event: overview" in line for line in received_lines)
            assert any("sse.test_ping" in line for line in received_lines)

            # 4. Configuration Center: Read, Validate Error (422), Hot-Update + Save YAML, Reset
            cfg_bundle = (await client.get("/api/config")).json()
            assert cfg_bundle["config"]["node_id"] == "qaegis-web-test-01"

            bad_resp = await client.put(
                "/api/config",
                json={
                    "config": {
                        "chameleon_fw": {
                            "elevated_risk_threshold": 0.90,
                            "critical_risk_threshold": 0.40,
                        }
                    }
                },
            )
            assert bad_resp.status_code == 422

            upd_resp = await client.put(
                "/api/config",
                json={
                    "persist_yaml": True,
                    "config": {
                        "chameleon_fw": {
                            "elevated_risk_threshold": 0.40,
                            "critical_risk_threshold": 0.80,
                        },
                        "quantum_entropy": {"harvester_qubits": 4, "harvester_shots": 128},
                    },
                },
            )
            assert upd_resp.status_code == 200
            assert runtime.config.chameleon_fw.critical_risk_threshold == 0.80
            assert cfg_file.is_file()
            saved_yaml = yaml.safe_load(cfg_file.read_text(encoding="utf-8"))
            assert saved_yaml["quantum_entropy"]["harvester_qubits"] == 4

            yaml_resp = await client.post(
                "/api/config/yaml",
                json={
                    "yaml": "lifecycle:\n  idle_cpu_threshold_pct: 33.5\n",
                    "persist_yaml": True,
                },
            )
            assert yaml_resp.status_code == 200
            assert runtime.config.lifecycle.idle_cpu_threshold_pct == 33.5

            # 5. Lifecycle Mode Toggle & Zero-Downtime Key Rotation + CBOM
            mode_resp = await client.post(
                "/api/lifecycle/mode",
                json={"mode": "NIGHT", "reason": "web_test"},
            )
            assert mode_resp.status_code == 200
            assert mode_resp.json()["new_mode"] == "NIGHT"
            await client.post("/api/lifecycle/mode", json={"mode": "DAY"})

            rot_resp = await client.post("/api/identity/rotate", json={"seal_backend": "none"})
            assert rot_resp.status_code == 200
            assert rot_resp.json()["active_bundle"]["key_version"] == 2
            cbom = (await client.get("/api/identity/cbom?format=cyclonedx")).json()
            assert cbom["bomFormat"] == "CycloneDX"

            # 6. Module 1: Proof of Reality & Gossip
            stamp = (
                await client.post(
                    "/api/reality/stamp",
                    json={
                        "sensor_id": "cam-web-01",
                        "perception_label": "drone_spotted",
                        "confidence": 0.95,
                        "metadata": {"alt_m": 42},
                    },
                )
            ).json()
            ver = (await client.post("/api/reality/verify", json={"stamp": stamp})).json()
            assert ver["valid"] is True
            assert ver["merkle_proof_ok"] is True

            art_sig = (
                await client.post(
                    "/api/reality/sign-artifact",
                    json={
                        "artifact_name": "weights_v1.onnx",
                        "content_text": '{"layers": 4, "version": "0.7.0"}',
                        "use_stateless_hash_sig": False,
                    },
                )
            ).json()
            art_ver_ok = (
                await client.post(
                    "/api/reality/verify-artifact",
                    json={
                        "bundle": art_sig,
                        "content_text": '{"layers": 4, "version": "0.7.0"}',
                    },
                )
            ).json()
            assert art_ver_ok["valid"] is True
            art_ver_bad = (
                await client.post(
                    "/api/reality/verify-artifact",
                    json={
                        "bundle": art_sig,
                        "content_text": '{"layers": 999, "tampered": true}',
                    },
                )
            ).json()
            assert art_ver_bad["valid"] is False
            assert art_ver_bad["digest_ok"] is False

            qrng = (await client.post("/api/reality/qrng", json={"num_bytes": 64})).json()
            assert qrng["num_bytes"] == 64
            gos_cp = (await client.post("/api/gossip/checkpoint", json={})).json()
            assert gos_cp["outcome"]["accepted"] is True
            assert (await client.get("/api/reality/state")).json()["tree_size"] >= 1
            assert (await client.get("/api/gossip")).status_code == 200

            # 7. Module 2: Quantum Chameleon Firewall
            cham = (
                await client.post(
                    "/api/chameleon/protect",
                    json={
                        "protocol": "satellite",
                        "sensitivity": "top_secret",
                        "retention_years": 15.0,
                        "payload_text": "classified_navigation_vector",
                    },
                )
            ).json()
            assert cham["roundtrip_verified"] is True
            assert cham["assessment"]["tier"] == "QUANTUM_CRITICAL"

            # 8. Module 3: AI-to-Qubit Compiler (Train ONNX + Compile OpenQASM 3.0 & PennyLane)
            tr = (
                await client.post(
                    "/api/compiler/train",
                    json={"epochs": 8, "samples_count": 32},
                )
            ).json()
            assert tr["final_loss"] <= tr["initial_loss"] + 0.5
            comp = (
                await client.post(
                    "/api/compiler/compile",
                    json={"vector": [0.2, -0.4, 0.7, 0.1], "run_pennylane": True},
                )
            ).json()
            assert "OPENQASM 3.0" in comp["artifact"]["openqasm3"]
            assert comp["angles"]["encoder_backend"] == "onnxruntime_cpu"

            # 9. Module 4: Quantum Dreamer (Enqueue + Night QAOA + Federated)
            enq = (
                await client.post(
                    "/api/dreamer/enqueue",
                    json={"kind": "maxcut", "num_nodes": 3, "priority": 90},
                )
            ).json()
            assert "problem_id" in enq
            await client.post("/api/dreamer/enqueue", json={"kind": "scheduling"})
            await client.post("/api/dreamer/enqueue", json={"kind": "resource_allocation"})

            night = (
                await client.post(
                    "/api/dreamer/run-night",
                    json={
                        "max_problems": 1,
                        "backend": "aer_statevector",
                        "mitigation": "none",
                    },
                )
            ).json()
            assert len(night["solutions"]) == 1
            assert (await client.get("/api/dreamer/state")).status_code == 200

            fed = (
                await client.post(
                    "/api/dreamer/federated",
                    json={"fleet_nodes": 3, "budget_seconds": 60.0},
                )
            ).json()
            assert fed["unique_problems_solved"] == 1
            assert fed["deduplicated_count"] == 2

            # 10. Module 5: Quantum Entropy, Audit Chain & Raw Prometheus Metrics
            ent = (
                await client.post(
                    "/api/entropy/harvest",
                    json={"num_qubits": 3, "shots": 128, "noise_rate": 0.01},
                )
            ).json()
            assert ent["pool_bytes"] >= 32
            tok = (await client.post("/api/entropy/sample-logits", json={})).json()
            assert tok["candidate_count"] >= 1
            evo = (
                await client.post(
                    "/api/entropy/evolve",
                    json={"genome_dim": 4, "population_size": 6, "generations": 5},
                )
            ).json()
            assert len(evo["best_genome"]) == 4
            assert (await client.get("/api/entropy/ollama")).status_code == 200

            audit = (await client.get("/api/audit?limit=50")).json()
            assert audit["chain_valid"] is True
            assert audit["total_records"] >= 3

            prom = await client.get("/api/metrics/raw")
            assert prom.status_code == 200
            assert "qaegis_reality_stamps_signed_total" in prom.text

            assert (
                await client.post("/api/config/reset", json={"persist_yaml": False})
            ).status_code == 200


@pytest.mark.integration
async def test_web_dashboard_bearer_token_auth(tmp_path: Path) -> None:
    """Verify constant-time Bearer token protection on dashboard API routes."""
    cfg = QAegisConfig(
        node_id="qaegis-auth-node",
        data_dir=tmp_path / "data",
        keys_dir=tmp_path / "keys",
        db_path=tmp_path / "data" / "auth.db",
        reality_stamp=RealityStampConfig(strict_nist_checks=False),
    )
    runtime = DashboardKernelRuntime(config=cfg)
    async with (
        DashboardServer(
            runtime=runtime,
            host="127.0.0.1",
            port=0,
            auth_token="quantum-secret-token-99",
        ) as server,
        httpx.AsyncClient(base_url=server.url, timeout=10.0) as client,
    ):
        # Public HTML still loads so browser can prompt for token
        assert (await client.get("/")).status_code == 200
        assert (await client.get("/api/auth-status")).json()["auth_required"] is True

        # Protected API without token -> 401
        assert (await client.get("/api/overview")).status_code == 401
        # Wrong token -> 401
        assert (
            await client.get(
                "/api/overview",
                headers={"Authorization": "Bearer wrong-token"},
            )
        ).status_code == 401
        # Correct token via Bearer header -> 200
        ok_resp = await client.get(
            "/api/overview",
            headers={"Authorization": "Bearer quantum-secret-token-99"},
        )
        assert ok_resp.status_code == 200


@pytest.mark.integration
def test_cli_dashboard_and_run_with_dashboard(tmp_path: Path) -> None:
    """Verify CLI `qaegis dashboard` and `qaegis run --dashboard` lifecycle startup/shutdown."""
    cli_yaml = tmp_path / "cli_dash.yaml"
    cli_yaml.write_text(
        yaml.safe_dump(
            {
                "node_id": "cli-dash-node",
                "data_dir": str(tmp_path / "cli_data"),
                "keys_dir": str(tmp_path / "cli_keys"),
                "db_path": str(tmp_path / "cli_data" / "cli.db"),
                "telemetry": {"enabled": False},
                "reality_stamp": {"strict_nist_checks": False},
            }
        ),
        encoding="utf-8",
    )
    runner = CliRunner()
    res_dash = runner.invoke(
        app,
        ["dashboard", "--config", str(cli_yaml), "--port", "0", "--max-seconds", "0.2"],
    )
    assert res_dash.exit_code == 0, res_dash.stdout
    assert "Mission-Control Dashboard online" in res_dash.stdout

    res_run = runner.invoke(
        app,
        [
            "run",
            "--config",
            str(cli_yaml),
            "--dashboard",
            "--dashboard-port",
            "0",
            "--max-ticks",
            "1",
            "--tick-interval",
            "0.05",
        ],
    )
    assert res_run.exit_code == 0, res_run.stdout
    assert "Web Mission-Control Dashboard serving" in res_run.stdout
