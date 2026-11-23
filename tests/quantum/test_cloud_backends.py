"""Multi-cloud quantum backend tests: AWS Braket LocalSimulator, IonQ API v0.3, and Registry."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from qaegis.cli import app
from qaegis.core.config import QuantumDreamerConfig
from qaegis.modules.quantum_dreamer.backends import (
    AwsBraketBackend,
    IonQBackend,
    build_braket_openqasm3,
    qiskit_to_ionq_circuit,
)
from qaegis.modules.quantum_dreamer.solvers import (
    AerStatevectorBackend,
    QaoaSolver,
    build_qaoa_circuit,
    get_backend_registry,
)
from qaegis.modules.qubit_compiler.qubo_mapper import build_maxcut_qubo, qubo_to_ising


@pytest.mark.quantum
def test_aws_braket_local_simulator_qaoa_maxcut() -> None:
    qubo = build_maxcut_qubo(4, [(0, 1, 1.5), (1, 2, 1.5), (2, 3, 1.5), (3, 0, 1.5)])
    ham = qubo_to_ising(qubo)
    qasm = build_braket_openqasm3(ham, gammas=[0.4], betas=[0.3])
    assert "OPENQASM 3.0;" in qasm
    assert "cnot " in qasm

    backend = AwsBraketBackend()
    assert backend.name == "aws_braket:local_simulator"
    solver = QaoaSolver(
        config=QuantumDreamerConfig(
            backend_type="aws_braket",
            qaoa_reps=1,
            qaoa_shots=256,
            max_optimizer_iters=25,
        ),
        backend=backend,
    )
    sol = solver.solve(qubo)
    assert sol.backend_name == "aws_braket:local_simulator"
    assert sol.exact_ground_energy == pytest.approx(-6.0)
    assert sol.approximation_ratio is not None
    assert sol.approximation_ratio >= 0.99


@pytest.mark.quantum
def test_ionq_gate_compilation_api_v03_and_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    qubo = build_maxcut_qubo(4, [(0, 1, 1.0), (1, 2, 1.0), (2, 3, 1.0), (3, 0, 1.0)])
    ham = qubo_to_ising(qubo)
    qc = build_qaoa_circuit(ham, gammas=[0.5], betas=[0.3], measure=False)
    ionq_body = qiskit_to_ionq_circuit(qc)
    assert ionq_body["qubits"] == 4
    gate_names = {g["gate"] for g in ionq_body["circuit"]}
    assert {"h", "cnot", "rz", "rx"}.issubset(gate_names)

    # Exercise full IonQ API v0.3 submit -> poll -> results -> calibration contract
    poll_calls = {"count": 0}

    def _ionq_transport(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path.endswith("/v0.3/jobs"):
            return httpx.Response(200, json={"id": "job-ionq-42", "status": "submitted"})
        if request.method == "GET" and request.url.path.endswith("/v0.3/jobs/job-ionq-42"):
            poll_calls["count"] += 1
            if poll_calls["count"] == 1:
                return httpx.Response(200, json={"id": "job-ionq-42", "status": "running"})
            return httpx.Response(
                200,
                json={
                    "id": "job-ionq-42",
                    "status": "completed",
                    "calibration": {"fidelity_1q": 0.9992, "fidelity_2q": 0.994},
                },
            )
        if request.method == "GET" and request.url.path.endswith("/v0.3/jobs/job-ionq-42/results"):
            # State 5 = 0b0101 -> bitstring '1010' (exact Max-Cut ground state)
            return httpx.Response(200, json={"histogram": {"5": 0.65, "10": 0.35}})
        return httpx.Response(404)

    with httpx.Client(transport=httpx.MockTransport(_ionq_transport)) as client:
        ionq = IonQBackend(
            target="qpu.aria-1",
            api_key="test-key",
            poll_interval_s=0.0,
            http_client=client,
        )
        assert ionq.name == "ionq:qpu.aria-1"
        dist = ionq.sample_distribution(ham, gammas=[0.5], betas=[0.3], shots=128)
        assert dist["1010"] == pytest.approx(0.65)
        assert dist["0101"] == pytest.approx(0.35)
        assert ionq.last_calibration["fidelity_2q"] == pytest.approx(0.994)

    # Without IONQ_API_KEY, transparently falls back to local noisy Aer
    monkeypatch.delenv("IONQ_API_KEY", raising=False)
    offline_ionq = IonQBackend(target="qpu.aria-1")
    assert offline_ionq.name == "ionq:aer_noisy_fallback"
    fallback_dist = offline_ionq.sample_distribution(ham, gammas=[0.5], betas=[0.3], shots=128)
    assert pytest.approx(sum(fallback_dist.values()), abs=1e-6) == 1.0


@pytest.mark.quantum
def test_backend_registry_and_cli_dream_braket(tmp_path: Path) -> None:
    reg = get_backend_registry()
    available = reg.available_backends()
    for required in ("aer_noisy", "aer_statevector", "aws_braket", "ibm_runtime", "ionq"):
        assert required in available

    # Verify dynamic third-party plugin registration
    reg.register("custom_test_sv", lambda _cfg: AerStatevectorBackend())
    assert reg.create("custom_test_sv", QuantumDreamerConfig()).name == "aer_statevector"

    cfg_file = tmp_path / "braket_cli.yaml"
    cfg_file.write_text(
        (
            f"data_dir: {tmp_path}/d\n"
            f"keys_dir: {tmp_path}/k\n"
            f"db_path: {tmp_path}/d/q.db\n"
            f"quantum_dreamer:\n"
            f"  qaoa_reps: 1\n"
            f"  qaoa_shots: 128\n"
            f"  max_optimizer_iters: 15\n"
        ),
        encoding="utf-8",
    )
    runner = CliRunner()
    res = runner.invoke(
        app,
        ["dream", "--nodes", "4", "--backend", "aws_braket", "--config", str(cfg_file)],
    )
    assert res.exit_code == 0, res.output
    assert "aws_braket:local_simulator" in res.output
