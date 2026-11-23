"""Quantum Error Mitigation tests verifying ZNE and TREX error reduction on noisy Aer."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
from qiskit_aer.noise import NoiseModel, ReadoutError, depolarizing_error
from typer.testing import CliRunner

from qaegis.cli import app
from qaegis.core.config import QuantumDreamerConfig
from qaegis.modules.quantum_dreamer.mitigation import (
    ErrorMitigationPipeline,
    extrapolate_zero_noise,
    fold_circuit_unitary,
)
from qaegis.modules.quantum_dreamer.solvers import (
    AerNoisyBackend,
    AerStatevectorBackend,
    QaoaSolver,
    build_qaoa_circuit,
)
from qaegis.modules.qubit_compiler.qubo_mapper import (
    build_maxcut_qubo,
    evaluate_ising,
    qubo_to_ising,
)


def _build_noisy_aer(
    err_1q: float = 0.006,
    err_2q: float = 0.03,
    p0_given_1: float = 0.12,
    p1_given_0: float = 0.04,
) -> AerSimulator:
    """Create a realistic noisy AerSimulator with depolarizing gate + asymmetric readout error."""
    nm = NoiseModel()
    nm.add_all_qubit_quantum_error(depolarizing_error(err_1q, 1), ["h", "rx", "ry", "rz", "x"])
    nm.add_all_qubit_quantum_error(depolarizing_error(err_2q, 2), ["cx", "rzz"])
    ro = ReadoutError([[1.0 - p1_given_0, p1_given_0], [p0_given_1, 1.0 - p0_given_1]])
    nm.add_all_qubit_readout_error(ro)
    return AerSimulator(noise_model=nm)


@pytest.mark.quantum
def test_unitary_folding_and_extrapolation_math() -> None:
    qc = QuantumCircuit(2)
    qc.h(0)
    qc.cx(0, 1)
    qc.rx(0.4, 1)
    qc.measure_all()

    f1 = fold_circuit_unitary(qc, 1)
    f3 = fold_circuit_unitary(qc, 3)
    f5 = fold_circuit_unitary(qc, 5)
    assert f3.depth() > f1.depth()
    assert f5.depth() > f3.depth()

    # Exact synthetic decay E(s) = -4.0 + 0.5 * s -> E(0) = -4.0
    assert extrapolate_zero_noise([1, 3, 5], [-3.5, -2.5, -1.5], method="linear") == pytest.approx(
        -4.0
    )
    assert extrapolate_zero_noise(
        [1, 3, 5], [-3.5, -2.5, -1.5], method="richardson"
    ) == pytest.approx(-4.0)
    # Exponential decay E(s) = -5.0 + 3.0 * exp(-0.4 * s) -> E(0) = -2.0
    exp_vals = [-5.0 + 3.0 * float(np.exp(-0.4 * s)) for s in (1, 3, 5)]
    assert extrapolate_zero_noise([1, 3, 5], exp_vals, method="exponential") == pytest.approx(
        -2.0, abs=1e-2
    )


@pytest.mark.quantum
def test_zne_and_trex_measurably_reduce_noisy_expectation_error() -> None:
    qubo = build_maxcut_qubo(4, [(0, 1, 1.5), (1, 2, 1.5), (2, 3, 1.5), (3, 0, 1.5)])
    ham = qubo_to_ising(qubo)
    gammas = [0.45, 0.70]
    betas = [0.55, 0.25]
    qc = build_qaoa_circuit(ham, gammas, betas, measure=True)

    # Exact statevector ground truth expectation <H_Ising>
    sv_dist = AerStatevectorBackend().sample_distribution(ham, gammas, betas, shots=1)
    exact_energy = sum(prob * evaluate_ising(ham, bs) for bs, prob in sv_dist.items())

    noisy_sim = _build_noisy_aer(err_1q=0.005, err_2q=0.025, p0_given_1=0.14, p1_given_0=0.04)

    # 1. TREX readout mitigation
    trex_pipe = ErrorMitigationPipeline(noisy_sim, mode="trex", num_twirls=16, seed=42)
    trex_res = trex_pipe.evaluate_expectation(qc, ham, shots=4096)

    # 2. ZNE gate-noise mitigation (linear extrapolation for robust low-variance noisy estimation)
    zne_pipe = ErrorMitigationPipeline(
        noisy_sim,
        mode="zne",
        scale_factors=[1, 3, 5],
        extrapolation="linear",
        seed=42,
    )
    zne_res = zne_pipe.evaluate_expectation(qc, ham, shots=4096)

    # 3. Combined ZNE + TREX mitigation
    both_pipe = ErrorMitigationPipeline(
        noisy_sim,
        mode="both",
        scale_factors=[1, 3, 5],
        extrapolation="linear",
        num_twirls=16,
        seed=42,
    )
    both_res = both_pipe.evaluate_expectation(qc, ham, shots=4096)

    raw_err = abs(both_res.unmitigated_energy - exact_energy)
    trex_err = abs(trex_res.mitigated_energy - exact_energy)
    zne_err = abs(zne_res.mitigated_energy - exact_energy)
    both_err = abs(both_res.mitigated_energy - exact_energy)

    assert raw_err > 0.2, f"Expected noticeable noise error, got {raw_err}"
    assert trex_err < raw_err, f"TREX did not reduce error: {trex_err} >= {raw_err}"
    assert zne_err < raw_err, f"ZNE did not reduce error: {zne_err} >= {raw_err}"
    assert both_err < raw_err, f"ZNE+TREX did not reduce error: {both_err} >= {raw_err}"


@pytest.mark.quantum
def test_qaoa_solver_with_mitigation_and_cli_flag(tmp_path: Path) -> None:
    qubo = build_maxcut_qubo(4, [(0, 1, 1.5), (1, 2, 1.5), (2, 3, 1.5), (3, 0, 1.5)])
    solver = QaoaSolver(
        config=QuantumDreamerConfig(
            backend_type="aer_noisy",
            qaoa_reps=1,
            qaoa_shots=512,
            max_optimizer_iters=15,
            mitigation_mode="both",
            zne_scale_factors=[1, 3],
            zne_extrapolation="linear",
        ),
        backend=AerNoisyBackend(seed=99),
    )
    sol = solver.solve(qubo)
    assert sol.mitigation_mode == "both"
    assert sol.mitigated_expected_energy is not None

    cfg_file = tmp_path / "mit_cli.yaml"
    cfg_file.write_text(
        (
            f"data_dir: {tmp_path}/d\n"
            f"keys_dir: {tmp_path}/k\n"
            f"db_path: {tmp_path}/d/q.db\n"
            f"quantum_dreamer:\n"
            f"  qaoa_reps: 1\n"
            f"  qaoa_shots: 256\n"
            f"  max_optimizer_iters: 12\n"
            f"  zne_scale_factors: [1, 3]\n"
            f"  zne_extrapolation: linear\n"
        ),
        encoding="utf-8",
    )
    runner = CliRunner()
    res = runner.invoke(
        app,
        [
            "dream",
            "--nodes",
            "4",
            "--backend",
            "aer_noisy",
            "--mitigation",
            "both",
            "--config",
            str(cfg_file),
        ],
    )
    assert res.exit_code == 0, res.output
    assert "aer_noisy" in res.output
