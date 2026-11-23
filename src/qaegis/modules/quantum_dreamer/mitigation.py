"""Quantum Error Mitigation Pipelines: Zero-Noise Extrapolation (ZNE) & TREX on Qiskit 2.x."""

from __future__ import annotations

import warnings
from typing import Any, Literal

import numpy as np
from pydantic import BaseModel, Field
from qiskit import QuantumCircuit, transpile
from scipy.optimize import OptimizeWarning, curve_fit

from qaegis.core.telemetry import QAegisMetrics
from qaegis.modules.qubit_compiler.qubo_mapper import IsingHamiltonian

ExtrapolationMethod = Literal["linear", "richardson", "exponential"]
MitigationMode = Literal["none", "zne", "trex", "both"]


class MitigatedExpectationResult(BaseModel):
    """Detailed result comparing unmitigated vs ZNE/TREX error-mitigated Ising expectation."""

    mode: MitigationMode
    unmitigated_energy: float
    mitigated_energy: float
    scale_factors: list[int] = Field(default_factory=list)
    scale_energies: list[float] = Field(default_factory=list)
    trex_calibration_factors: list[float] = Field(default_factory=list)


def strip_measurements(qc: QuantumCircuit) -> QuantumCircuit:
    """Return a copy of `qc` containing only non-measurement unitary instructions."""
    unitary = QuantumCircuit(qc.num_qubits)
    qubit_map = {q: idx for idx, q in enumerate(qc.qubits)}
    for inst in qc.data:
        if str(inst.operation.name).lower() == "measure":
            continue
        q_indices = [qubit_map[q] for q in inst.qubits]
        unitary.append(inst.operation, q_indices)
    return unitary


def fold_circuit_unitary(qc: QuantumCircuit, scale_factor: int) -> QuantumCircuit:
    """Perform exact global unitary circuit folding U -> U (U^dagger U)^k for odd scale_factor.

    Inserts barriers between folded segments so the Qiskit transpiler preserves noise scaling
    instead of canceling adjacent U^dagger * U pairs.
    """
    if scale_factor < 1 or scale_factor % 2 == 0:
        raise ValueError(
            f"Unitary folding requires an odd positive scale_factor, got {scale_factor}"
        )

    unitary = strip_measurements(qc)
    n = unitary.num_qubits
    if scale_factor == 1:
        folded = unitary.copy()
        folded.measure_all()
        return folded

    inv_unitary = unitary.inverse()
    k = (scale_factor - 1) // 2

    folded = QuantumCircuit(n, n)
    folded.compose(unitary, inplace=True)
    for _ in range(k):
        folded.barrier()
        folded.compose(inv_unitary, inplace=True)
        folded.barrier()
        folded.compose(unitary, inplace=True)
    folded.barrier()
    folded.measure(range(n), range(n))
    return folded


def extrapolate_zero_noise(
    scale_factors: list[int] | list[float],
    values: list[float],
    method: ExtrapolationMethod = "richardson",
) -> float:
    """Extrapolate noisy expectation values E(s) to the zero-noise limit E(0)."""
    if len(scale_factors) != len(values) or len(values) < 2:
        raise ValueError("Zero-noise extrapolation requires at least 2 (scale, value) points")

    xs = np.asarray(scale_factors, dtype=np.float64)
    ys = np.asarray(values, dtype=np.float64)

    if method == "linear":
        slope, intercept = np.polyfit(xs, ys, deg=1)
        del slope
        return float(intercept)

    if method == "richardson":
        # Exact Lagrange interpolation polynomial evaluated at x = 0
        total = 0.0
        m = len(xs)
        for j in range(m):
            coeff = 1.0
            for k in range(m):
                if k != j:
                    coeff *= -xs[k] / (xs[j] - xs[k])
            total += float(ys[j]) * coeff
        return float(total)

    # Exponential fit: E(s) = c + a * exp(-b * s) -> E(0) = c + a
    if len(xs) < 3:
        slope, intercept = np.polyfit(xs, ys, deg=1)
        del slope
        return float(intercept)

    def _exp_model(s: np.ndarray, a: float, b: float, c: float) -> np.ndarray:
        out: np.ndarray = c + a * np.exp(-b * s)
        return out

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", OptimizeWarning)
            popt, _cov = curve_fit(
                _exp_model,
                xs,
                ys,
                p0=[float(ys[0] - ys[-1]), 0.3, float(ys[-1])],
                bounds=([-1e4, 1e-4, -1e4], [1e4, 10.0, 1e4]),
                maxfev=2000,
            )
        return float(popt[2] + popt[0])
    except Exception:
        # Clean linear fallback if noisy points are non-monotonic for exponential decay
        slope, intercept = np.polyfit(xs, ys, deg=1)
        del slope
        return float(intercept)


def _counts_to_ising_expectation(
    counts: dict[str, int],
    hamiltonian: IsingHamiltonian,
    trex_factors: list[float] | None = None,
) -> float:
    """Compute <H_Ising> from Qiskit count dict (little-endian keys) with optional TREX scaling."""
    total = float(sum(counts.values()))
    n = hamiltonian.num_qubits
    z_single = np.zeros(n, dtype=np.float64)
    z_pairs: dict[tuple[int, int], float] = {(c.i, c.j): 0.0 for c in hamiltonian.couplings}

    for raw_key, cnt in counts.items():
        # Strip spaces if measure_all created multiple classical registers
        key = raw_key.replace(" ", "")[::-1]
        prob = float(cnt) / total
        z = [1.0 if key[q] == "0" else -1.0 for q in range(n)]
        for q in range(n):
            z_single[q] += prob * z[q]
        for c in hamiltonian.couplings:
            z_pairs[(c.i, c.j)] += prob * z[c.i] * z[c.j]

    energy = hamiltonian.offset
    for q, h_i in enumerate(hamiltonian.linear_h):
        scale = trex_factors[q] if trex_factors is not None else 1.0
        energy += h_i * (float(z_single[q]) / scale)
    for c in hamiltonian.couplings:
        scale_ij = (trex_factors[c.i] * trex_factors[c.j]) if trex_factors is not None else 1.0
        energy += c.weight * (z_pairs[(c.i, c.j)] / scale_ij)
    return float(energy)


def calibrate_trex_factors(
    simulator: Any,
    num_qubits: int,
    num_twirls: int = 16,
    shots_per_twirl: int = 256,
    seed: int = 42,
) -> list[float]:
    """Estimate per-qubit TREX diagonal readout calibration factors lambda_q = <Z_q>_twirled."""
    rng = np.random.default_rng(seed)
    z_accum = np.zeros(num_qubits, dtype=np.float64)

    for t_idx in range(num_twirls):
        mask = rng.integers(0, 2, size=num_qubits)
        qc = QuantumCircuit(num_qubits, num_qubits)
        for q in range(num_qubits):
            if mask[q] == 1:
                qc.x(q)
        qc.measure(range(num_qubits), range(num_qubits))
        tqc = transpile(qc, simulator, optimization_level=0)
        counts: dict[str, int] = dict(
            simulator.run(tqc, shots=shots_per_twirl, seed_simulator=seed + t_idx)
            .result()
            .get_counts()
        )
        total = float(sum(counts.values()))
        for raw_key, cnt in counts.items():
            key = raw_key.replace(" ", "")[::-1]
            prob = float(cnt) / total
            for q in range(num_qubits):
                unmasked_bit = int(key[q]) ^ int(mask[q])
                z_accum[q] += prob * (1.0 if unmasked_bit == 0 else -1.0)

    factors = z_accum / float(num_twirls)
    # Guard against division by near-zero under extreme (>45%) readout error
    return [float(np.clip(f, 0.2, 1.0)) for f in factors]


def run_twirled_circuit_counts(
    unitary_qc: QuantumCircuit,
    simulator: Any,
    shots: int = 1024,
    num_twirls: int = 12,
    seed: int = 42,
) -> dict[str, int]:
    """Execute Pauli-X readout-twirled copies of a circuit and return unmasked counts."""
    n = unitary_qc.num_qubits
    rng = np.random.default_rng(seed)
    shots_each = max(16, shots // num_twirls)
    combined_counts: dict[str, int] = {}

    for t_idx in range(num_twirls):
        mask = rng.integers(0, 2, size=n)
        twirled = QuantumCircuit(n, n)
        twirled.compose(unitary_qc, inplace=True)
        twirled.barrier()
        for q in range(n):
            if mask[q] == 1:
                twirled.x(q)
        twirled.measure(range(n), range(n))
        tqc = transpile(twirled, simulator, optimization_level=0)
        raw_counts: dict[str, int] = dict(
            simulator.run(tqc, shots=shots_each, seed_simulator=seed + 100 + t_idx)
            .result()
            .get_counts()
        )
        for raw_key, cnt in raw_counts.items():
            # Unmask in x_0..x_{n-1} order, then store back in Qiskit little-endian order
            bits = raw_key.replace(" ", "")[::-1]
            unmasked = "".join(str(int(bits[q]) ^ int(mask[q])) for q in range(n))
            le_key = unmasked[::-1]
            combined_counts[le_key] = combined_counts.get(le_key, 0) + int(cnt)

    return combined_counts


class ErrorMitigationPipeline:
    """Production Qiskit ZNE & TREX error mitigation pipeline for noisy NISQ execution."""

    def __init__(
        self,
        simulator: Any,
        mode: MitigationMode = "both",
        scale_factors: list[int] | None = None,
        extrapolation: ExtrapolationMethod = "richardson",
        num_twirls: int = 12,
        seed: int = 42,
        metrics: QAegisMetrics | None = None,
    ) -> None:
        self._sim = simulator
        self._mode = mode
        self._scale_factors = scale_factors or [1, 3, 5]
        self._extrapolation = extrapolation
        self._num_twirls = num_twirls
        self._seed = seed
        self._metrics = metrics or QAegisMetrics()
        self._cached_trex: dict[int, list[float]] = {}

    def _get_trex_factors(self, num_qubits: int, shots: int) -> list[float]:
        cached = self._cached_trex.get(num_qubits)
        if cached is None:
            cached = calibrate_trex_factors(
                self._sim,
                num_qubits=num_qubits,
                num_twirls=max(self._num_twirls, 16),
                shots_per_twirl=max(128, shots // 4),
                seed=self._seed,
            )
            self._cached_trex[num_qubits] = cached
        return cached

    def evaluate_expectation(
        self,
        circuit: QuantumCircuit,
        hamiltonian: IsingHamiltonian,
        shots: int = 1024,
    ) -> MitigatedExpectationResult:
        """Evaluate <H_Ising> on noisy backend with configured ZNE / TREX error mitigation."""
        unitary = strip_measurements(circuit)
        raw_qc = unitary.copy()
        raw_qc.measure_all()
        t_raw = transpile(raw_qc, self._sim, optimization_level=0)
        raw_counts: dict[str, int] = dict(
            self._sim.run(t_raw, shots=shots, seed_simulator=self._seed).result().get_counts()
        )
        unmitigated = _counts_to_ising_expectation(raw_counts, hamiltonian)

        if self._mode == "none":
            return MitigatedExpectationResult(
                mode="none",
                unmitigated_energy=unmitigated,
                mitigated_energy=unmitigated,
            )

        use_trex = self._mode in ("trex", "both")
        use_zne = self._mode in ("zne", "both")
        trex_factors: list[float] = (
            self._get_trex_factors(hamiltonian.num_qubits, shots) if use_trex else []
        )

        if not use_zne:
            # TREX-only mitigation at noise scale 1
            twirled_counts = run_twirled_circuit_counts(
                unitary,
                self._sim,
                shots=shots,
                num_twirls=self._num_twirls,
                seed=self._seed,
            )
            mitigated = _counts_to_ising_expectation(twirled_counts, hamiltonian, trex_factors)
            self._metrics.mitigation_runs.labels(technique="trex").inc()
            return MitigatedExpectationResult(
                mode="trex",
                unmitigated_energy=unmitigated,
                mitigated_energy=mitigated,
                scale_factors=[1],
                scale_energies=[mitigated],
                trex_calibration_factors=trex_factors,
            )

        # ZNE (optionally combined with TREX readout mitigation at every scale factor)
        scale_energies: list[float] = []
        for idx, scale in enumerate(self._scale_factors):
            folded = fold_circuit_unitary(unitary, scale)
            if use_trex:
                folded_unitary = strip_measurements(folded)
                counts = run_twirled_circuit_counts(
                    folded_unitary,
                    self._sim,
                    shots=shots,
                    num_twirls=self._num_twirls,
                    seed=self._seed + idx * 31,
                )
                e_s = _counts_to_ising_expectation(counts, hamiltonian, trex_factors)
            else:
                t_folded = transpile(folded, self._sim, optimization_level=0)
                counts = dict(
                    self._sim.run(t_folded, shots=shots, seed_simulator=self._seed + idx * 31)
                    .result()
                    .get_counts()
                )
                e_s = _counts_to_ising_expectation(counts, hamiltonian)
            scale_energies.append(e_s)

        extrapolated = extrapolate_zero_noise(
            self._scale_factors,
            scale_energies,
            method=self._extrapolation,
        )
        self._metrics.mitigation_runs.labels(technique=self._mode).inc()
        return MitigatedExpectationResult(
            mode=self._mode,
            unmitigated_energy=unmitigated,
            mitigated_energy=extrapolated,
            scale_factors=list(self._scale_factors),
            scale_energies=scale_energies,
            trex_calibration_factors=trex_factors,
        )
