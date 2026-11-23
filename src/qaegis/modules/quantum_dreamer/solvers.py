"""Real Qiskit QAOA solvers with pluggable Aer Statevector, Aer Noisy, and IBM Runtime backends."""

from __future__ import annotations

import os
import time
from abc import ABC, abstractmethod

import numpy as np
from pydantic import BaseModel, Field
from qiskit import QuantumCircuit, qasm3, transpile
from qiskit_aer import AerSimulator
from qiskit_aer.noise import NoiseModel, ReadoutError, depolarizing_error
from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2
from scipy.optimize import minimize

from qaegis.core.config import QuantumDreamerConfig
from qaegis.core.telemetry import get_logger
from qaegis.modules.qubit_compiler.qubo_mapper import (
    IsingHamiltonian,
    QuboProblem,
    evaluate_qubo,
    qubo_to_ising,
)

logger = get_logger(__name__)


class QaoaSolution(BaseModel):
    """Result of executing QAOA on a local simulator or remote IBM Quantum QPU."""

    problem_id: str
    backend_name: str
    optimal_bitstring: str
    optimal_energy: float
    exact_ground_energy: float | None = None
    expected_energy: float
    approximation_ratio: float | None = None
    optimal_gammas: list[float]
    optimal_betas: list[float]
    shots: int
    optimizer_iters: int
    top_probabilities: dict[str, float] = Field(default_factory=dict)
    openqasm3: str
    solve_time_s: float


def build_qaoa_circuit(
    hamiltonian: IsingHamiltonian,
    gammas: list[float],
    betas: list[float],
    measure: bool = True,
) -> QuantumCircuit:
    """Construct an exact QAOA QuantumCircuit for an Ising Hamiltonian."""
    if len(gammas) != len(betas) or not gammas:
        raise ValueError("gammas and betas must be non-empty lists of equal length")
    n = hamiltonian.num_qubits
    qc = QuantumCircuit(n, n if measure else 0)

    # Initial uniform superposition |+>^n
    for q in range(n):
        qc.h(q)

    for gamma, beta in zip(gammas, betas, strict=True):
        # Cost unitary exp(-i * gamma * H_C)
        for q, h_i in enumerate(hamiltonian.linear_h):
            if abs(h_i) > 1e-12:
                qc.rz(2.0 * gamma * h_i, q)
        for c in hamiltonian.couplings:
            if abs(c.weight) > 1e-12:
                qc.rzz(2.0 * gamma * c.weight, c.i, c.j)
        # Mixer unitary exp(-i * beta * sum X_i)
        for q in range(n):
            qc.rx(2.0 * beta, q)

    if measure:
        qc.measure(range(n), range(n))
    return qc


def _exact_qubo_ground_energy(problem: QuboProblem) -> tuple[float, float] | None:
    """Compute exact (min_energy, max_energy) by brute force for small verification instances."""
    n = problem.num_variables
    if n > 12:
        return None
    min_e = float("inf")
    max_e = float("-inf")
    for idx in range(1 << n):
        bs = format(idx, f"0{n}b")
        e = evaluate_qubo(problem, bs)
        if e < min_e:
            min_e = e
        if e > max_e:
            max_e = e
    return (min_e, max_e)


class QuantumBackend(ABC):
    """Pluggable execution backend evaluating QAOA probability distributions."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable identifier of the execution backend."""

    @abstractmethod
    def sample_distribution(
        self,
        hamiltonian: IsingHamiltonian,
        gammas: list[float],
        betas: list[float],
        shots: int,
    ) -> dict[str, float]:
        """Execute the QAOA circuit and return {bitstring (x_0..x_{n-1}): probability}."""


class AerStatevectorBackend(QuantumBackend):
    """Exact noiseless Qiskit Aer statevector backend."""

    def __init__(self) -> None:
        self._sim = AerSimulator(method="statevector")

    @property
    def name(self) -> str:
        return "aer_statevector"

    def sample_distribution(
        self,
        hamiltonian: IsingHamiltonian,
        gammas: list[float],
        betas: list[float],
        shots: int,
    ) -> dict[str, float]:
        del shots  # Statevector yields exact analytical probabilities
        n = hamiltonian.num_qubits
        qc = build_qaoa_circuit(hamiltonian, gammas, betas, measure=False)
        qc.save_statevector()
        result = self._sim.run(transpile(qc, self._sim)).result()
        sv = np.asarray(result.get_statevector(qc), dtype=np.complex128)
        probs = np.abs(sv) ** 2

        dist: dict[str, float] = {}
        for idx, prob in enumerate(probs):
            p_val = float(prob)
            if p_val > 1e-9:
                # Convert Qiskit little-endian state index to x_0..x_{n-1} order
                bitstring = "".join(str((idx >> q) & 1) for q in range(n))
                dist[bitstring] = p_val
        return dist


class AerNoisyBackend(QuantumBackend):
    """Realistic noisy Qiskit Aer simulator with depolarizing gate errors and readout noise."""

    def __init__(
        self,
        single_qubit_error: float = 0.002,
        two_qubit_error: float = 0.015,
        readout_error: float = 0.02,
        seed: int = 42,
    ) -> None:
        noise_model = NoiseModel()
        err_1q = depolarizing_error(single_qubit_error, 1)
        err_2q = depolarizing_error(two_qubit_error, 2)
        ro_err = ReadoutError(
            [[1.0 - readout_error, readout_error], [readout_error, 1.0 - readout_error]]
        )
        noise_model.add_all_qubit_quantum_error(err_1q, ["h", "rx", "ry", "rz"])
        noise_model.add_all_qubit_quantum_error(err_2q, ["cx", "rzz"])
        noise_model.add_all_qubit_readout_error(ro_err)

        self._sim = AerSimulator(noise_model=noise_model)
        self._seed = seed

    @property
    def name(self) -> str:
        return "aer_noisy"

    def sample_distribution(
        self,
        hamiltonian: IsingHamiltonian,
        gammas: list[float],
        betas: list[float],
        shots: int,
    ) -> dict[str, float]:
        qc = build_qaoa_circuit(hamiltonian, gammas, betas, measure=True)
        tqc = transpile(qc, self._sim, optimization_level=1)
        counts: dict[str, int] = dict(
            self._sim.run(tqc, shots=shots, seed_simulator=self._seed).result().get_counts()
        )
        total = float(sum(counts.values()))
        # Reverse Qiskit little-endian count key to x_0..x_{n-1} order
        return {key[::-1]: float(cnt) / total for key, cnt in counts.items()}


class IbmRuntimeBackend(QuantumBackend):
    """Production IBM Quantum Runtime (SamplerV2) backend with honest local noisy fallback."""

    def __init__(
        self,
        backend_name: str = "ibm_brisbane",
        channel: str = "ibm_quantum",
        token: str | None = None,
    ) -> None:
        self._requested_backend = backend_name
        self._channel = channel
        self._token = (
            token or os.environ.get("IBM_QUANTUM_TOKEN") or os.environ.get("QISKIT_IBM_TOKEN")
        )
        self._fallback = AerNoisyBackend()
        self._service: QiskitRuntimeService | None = None
        self._remote_backend_obj: object | None = None

        if self._token:
            self._service = QiskitRuntimeService(channel=self._channel, token=self._token)
            self._remote_backend_obj = self._service.backend(self._requested_backend)
        else:
            logger.info(
                "ibm_runtime_token_not_configured_using_local_noisy_aer",
                requested_backend=self._requested_backend,
            )

    @property
    def name(self) -> str:
        if self._remote_backend_obj is not None:
            return f"ibm_runtime:{self._requested_backend}"
        return "aer_noisy_fallback"

    def sample_distribution(
        self,
        hamiltonian: IsingHamiltonian,
        gammas: list[float],
        betas: list[float],
        shots: int,
    ) -> dict[str, float]:
        if self._remote_backend_obj is None:
            return self._fallback.sample_distribution(hamiltonian, gammas, betas, shots)

        qc = build_qaoa_circuit(hamiltonian, gammas, betas, measure=True)
        tqc = transpile(qc, backend=self._remote_backend_obj, optimization_level=2)
        sampler = SamplerV2(mode=self._remote_backend_obj)
        job = sampler.run([tqc], shots=shots)
        pub_result = job.result()[0]
        counts: dict[str, int] = dict(pub_result.data.c.get_counts())
        total = float(sum(counts.values()))
        return {key[::-1]: float(cnt) / total for key, cnt in counts.items()}


def create_quantum_backend(config: QuantumDreamerConfig) -> QuantumBackend:
    """Instantiate the configured real quantum execution backend."""
    if config.backend_type == "aer_statevector":
        return AerStatevectorBackend()
    if config.backend_type == "aer_noisy":
        return AerNoisyBackend()
    return IbmRuntimeBackend(
        backend_name=config.ibm_backend_name,
        channel=config.ibm_channel,
    )


class QaoaSolver:
    """Variational QAOA optimizer minimizing QUBO/Ising Hamiltonians via COBYLA."""

    def __init__(
        self,
        config: QuantumDreamerConfig | None = None,
        backend: QuantumBackend | None = None,
    ) -> None:
        self._config = config or QuantumDreamerConfig()
        self._backend = backend or create_quantum_backend(self._config)

    @property
    def backend(self) -> QuantumBackend:
        return self._backend

    def solve(self, problem: QuboProblem) -> QaoaSolution:
        """Optimize QAOA angles (gamma, beta) for `problem` and return the best bitstring."""
        t0 = time.perf_counter()
        hamiltonian = qubo_to_ising(problem)
        p = self._config.qaoa_reps
        shots = self._config.qaoa_shots

        # Precompute energy cache for fast classical expectation evaluation
        energy_cache: dict[str, float] = {}

        def _energy(bs: str) -> float:
            val = energy_cache.get(bs)
            if val is None:
                val = evaluate_qubo(problem, bs)
                energy_cache[bs] = val
            return val

        eval_count = 0

        def _objective(params: np.ndarray) -> float:
            nonlocal eval_count
            eval_count += 1
            gammas = [float(x) for x in params[:p]]
            betas = [float(x) for x in params[p:]]
            dist = self._backend.sample_distribution(hamiltonian, gammas, betas, shots)
            return float(sum(prob * _energy(bs) for bs, prob in dist.items()))

        # Physically motivated linear adiabatic ramp initialization
        init_gammas = np.linspace(0.25, 0.75, p, dtype=np.float64)
        init_betas = np.linspace(0.60, 0.20, p, dtype=np.float64)
        x0 = np.concatenate([init_gammas, init_betas])

        opt_result = minimize(
            _objective,
            x0,
            method="COBYLA",
            options={"maxiter": self._config.max_optimizer_iters},
        )
        best_params = np.asarray(opt_result.x, dtype=np.float64)
        opt_gammas = [float(x) for x in best_params[:p]]
        opt_betas = [float(x) for x in best_params[p:]]

        final_dist = self._backend.sample_distribution(hamiltonian, opt_gammas, opt_betas, shots)
        expected_energy = float(sum(prob * _energy(bs) for bs, prob in final_dist.items()))

        # Select lowest-energy bitstring observed with meaningful probability
        sorted_by_energy = sorted(final_dist.items(), key=lambda kv: (_energy(kv[0]), -kv[1]))
        best_bitstring = sorted_by_energy[0][0]
        best_energy = _energy(best_bitstring)

        exact_bounds = _exact_qubo_ground_energy(problem)
        exact_min: float | None = None
        approx_ratio: float | None = None
        if exact_bounds is not None:
            exact_min, exact_max = exact_bounds
            span = exact_max - exact_min
            if span > 1e-9:
                # 1.0 = exact ground state, 0.0 = worst possible state
                approx_ratio = float(np.clip((exact_max - best_energy) / span, 0.0, 1.0))
            else:
                approx_ratio = 1.0

        top_probs = dict(sorted(final_dist.items(), key=lambda kv: -kv[1])[:8])
        final_qc = build_qaoa_circuit(hamiltonian, opt_gammas, opt_betas, measure=True)
        qasm3_str = str(qasm3.dumps(final_qc))

        return QaoaSolution(
            problem_id=problem.problem_id,
            backend_name=self._backend.name,
            optimal_bitstring=best_bitstring,
            optimal_energy=best_energy,
            exact_ground_energy=exact_min,
            expected_energy=expected_energy,
            approximation_ratio=approx_ratio,
            optimal_gammas=opt_gammas,
            optimal_betas=opt_betas,
            shots=shots,
            optimizer_iters=eval_count,
            top_probabilities=top_probs,
            openqasm3=qasm3_str,
            solve_time_s=time.perf_counter() - t0,
        )
