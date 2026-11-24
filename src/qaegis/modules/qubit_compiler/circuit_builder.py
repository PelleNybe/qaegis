"""Noise-aware Qiskit (OpenQASM 3.0) and PennyLane parameterized circuit builders."""

from __future__ import annotations

import math
from typing import Literal

import numpy as np
import pennylane as qml
from pydantic import BaseModel, Field
from qiskit import QuantumCircuit, qasm3, transpile

from qaegis.modules.qubit_compiler.autoencoder import QuantumAnglePayload


class BackendNoiseProfile(BaseModel):
    """Hardware error rates and topology profile guiding noise-aware transpilation."""

    name: str = "edge_nisq_profile"
    single_qubit_error: float = Field(default=0.001, ge=0.0, le=0.2)
    two_qubit_error: float = Field(default=0.015, ge=0.0, le=0.5)
    readout_error: float = Field(default=0.02, ge=0.0, le=0.5)
    topology: Literal["linear", "ring", "all_to_all"] = "linear"
    optimization_level: int = Field(default=2, ge=0, le=3)


class CompiledCircuitArtifact(BaseModel):
    """Validated quantum circuit artifact with OpenQASM 3.0 representation and fidelity estimate."""

    num_qubits: int
    depth: int
    gate_counts: dict[str, int]
    two_qubit_gate_count: int
    estimated_fidelity: float = Field(ge=0.0, le=1.0)
    optimization_level: int
    entanglement_pattern: str
    openqasm3: str
    framework: str


class PennyLaneExecutionResult(BaseModel):
    """Output of executing the compiled rotation-angle ansatz on PennyLane."""

    num_qubits: int
    probabilities: list[float]
    pauli_z_expectations: list[float]
    noise_level: float
    device_name: str


class NoiseAwareCircuitBuilder:
    """Builds noise-adapted Qiskit (OpenQASM 3.0) and PennyLane quantum feature circuits."""

    def __init__(self, noise_profile: BackendNoiseProfile | None = None) -> None:
        self._profile = noise_profile or BackendNoiseProfile()

    def build_qiskit_circuit(
        self,
        payload: QuantumAnglePayload,
        entangling_layers: int = 1,
        measure: bool = True,
    ) -> tuple[QuantumCircuit, CompiledCircuitArtifact]:
        """Construct and transpile a noise-aware Qiskit circuit and export OpenQASM 3.0."""
        if entangling_layers < 1:
            raise ValueError("entangling_layers must be >= 1")
        n = payload.num_qubits
        if len(payload.angles_rad) != n:
            raise ValueError(f"Expected {n} qubit angle triplets, got {len(payload.angles_rad)}")
        qc = QuantumCircuit(n, n if measure else 0)

        # Select entanglement strategy based on two-qubit gate error to minimize SWAP overhead
        if self._profile.two_qubit_error >= 0.02 or self._profile.topology == "linear":
            entanglement = "linear"
        elif self._profile.topology == "ring":
            entanglement = "ring"
        else:
            entanglement = "brickwork"

        for layer in range(entangling_layers):
            scale = 1.0 / (layer + 1)
            for q in range(n):
                rx, ry, rz = payload.angles_rad[q]
                qc.rx(rx * scale, q)
                qc.ry(ry * scale, q)
                qc.rz(rz * scale, q)

            if n > 1:
                if entanglement == "linear":
                    for q in range(n - 1):
                        qc.cx(q, q + 1)
                elif entanglement == "ring":
                    for q in range(n):
                        qc.cx(q, (q + 1) % n)
                else:
                    for q in range(0, n - 1, 2):
                        qc.cx(q, q + 1)
                    for q in range(1, n - 1, 2):
                        qc.cx(q, q + 1)

        if measure:
            qc.measure(range(n), range(n))

        # Transpile onto standard basis gates with hardware-adapted optimization level
        basis = ["rx", "ry", "rz", "cx", "measure"] if measure else ["rx", "ry", "rz", "cx"]
        transpiled = transpile(
            qc,
            basis_gates=basis,
            optimization_level=self._profile.optimization_level,
        )

        # Export valid OpenQASM 3.0 and validate syntactic round-trip
        qasm3_str = str(qasm3.dumps(transpiled))
        _ = qasm3.loads(qasm3_str)

        raw_counts = transpiled.count_ops()
        gate_counts = {str(k): int(v) for k, v in raw_counts.items()}
        two_q_gates = gate_counts.get("cx", 0)
        one_q_gates = sum(gate_counts.get(g, 0) for g in ("rx", "ry", "rz", "sx", "x", "h"))
        meas_gates = gate_counts.get("measure", 0)

        # Analytical multiplicative fidelity estimate under independent depolarizing/readout errors
        est_fidelity = (
            ((1.0 - self._profile.single_qubit_error) ** one_q_gates)
            * ((1.0 - self._profile.two_qubit_error) ** two_q_gates)
            * ((1.0 - self._profile.readout_error) ** meas_gates)
        )
        est_fidelity = max(0.0, min(1.0, float(est_fidelity)))

        artifact = CompiledCircuitArtifact(
            num_qubits=n,
            depth=int(transpiled.depth()),
            gate_counts=gate_counts,
            two_qubit_gate_count=two_q_gates,
            estimated_fidelity=est_fidelity,
            optimization_level=self._profile.optimization_level,
            entanglement_pattern=entanglement,
            openqasm3=qasm3_str,
            framework="qiskit",
        )
        return transpiled, artifact

    def run_pennylane_circuit(
        self,
        payload: QuantumAnglePayload,
        noise_level: float = 0.0,
    ) -> PennyLaneExecutionResult:
        """Execute the compiled rotation-angle ansatz natively on PennyLane."""
        n = payload.num_qubits
        angles_arr = np.asarray(payload.angles_rad, dtype=np.float64)
        use_mixed = noise_level > 0.0
        device_name = "default.mixed" if use_mixed else "default.qubit"
        dev = qml.device(device_name, wires=n)

        def _apply_ansatz(theta: np.ndarray) -> None:
            for q in range(n):
                qml.RX(float(theta[q, 0]), wires=q)
                qml.RY(float(theta[q, 1]), wires=q)
                qml.RZ(float(theta[q, 2]), wires=q)
                if use_mixed:
                    qml.DepolarizingChannel(min(noise_level, 0.75), wires=q)
            for q in range(n - 1):
                qml.CNOT(wires=[q, q + 1])
                if use_mixed:
                    qml.DepolarizingChannel(min(noise_level * 1.5, 0.75), wires=q + 1)

        def _probs_fn(theta: np.ndarray) -> object:
            _apply_ansatz(theta)
            return qml.probs(wires=list(range(n)))

        def _expval_fn(theta: np.ndarray) -> list[object]:
            _apply_ansatz(theta)
            return [qml.expval(qml.PauliZ(q)) for q in range(n)]

        probs_qnode = qml.QNode(_probs_fn, dev)
        expval_qnode = qml.QNode(_expval_fn, dev)

        probs_raw = np.asarray(probs_qnode(angles_arr), dtype=np.float64)
        expvals_raw = [float(v) for v in np.atleast_1d(expval_qnode(angles_arr))]

        # Validate probability normalization
        if not math.isclose(float(np.sum(probs_raw)), 1.0, abs_tol=1e-5):
            probs_raw = probs_raw / float(np.sum(probs_raw))

        return PennyLaneExecutionResult(
            num_qubits=n,
            probabilities=[float(p) for p in probs_raw],
            pauli_z_expectations=expvals_raw,
            noise_level=noise_level,
            device_name=device_name,
        )
