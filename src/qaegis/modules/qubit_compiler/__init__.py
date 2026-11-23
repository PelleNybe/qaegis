"""Module 3: AI-to-Qubit Compiler (PyTorch/ONNX Encoder, Qiskit/PennyLane, QUBO/Ising)."""

from __future__ import annotations

from qaegis.modules.qubit_compiler.autoencoder import (
    AngleEncoderPipeline,
    QuantumAnglePayload,
    SensorToAngleAutoencoder,
)
from qaegis.modules.qubit_compiler.circuit_builder import (
    BackendNoiseProfile,
    CompiledCircuitArtifact,
    NoiseAwareCircuitBuilder,
    PennyLaneExecutionResult,
)
from qaegis.modules.qubit_compiler.qubo_mapper import (
    IsingCoupling,
    IsingHamiltonian,
    QuboProblem,
    build_maxcut_qubo,
    build_resource_allocation_qubo,
    build_task_scheduling_qubo,
    evaluate_ising,
    evaluate_qubo,
    qubo_to_ising,
)
from qaegis.modules.qubit_compiler.service import QubitCompilerService

__all__ = [
    "AngleEncoderPipeline",
    "BackendNoiseProfile",
    "CompiledCircuitArtifact",
    "IsingCoupling",
    "IsingHamiltonian",
    "NoiseAwareCircuitBuilder",
    "PennyLaneExecutionResult",
    "QuantumAnglePayload",
    "QubitCompilerService",
    "QuboProblem",
    "SensorToAngleAutoencoder",
    "build_maxcut_qubo",
    "build_resource_allocation_qubo",
    "build_task_scheduling_qubo",
    "evaluate_ising",
    "evaluate_qubo",
    "qubo_to_ising",
]
