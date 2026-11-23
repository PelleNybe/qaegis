"""Module 4: Quantum Dreaming Asynchronous Day/Night QAOA Optimizer."""

from __future__ import annotations

from qaegis.modules.quantum_dreamer.backends import (
    AwsBraketBackend,
    IonQBackend,
    build_braket_openqasm3,
    qiskit_to_ionq_circuit,
)
from qaegis.modules.quantum_dreamer.policy_updater import (
    PolicyScorer,
    PolicyUpdater,
    PolicyUpdateResult,
    bitstring_to_policy_weights,
)
from qaegis.modules.quantum_dreamer.problem_queue import DreamProblemQueue
from qaegis.modules.quantum_dreamer.service import NightCycleReport, QuantumDreamerService
from qaegis.modules.quantum_dreamer.solvers import (
    AerNoisyBackend,
    AerStatevectorBackend,
    IbmRuntimeBackend,
    QaoaSolution,
    QaoaSolver,
    QuantumBackend,
    QuantumBackendRegistry,
    build_qaoa_circuit,
    create_quantum_backend,
    get_backend_registry,
)

__all__ = [
    "AerNoisyBackend",
    "AerStatevectorBackend",
    "AwsBraketBackend",
    "DreamProblemQueue",
    "IbmRuntimeBackend",
    "IonQBackend",
    "NightCycleReport",
    "PolicyScorer",
    "PolicyUpdateResult",
    "PolicyUpdater",
    "QaoaSolution",
    "QaoaSolver",
    "QuantumBackend",
    "QuantumBackendRegistry",
    "QuantumDreamerService",
    "bitstring_to_policy_weights",
    "build_braket_openqasm3",
    "build_qaoa_circuit",
    "create_quantum_backend",
    "get_backend_registry",
    "qiskit_to_ionq_circuit",
]
