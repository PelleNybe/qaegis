"""Module 4: Quantum Dreaming Asynchronous Day/Night QAOA Optimizer & Federated Fleet."""

from __future__ import annotations

from qaegis.modules.quantum_dreamer.backends import (
    AwsBraketBackend,
    IonQBackend,
    build_braket_openqasm3,
    qiskit_to_ionq_circuit,
)
from qaegis.modules.quantum_dreamer.federated import (
    FederatedJobSubmission,
    FederatedScheduler,
    FederatedScheduleReport,
    SignedPolicyBroadcast,
    apply_federated_broadcast,
    canonicalize_qubo,
    remap_bitstring,
    verify_federated_broadcast,
)
from qaegis.modules.quantum_dreamer.mitigation import (
    ErrorMitigationPipeline,
    ExtrapolationMethod,
    MitigatedExpectationResult,
    MitigationMode,
    calibrate_trex_factors,
    extrapolate_zero_noise,
    fold_circuit_unitary,
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
    "ErrorMitigationPipeline",
    "ExtrapolationMethod",
    "FederatedJobSubmission",
    "FederatedScheduleReport",
    "FederatedScheduler",
    "IbmRuntimeBackend",
    "IonQBackend",
    "MitigatedExpectationResult",
    "MitigationMode",
    "NightCycleReport",
    "PolicyScorer",
    "PolicyUpdateResult",
    "PolicyUpdater",
    "QaoaSolution",
    "QaoaSolver",
    "QuantumBackend",
    "QuantumBackendRegistry",
    "QuantumDreamerService",
    "SignedPolicyBroadcast",
    "apply_federated_broadcast",
    "bitstring_to_policy_weights",
    "build_braket_openqasm3",
    "build_qaoa_circuit",
    "calibrate_trex_factors",
    "canonicalize_qubo",
    "create_quantum_backend",
    "extrapolate_zero_noise",
    "fold_circuit_unitary",
    "get_backend_registry",
    "qiskit_to_ionq_circuit",
    "remap_bitstring",
    "verify_federated_broadcast",
]
