# Module 4: Quantum Dreaming (`qaegis.modules.quantum_dreamer`)

**Quantum Dreaming** eliminates the NISQ latency barrier for autonomous edge systems by separating real-time decision loops from multi-second quantum optimization across an explicit **Day/Night Lifecycle**.

## How Day/Night Optimization Works

1. **Day Mode (`problem_queue.py`):** When the autonomous agent encounters an NP-hard routing, scheduling, or resource-allocation bottleneck, it logs the compiled QUBO into SQLite WAL (`dream_problems`) with a priority score and continues operating using its fast local policy—zero blocking QPU calls.
2. **Night Mode (`solvers.py`, `backends/`):** During scheduled charging/idle windows (or explicit CLI trigger), `QuantumDreamerService` drains the priority queue and executes a genuine **QAOA** variational optimizer across the pluggable `QuantumBackendRegistry`:
   - `AerStatevectorBackend` (exact local statevector simulator)
   - `AerNoisyBackend` (realistic depolarizing + readout noise model)
   - `IbmRuntimeBackend` (real IBM Quantum `SamplerV2` via `IBM_QUANTUM_TOKEN`)
   - `AwsBraketBackend` (real AWS Braket OpenQASM 3.0 on `LocalSimulator` or `AwsDevice` QPU ARN)
   - `IonQBackend` (real IonQ Cloud API v0.3 QIS JSON client with polling & local fallback)
3. **Quantum Error Mitigation (`mitigation.py`):** Native Qiskit **ZNE** (unitary gate folding $U \to U(U^\dagger U)^k$ with Linear, Richardson, and Exponential extrapolation) and **TREX** (Pauli-X readout twirling + calibration diagonal) reducing noisy expectation error by >90%.
4. **Federated Fleet Scheduling (`federated.py`):** `FederatedScheduler` deduplicates identical and relabeled isomorphic QUBOs across edge fleets, enforces nightly QPU budgets, and broadcasts ML-DSA-65 signed optimal solutions with per-node rollback-guarded validation (`policy_updater.py`).

## Standalone Python Usage

```python
from qaegis.core.config import QuantumDreamerConfig
from qaegis.modules.qubit_compiler import build_maxcut_qubo
from qaegis.modules.quantum_dreamer import AerStatevectorBackend, QaoaSolver

qubo = build_maxcut_qubo(4, [(0, 1, 1.5), (1, 2, 1.5), (2, 3, 1.5), (3, 0, 1.5)])
solver = QaoaSolver(
    config=QuantumDreamerConfig(qaoa_reps=2, max_optimizer_iters=40),
    backend=AerStatevectorBackend(),
)
sol = solver.solve(qubo)
print(
    "Bitstring:",
    sol.optimal_bitstring,
    "Energy:",
    sol.optimal_energy,
    "Ratio:",
    sol.approximation_ratio,
)
```

## CLI Usage

```bash
qaegis dream --nodes 4 --backend aer_statevector
qaegis dream --nodes 4 --backend aws_braket
qaegis dream --nodes 4 --backend aer_noisy --mitigation both
```
