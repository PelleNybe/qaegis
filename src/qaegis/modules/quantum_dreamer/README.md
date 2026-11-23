# Module 4: Quantum Dreaming (`qaegis.modules.quantum_dreamer`)

**Quantum Dreaming** eliminates the NISQ latency barrier for autonomous edge systems by separating real-time decision loops from multi-second quantum optimization across an explicit **Day/Night Lifecycle**.

## How Day/Night Optimization Works

1. **Day Mode (`problem_queue.py`):** When the autonomous agent encounters an NP-hard routing, scheduling, or resource-allocation bottleneck, it logs the compiled QUBO into SQLite WAL (`dream_problems`) with a priority score and continues operating using its fast local policy—zero blocking QPU calls.
2. **Night Mode (`solvers.py`):** During scheduled charging/idle windows (or explicit CLI trigger), `QuantumDreamerService` drains the priority queue and executes a genuine **QAOA** variational optimizer in Qiskit across pluggable backends:
   - `AerStatevectorBackend` (exact local statevector simulator)
   - `AerNoisyBackend` (realistic depolarizing + readout noise model)
   - `IbmRuntimeBackend` (real IBM Quantum `SamplerV2` via `IBM_QUANTUM_TOKEN`, transparently falling back to `AerNoisyBackend` if unconfigured)
3. **Rollback-Guarded Policy Update (`policy_updater.py`):** Optimal QAOA bitstrings are blended into candidate AI policy weights and benchmarked on held-out validation checks. Updates are activated **only if** they outperform the active baseline; regressions trigger an automatic rollback and tamper-evident audit entry.

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
qaegis dream --nodes 4 --backend aer_noisy
```
