# Module 5: Quantum Entropy Evolution Engine (`qaegis.modules.quantum_entropy`)

The **Quantum Entropy Evolution Engine** harvests genuine quantum measurement probability distributions from entangled multi-qubit circuits, XOR-mixes them with NIST-validated QRNG streams, and channels thread-safe non-deterministic exploration into autonomous planners and local LLM agents.

## Components

- **Entangled Distribution Harvester & Thread-Safe Pool (`harvester.py`):** Executes entangled Qiskit circuits (`H` -> `RY` -> `CNOT` chain -> `RY` -> measurement) on `AerSimulator` (offloaded cleanly via `asyncio.to_thread`), XOR-mixes shot outcomes with `MultiSourceQrng`, and exposes a lock-protected, NumPy-vectorized `QuantumEntropyPool` (`next_bytes`, `next_uint32`, `next_float`, `next_gaussians`).
- **Quantum Planners & Samplers (`sampler.py`):**
  - `QuantumMCTS`: Monte Carlo Tree Search using verified quantum entropy for rollouts and UCT tie-break exploration jitter.
  - `QuantumEvolutionaryMutator`: Continuous genome optimization via vectorized Box-Muller quantum Gaussian mutations.
  - `QuantumLogitSampler`: Temperature + top-k + top-p nucleus token sampler with quantum logit perturbation.
- **Local LLM Bridge (`ollama_bridge.py`):** Async `httpx` adapter for **Ollama** (`/api/generate`, `/api/tags`) and **llama.cpp / OpenAI-compatible** (`/v1/chat/completions`) endpoints, injecting quantum-derived 31-bit seeds and perturbed temperature/top-p schedules per reasoning branch.

## Standalone Python Usage

```python
import asyncio
from qaegis.modules.quantum_entropy import (
    OllamaQuantumBridge,
    QuantumDistributionHarvester,
    QuantumLogitSampler,
)


async def main() -> None:
    harvester = QuantumDistributionHarvester()
    batch, pool = await harvester.harvest_batch(num_qubits=6, shots=512)
    print(f"Harvested {batch.pool_bytes} B (Shannon entropy={batch.shannon_entropy_bits:.3f} bits)")

    sampler = QuantumLogitSampler(pool)
    choice = sampler.sample_token([0.2, 1.5, 4.2, 0.8, -1.0], temperature=0.7, top_k=3)
    print("Sampled token index:", choice.token_index)

    bridge = OllamaQuantumBridge()
    healthy, _models = await bridge.check_health()
    if healthy:
        gen = await bridge.generate_with_quantum_seed(
            "Suggest two evasive drone maneuvers.", pool=pool
        )
        print(gen.response_text)


asyncio.run(main())
```

## CLI Usage

```bash
qaegis entropy --qubits 6 --shots 512
```
