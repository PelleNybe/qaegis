# Module 5: Quantum Entropy Evolution Engine (`qaegis.modules.quantum_entropy`)

The **Quantum Entropy Evolution Engine** harvests genuine quantum measurement probability distributions from entangled circuits, XOR-mixes them with NIST-validated QRNG pools, and channels non-deterministic exploration into autonomous planning and local LLM agents.

## Components

- **Entangled Distribution Harvester (`harvester.py`):** Executes multi-qubit entangled Qiskit circuits (`H` -> `RY` -> `CNOT` chain -> `RY` -> measurement) on `AerSimulator` (with configurable depolarizing noise) and XOR-mixes outcomes with `MultiSourceQrng` to construct a `QuantumEntropyPool`.
- **Quantum Planners & Samplers (`sampler.py`):**
  - `QuantumMCTS`: Monte Carlo Tree Search using verified quantum entropy for rollouts and UCT tie-break exploration jitter.
  - `QuantumEvolutionaryMutator`: Continuous genome optimization via Box-Muller quantum Gaussian mutations.
  - `QuantumLogitSampler`: Temperature + top-k + top-p nucleus token sampler with quantum logit perturbation.
- **Local LLM Bridge (`ollama_bridge.py`):** Async `httpx` adapter for **Ollama** (`/api/generate`, `/api/tags`) and **llama.cpp / OpenAI-compatible** (`/v1/chat/completions`) servers, injecting quantum-derived 31-bit seeds and perturbed temperature/top-p schedules per reasoning branch.

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
    healthy, models = await bridge.check_health()
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
