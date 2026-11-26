# Module 3: AI-to-Qubit Compiler (`qaegis.modules.qubit_compiler`)

The **AI-to-Qubit Compiler** bridges high-dimensional classical edge sensor streams with near-term NISQ quantum circuits and combinatorial QUBO/Ising Hamiltonians.

## Components

- **Self-Contained Bounded Angle Autoencoder (`autoencoder.py`):** A CPU-optimized PyTorch autoencoder whose bottleneck applies $\tanh(z)\cdot\pi$, compressing arbitrary numeric feature vectors directly into valid $(R_x, R_y, R_z)$ rotation angles strictly inside $[-\pi, \pi]$. Exported ONNX graphs fuse training $(\mu, \sigma)$ input standardization directly into the ONNX computation graph, delivering **`0.073 ms`** standalone `onnxruntime` CPU inference (**6.1x faster** than PyTorch).
- **Noise-Aware Circuit Builder (`circuit_builder.py`):** Compiles bounded angle payloads into hardware-adapted quantum circuits for both **Qiskit** (with topology-aware entanglement, transpilation, analytical fidelity estimation, and syntax-verified **OpenQASM 3.0** output) and **PennyLane** (`default.qubit` and noisy `default.mixed` with depolarizing channels).
- **QUBO & Ising Mapper (`qubo_mapper.py`):** Translates concrete edge optimization tasks—weighted Max-Cut routing, conflict-constrained task scheduling, and utility-vs-cost resource allocation—into QUBO matrices and exact Ising spin Hamiltonians ($x_i = (1 - z_i)/2$).

## Standalone Python Usage

```python
import numpy as np
from pathlib import Path
from qaegis.modules.qubit_compiler import (
    AngleEncoderPipeline,
    BackendNoiseProfile,
    NoiseAwareCircuitBuilder,
)

rng = np.random.default_rng(42)
samples = rng.normal(size=(128, 16)).astype(np.float32)

pipe = AngleEncoderPipeline(input_dim=16, num_qubits=4)
pipe.train(samples, epochs=40)
pipe.export_onnx(Path("./angle_encoder.onnx"))
pipe.load_onnx(Path("./angle_encoder.onnx"))

angles = pipe.encode_to_angles(samples[0])
builder = NoiseAwareCircuitBuilder(BackendNoiseProfile(topology="linear", optimization_level=2))
qc, artifact = builder.build_qiskit_circuit(angles)
pl_res = builder.run_pennylane_circuit(angles, noise_level=0.01)

print("Depth:", artifact.depth, "Est. Fidelity:", round(artifact.estimated_fidelity, 4))
print("OpenQASM 3.0 preview:\n", artifact.openqasm3[:200])
```

## CLI Usage

```bash
qaegis compile-circuit --qubits 4 --vector "0.4,-0.1,0.9,0.2,0.5,-0.3,0.8,0.1" --output-qasm out.qasm
```
