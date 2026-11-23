# Q-Aegis

**Quantum-Secured Autonomous Edge-AI Platform (v0.4.0)**

[![CI](https://img.shields.io/github/actions/workflow/status/PelleNybe/qaegis/ci.yml?label=CI&logo=github)](https://github.com/PelleNybe/qaegis/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/Docs-GitHub_Pages-0EA5E9?logo=materialformkdocs&logoColor=white)](https://pellenybe.github.io/qaegis/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![NIST PQC](https://img.shields.io/badge/NIST_PQC-FIPS_203_%7C_204_%7C_205-0F766E)](docs/cryptography-threat-model.md)
[![Hardware Security](https://img.shields.io/badge/HSM_%7C_TPM_2.0-PKCS%2311_%7C_CurveZMQ-15803D)](docs/manuals/operators-manual.md)
[![Quantum](https://img.shields.io/badge/Quantum-IBM_%7C_Braket_%7C_IonQ_%7C_ZNE%2FTREX-6929C4)](docs/quantum-backends.md)
[![Typing: mypy --strict](https://img.shields.io/badge/Typing-mypy_--strict-2A6DB2)](pyproject.toml)

---

## Try the 10-Second Live Demo (`qaegis demo`)

Experience all five Q-Aegis subsystems executing **100% real cryptography, ONNX Runtime, QAOA, and ZNE+TREX error mitigation** locally with zero cloud API keys:

```bash
pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
pip install --no-cache-dir -e .
qaegis demo
```

`qaegis demo` executes a live 5-stage pipeline in an isolated workspace:
1. Generates **NIST FIPS 203 / 204 / 205** device keys (`ML-KEM-768`, `ML-DSA-65`, `SLH-DSA-SHA2-128f`).
2. Harvests **QRNG** entropy, validates **NIST SP 800-22/90B**, signs a perception frame, and verifies its **Merkle inclusion proof**.
3. Escalates **Quantum Chameleon** live across `STANDARD` → `ELEVATED` (Hybrid ML-KEM-768) → `QUANTUM_CRITICAL` (Hybrid + ML-DSA-65).
4. Compresses a 16-D sensor vector via **ONNX Runtime** into bounded $[-\pi, \pi]$ angles and emits **OpenQASM 3.0**.
5. Solves a 4-qubit Max-Cut **QAOA** problem with **ZNE + TREX** error mitigation on noisy `AerSimulator` and prints real measured error reduction.

*(Use `qaegis demo --fast` for ~3-second CI smoke tests.)*

---

## Why Q-Aegis Exists

Autonomous edge fleets—drones, industrial robotics, tactical telemetry relays, and critical IoT infrastructure—face three converging engineering challenges that conventional security and AI stacks cannot solve in isolation:

1. **Harvest Now, Decrypt Later (HNDL):** Adversaries are recording encrypted telemetry and command links today to decrypt them once cryptographically relevant quantum computers arrive. Classical ECDH/RSA handshakes provide zero long-term confidentiality.
2. **The Edge-AI Trust Crisis:** Autonomous perception pipelines produce high-stakes inferences without cryptographic provenance, making single-node audit logs vulnerable to split-view tampering or key extraction.
3. **The NISQ Latency & Noise Barrier:** Real-time edge control loops demand millisecond determinism, whereas cloud Quantum Processing Units (QPUs) exhibit multi-second latency and hardware gate/readout noise.

**Q-Aegis v0.3** unifies **NIST-standardized Post-Quantum Cryptography** (`liboqs`), **hardware-backed PKCS#11 / TPM 2.0 key sealing**, **CurveZMQ authenticated fleet messaging**, **multi-node ML-DSA-65 Merkle root gossiping**, **real-time Edge-AI** (PyTorch/ONNX), and **federated Day/Night multi-cloud QAOA with ZNE & TREX error mitigation** (IBM Quantum, AWS Braket, IonQ, Qiskit Aer, PennyLane, OpenQASM 3.0).

---

## Five Unified Subsystems

| Subsystem | Package | Core Capability | Real Backing Stack |
| :--- | :--- | :--- | :--- |
| **1. Proof of Reality** | `qaegis.modules.reality_stamp` | Multi-source QRNG + NIST SP 800-22/90B validation + ML-DSA-65 / SLH-DSA signatures + Merkle audit log + **P2P Merkle Gossip & Equivocation Detection** | `liboqs`, Qiskit H-gate QRNG, `scipy`, SQLite WAL, CurveZMQ |
| **2. Quantum Chameleon** | `qaegis.modules.chameleon_fw` | Real-time AI anomaly & HNDL risk firewall switching dynamically from X25519 to Hybrid ML-KEM-768 + PQC Signatures | `scikit-learn` IsolationForest, ONNX Runtime, `liboqs`, AES-256-GCM |
| **3. AI-to-Qubit Compiler** | `qaegis.modules.qubit_compiler` | Neural autoencoder compressing sensor tensors into bounded $[-\pi, \pi]$ $(R_x, R_y, R_z)$ angles, OpenQASM 3.0, and QUBO/Ising matrices | PyTorch CPU, ONNX Runtime, Qiskit, PennyLane |
| **4. Quantum Dreaming** | `qaegis.modules.quantum_dreamer` | Asynchronous Day-Mode queuing + Night-Mode **Federated QAOA** across **IBM Runtime / AWS Braket / IonQ / Aer** + **ZNE & TREX Error Mitigation** + rollback-guarded policy updates | Qiskit QAOA, `amazon-braket-sdk`, IonQ v0.3, `qiskit-aer`, SciPy |
| **5. Quantum Entropy Engine** | `qaegis.modules.quantum_entropy` | Batched entangled-circuit probability harvester driving MCTS planning, evolutionary mutation, and local Ollama / `llama.cpp` agent sampling | Qiskit Aer, NIST QRNG XOR-mixer, `httpx` |

---

## Distributed Fleet & Day/Night Architecture

```mermaid
flowchart LR
    subgraph Edge["Day Mode: Real-Time Edge Node (Sub-10ms)"]
        HSM["PKCS#11 HSM / TPM 2.0<br/>Sealed PQC Identity"] -.-> M1
        S["Sensors / MQTT / ROS 2"] --> BUS(("CurveZMQ / Inproc EventBus<br/>ZAP Allowlist Auth"))
        BUS --> M1["1. Proof of Reality<br/>QRNG + ML-DSA-65 / SLH-DSA<br/>+ Merkle Tree"]
        M1 --> M2["2. Quantum Chameleon<br/>IsolationForest + ONNX HNDL<br/>X25519 <-> ML-KEM-768"]
        BUS --> M3["3. AI-to-Qubit Compiler<br/>ONNX Autoencoder -> [-pi, pi]<br/>OpenQASM 3.0 & QUBO"]
        M3 --> Q[("SQLite WAL<br/>Priority Problem Queue")]
        BUS --> M5["5. Quantum Entropy Engine<br/>Entangled Harvester -> MCTS / Ollama"]
    end

    subgraph Fleet["Fleet Witnessing & Federated Night Mode"]
        M1 <== "ML-DSA-65 Signed Roots<br/>Equivocation Detection" ==> GOSSIP["Multi-Node Merkle<br/>Gossip Mesh"]
        Q --> FED["Federated QAOA Scheduler<br/>Isomorphism Dedup + QPU Budget"]
        FED --> MIT["ZNE Folding + TREX Twirling<br/>Error Mitigation Pipeline"]
        MIT --> QPU["Multi-Cloud QPUs<br/>IBM Runtime | AWS Braket | IonQ | Aer"]
        QPU --> GUARD{"Per-Node Held-Out<br/>Policy Validation Gate"}
        GUARD -- "Improves Baseline" --> APPLY["Activate Policy Snapshot"]
        GUARD -- "Regresses" --> ROLLBACK["Automatic Rollback + Audit"]
    end

    APPLY -.-> Edge
```

---

## Feature Comparison Matrix

| Capability | Traditional TLS + Edge ML | Standalone PQC Library | Cloud Quantum SDK | **Q-Aegis v0.3** |
| :--- | :---: | :---: | :---: | :---: |
| NIST FIPS 203/204/205 (`ML-KEM`, `ML-DSA`, `SLH-DSA`) + CBOM | No | Partial | No | **Full Hybrid + CBOM** |
| Hardware Key Sealing (`PKCS#11` HSM/SoftHSM2 & Linux `TPM 2.0`) | Partial | No | No | **Yes (Envelope AEAD)** |
| AI-Driven Dynamic Crypto-Agility (`STANDARD` -> `CRITICAL`) | No | No | No | **Yes (IsolationForest + ONNX)** |
| Multi-Node Merkle Root Gossip & Equivocation Detection | No | No | No | **Yes (ML-DSA-65 + CurveZMQ)** |
| Federated Day/Night QAOA with Isomorphism Dedup & Budget | No | No | No | **Yes (Multi-Vendor Registry)** |
| Native Qiskit ZNE + TREX Quantum Error Mitigation | No | No | Vendor-locked | **Yes (-92.6% noisy error)** |
| Multi-Cloud QPU Backends (`IBM`, `AWS Braket`, `IonQ`, `Aer`) | No | No | Single-vendor | **Yes (Pluggable Registry)** |

---

## 5-Minute Quickstart

### 1. Install Q-Aegis (Lean CPU-Only PyTorch)

```bash
git clone https://github.com/PelleNybe/qaegis.git
cd qaegis
python3 -m venv .venv
source .venv/bin/activate
pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
pip install --no-cache-dir -e ".[dev,docs]"
```

### 2. Initialize & Hardware-Seal Post-Quantum Identity

```bash
qaegis version
qaegis init-identity
qaegis doctor
qaegis cbom --output cbom.json
# Optional: seal private keys into a PKCS#11 HSM / SoftHSM2 token or TPM 2.0
qaegis seal-identity --backend pkcs11 --token-label qaegis --pin 1234
```

### 3. Sign, Offline-Verify & Cross-Witness a Proof-of-Reality Stamp

```bash
qaegis stamp --sensor lidar-front-01 --label pedestrian_detected --confidence 0.98 --output stamp.json
qaegis verify-stamp stamp.json
qaegis gossip status
```

### 4. Compile Sensor Telemetry & Run Multi-Cloud Error-Mitigated QAOA

```bash
qaegis compile-circuit --qubits 4 --output-qasm sensor_circuit.qasm
qaegis dream --nodes 4 --backend aws_braket
qaegis dream --nodes 4 --backend aer_noisy --mitigation both
qaegis entropy --qubits 6 --shots 512
```

---

## Reproducible Hardware Benchmarks (v0.3.0)

Measured locally via `.venv/bin/python benchmarks/run_benchmarks.py` ([benchmarks/results.json](benchmarks/results.json)) on a **4-core Intel Core i5-6200U @ 2.30 GHz (15 GB RAM, Linux x86_64, Python 3.14.4, `liboqs` 0.16.0, SoftHSM2, Qiskit 2.6.2, PyTorch 2.15.0+cpu)**:

### Post-Quantum Primitives, Hardware Sealing & Fleet Transport

| Operation / Subsystem | Mean Latency | p95 Latency | Throughput / Size |
| :--- | ---: | ---: | :--- |
| **ML-KEM-768** Encap + Decap (FIPS 203) | `0.071 ms` | `0.102 ms` | `14,095.4 ops/s` (PK `1,184 B` / CT `1,088 B`) |
| **ML-DSA-65** Sign / Verify (FIPS 204) | `0.363 ms` / `0.160 ms` | `0.882` / `0.187 ms` | `2,757.8` / `6,250.8 ops/s` (Sig `3,309 B`) |
| **SLH-DSA-SHA2-128f** Sign / Verify (FIPS 205) | `40.790 ms` / `2.344 ms` | `59.964` / `2.533 ms` | `24.5` / `426.6 ops/s` (Sig `17,088 B`) |
| **Chameleon `STANDARD`** (1 KB, X25519 + AES-GCM) | `0.272 ms` | `0.323 ms` | `3,678.5 ops/s` (`1,960 B` JSON) |
| **Chameleon `ELEVATED`** (1 KB, Hybrid ML-KEM-768) | `0.433 ms` | `0.481 ms` | `2,306.9 ops/s` (`3,435 B` JSON) |
| **Chameleon `QUANTUM_CRITICAL`** (Hybrid + ML-DSA-65) | `1.096 ms` | `1.701 ms` | `912.1 ops/s` (`10,460 B` JSON) |
| **RealityStamp E2E** (QRNG + ML-DSA-65 + Merkle + WAL) | `4.671 ms` | `10.156 ms` | `214.1 stamps/s` |
| **PKCS#11 SoftHSM2 Seal / Unseal** (6 KB PQC bundle) | `5.245 ms` / `5.827 ms` | `7.118` / `8.799 ms` | `190.7` / `171.6 ops/s` |
| **CurveZMQ Authenticated Event Bus** (Curve25519 ZAP) | `0.450 ms/msg` | — | **`2,223.0 msgs/s`** |
| **3-Node ML-DSA-65 Merkle Gossip Mesh** | **`17.68 ms`** | — | Full 3-node convergence |

### Edge-AI Compilation, QAOA & Quantum Error Mitigation (ZNE + TREX)

| Quantum Workload | Measured Result | Quality / Error Reduction |
| :--- | :--- | :--- |
| **AI-to-Qubit Autoencoder** (PyTorch vs ONNX Runtime, 4q) | `0.374 ms` vs **`0.070 ms`** | **5.3x ONNX speedup** (`14,226.4 ops/s`) |
| **QAOA Weighted Max-Cut** (4q SV / 6q SV / 4q Noisy) | `4.71 s` / `5.31 s` / `1.32 s` | **Approximation Ratio `1.0000`** on all 3 |
| **Noisy Aer Expectation — Unmitigated** (exact `-0.4831`) | `-1.5879` | Abs error `1.1048` (baseline) |
| **Noisy Aer Expectation — ZNE Only** (linear fold `[1,3,5]`) | `-1.4114` | Abs error `0.9283` (`-16.0%`) |
| **Noisy Aer Expectation — TREX Only** (16 Pauli-X twirls) | `-0.7986` | Abs error `0.3155` (`-71.4%`) |
| **Noisy Aer Expectation — Combined ZNE + TREX** | **`-0.5652`** | Abs error **`0.0821`** (**`-92.6%` error reduction**) |
| **Quantum Entropy Harvester** (6q, 512 shots + QRNG XOR) | `62.28 ms` (`256 B` pool) | Shannon Entropy **`3.9268 bits`** |

---

## Documentation & Manuals

- **Full Documentation Site:** `mkdocs serve` (verified with `mkdocs build --strict`).
- **Core References:** [Architecture](docs/architecture.md) · [Cryptography & Threat Model](docs/cryptography-threat-model.md) · [Quantum Backends & Error Mitigation](docs/quantum-backends.md) · [API Reference](docs/api-reference.md)
- **Production Manuals:** [Linux & ARM64 Installation](docs/manuals/installation-linux-arm64.md) · [Operator's Manual](docs/manuals/operators-manual.md) · [Developer Plugin Guide](docs/manuals/developer-plugin-guide.md) · [Troubleshooting](docs/manuals/troubleshooting.md)
- **Standalone Module READMEs:**
  - [Module 1: `reality_stamp`](src/qaegis/modules/reality_stamp/README.md)
  - [Module 2: `chameleon_fw`](src/qaegis/modules/chameleon_fw/README.md)
  - [Module 3: `qubit_compiler`](src/qaegis/modules/qubit_compiler/README.md)
  - [Module 4: `quantum_dreamer`](src/qaegis/modules/quantum_dreamer/README.md)
  - [Module 5: `quantum_entropy`](src/qaegis/modules/quantum_entropy/README.md)

---

## Roadmap

- [x] **v0.1.0:** Core microkernel, all five subsystems, `liboqs` FIPS 203/204/205, Qiskit/PennyLane/OpenQASM 3.0, ONNX export, MQTT & ROS 2 adapters, Docker multi-arch, systemd hardening.
- [x] **v0.2.0:** Hardware PKCS#11 (HSM/SoftHSM2) & Linux TPM 2.0 key sealing, AWS Braket & IonQ Cloud API v0.3 backend plugins, and CurveZMQ authenticated Event Bus with ZAP allowlist metrics.
- [x] **v0.3.0:** Distributed multi-node ML-DSA-65 Merkle root gossiping with equivocation detection, federated Night-Mode QAOA fleet scheduling with isomorphism deduplication & budget enforcement, and Qiskit ZNE + TREX error mitigation pipelines.
- [x] **v0.4.0:** Zero-downtime PQC key rotation with historical `keyring.json` verification (`qaegis rotate-keys`), interactive `qaegis demo` live showcase, CycloneDX 1.6 CBOM export (`qaegis cbom --format cyclonedx`), Grafana v10+ dashboard & Prometheus alert rules, >=90% branch+statement coverage gate, and automated wheel/sdist build verification.

---

## Contributing & Citation

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

```bibtex
@software{qaegis2026,
  title        = {Q-Aegis: Quantum-Secured Autonomous Edge-AI Platform},
  author       = {{Q-Aegis Contributors}},
  year         = {2026},
  version      = {0.4.0},
  license      = {Apache-2.0},
  url          = {https://github.com/PelleNybe/qaegis}
}
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
