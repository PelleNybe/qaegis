# Q-Aegis Documentation

Welcome to **Q-Aegis**, an open-source, production-ready **Quantum-Secured Autonomous Edge-AI Platform** licensed under Apache 2.0.

Q-Aegis integrates five interoperable subsystems onto a single asynchronous microkernel:

1. **Proof of Reality (`reality_stamp`):** Multi-source QRNG + NIST SP 800-22/800-90B validation + NIST FIPS 204/205 PQC signatures + Merkle audit log.
2. **Quantum Chameleon (`chameleon_fw`):** Real-time AI anomaly & HNDL risk firewall dynamically switching between X25519 and Hybrid ML-KEM-768 + ML-DSA-65.
3. **AI-to-Qubit Compiler (`qubit_compiler`):** PyTorch/ONNX neural autoencoder mapping sensor vectors into bounded quantum rotation angles, OpenQASM 3.0 circuits, and QUBO/Ising matrices.
4. **Quantum Dreaming (`quantum_dreamer`):** Asynchronous Day/Night QAOA optimizer for IBM Quantum Runtime and local Aer simulators with rollback-guarded policy updates.
5. **Quantum Entropy Evolution Engine (`quantum_entropy`):** Entangled-circuit probability harvester driving MCTS planning, evolutionary mutation, and local Ollama / `llama.cpp` agents.

## Where to Start

- **Deploying on Ubuntu or Raspberry Pi 5?** Read the [Linux & ARM64 Installation Manual](manuals/installation-linux-arm64.md).
- **Running in production?** Review the [Operator's Manual](manuals/operators-manual.md) and [Cryptography & Threat Model](cryptography-threat-model.md).
- **Understanding the Day/Night microkernel?** Explore the [System Architecture](architecture.md) and [Quantum Backends](quantum-backends.md).
- **Building a custom plugin or backend?** Follow the [Developer Plugin Guide](manuals/developer-plugin-guide.md).
