# Q-Aegis Documentation

**Quantum-Secured Autonomous Edge-AI, Post-Quantum Security & Multi-Cloud Quantum Optimization Platform (`v0.7.0`)**

Welcome to the official documentation for **Q-Aegis**—an open-source (Apache-2.0), strictly typed, zero-mock platform unifying **NIST FIPS 203 / 204 / 205 Post-Quantum Cryptography**, **hardware key sealing (`PKCS#11` HSM & `TPM 2.0`)**, **Edge-AI tensor-to-qubit compilation**, **multi-cloud federated QAOA with ZNE & TREX error mitigation**, a **Live Web Mission-Control Dashboard**, and the **`QAegisClient` Python SDK**.

---

## Instant Quickstarts

=== "1. Live Terminal Demo"

    Run all five subsystems end-to-end in ~10 seconds without any external cloud API keys:

    ```bash
    pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
    pip install --no-cache-dir -e .
    qaegis demo
    ```

=== "2. Live Web Mission-Control UI"

    Launch the offline-ready 8-tab browser control plane with live Server-Sent Events (SSE) and hot-reloadable YAML configuration:

    ```bash
    qaegis dashboard --host 127.0.0.1 --port 8080
    ```

=== "3. CLI File Sign & Encrypt"

    Sign ML models, SBOMs, or firmware with `ML-DSA-65` / `SLH-DSA` and encrypt sensitive files with hybrid `X25519 + ML-KEM-768 + AES-256-GCM`:

    ```bash
    qaegis init-config --profile developer -o qaegis.yaml
    qaegis sign-file weights.onnx -o weights.onnx.sig.json
    qaegis verify-file weights.onnx weights.onnx.sig.json --keyring ./keys/keyring.json
    qaegis encrypt secrets.env -o secrets.env.enc.json --tier QUANTUM_CRITICAL
    qaegis decrypt secrets.env.enc.json -o secrets.env.restored
    ```

=== "4. Python SDK (`QAegisClient`)"

    Embed post-quantum provenance, hybrid encryption, and quantum optimization in a few lines of async Python:

    ```python
    import asyncio
    from qaegis import QAegisClient


    async def main() -> None:
        async with QAegisClient("./my_qaegis") as client:
            stamp = await client.stamp("cam-01", "vehicle_detected", confidence=0.98)
            assert client.verify_stamp(stamp).valid
            enc = client.encrypt(b"api-master-secret")
            assert client.decrypt(enc, use_local_keyring=True) == b"api-master-secret"


    asyncio.run(main())
    ```

---

## Five Interoperable Subsystems + Mission Control

1. **Proof of Reality (`qaegis.modules.reality_stamp`):** Multi-source QRNG + NIST SP 800-22/90B statistical health tests + `ML-DSA-65` / `SLH-DSA-SHA2-128f` perception stamps & detached file signatures + RFC 6962 Merkle audit log + multi-node CurveZMQ Merkle root gossip with split-view equivocation detection.
2. **Quantum Chameleon (`qaegis.modules.chameleon_fw`):** Real-time `IsolationForest` anomaly + ONNX Runtime HNDL risk firewall dynamically switching between `STANDARD` (`X25519`), `ELEVATED` (Hybrid `ML-KEM-768`), and `QUANTUM_CRITICAL` (Hybrid + `ML-DSA-65` + ephemeral rekeying) with replay defense.
3. **AI-to-Qubit Compiler (`qaegis.modules.qubit_compiler`):** Self-contained PyTorch/ONNX autoencoder mapping sensor vectors into bounded $[-\pi, \pi]$ $(R_x, R_y, R_z)$ rotation angles, transpiled **OpenQASM 3.0** circuits, PennyLane executions, and QUBO/Ising matrices.
4. **Quantum Dreaming (`qaegis.modules.quantum_dreamer`):** Day-Mode SQLite WAL queuing + Night-Mode **Federated QAOA** across **IBM Quantum Runtime, AWS Braket, IonQ, and Qiskit Aer** with isomorphism deduplication, native **ZNE + TREX** error mitigation, and rollback-guarded policy updates.
5. **Quantum Entropy Evolution Engine (`qaegis.modules.quantum_entropy`):** Entangled-circuit probability harvester XOR-mixed with verified QRNG driving MCTS planning, Box-Muller evolutionary mutation, nucleus token sampling, and local **Ollama / `llama.cpp`** agents.

---

## Documentation Navigation by Role

- **Systems & Hardware Engineers:** Start with the [Linux & ARM64 Installation Manual](manuals/installation-linux-arm64.md) and [System Architecture](architecture.md).
- **Security & Compliance Architects:** Review [Cryptography & Threat Model](cryptography-threat-model.md) (`FIPS 203/204/205`, HSM/TPM 2.0 sealing, CycloneDX 1.6 CBOM).
- **Site Reliability & Fleet Operators:** Read the [Operator's Manual](manuals/operators-manual.md) and [Troubleshooting Guide](manuals/troubleshooting.md).
- **Application & Quantum Developers:** Explore [Quantum Backends & Error Mitigation](quantum-backends.md), the [Developer Plugin Guide](manuals/developer-plugin-guide.md), and the [Typed API Reference](api-reference.md).

---

## Credits & Sponsorship

**Q-Aegis** is created and maintained by **[Corax CoLAB](https://coraxcolab.com)** and **[Pelle (@PelleNybe)](https://github.com/PelleNybe)** under the Apache-2.0 License.

If Q-Aegis helps your engineering team or research, you can support ongoing open-source development via **[Buy Me a Coffee](https://buymeacoffee.com/pellenybe)**.
