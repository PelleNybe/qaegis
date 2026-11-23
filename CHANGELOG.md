# Changelog

All notable changes to **Q-Aegis** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-11-24

### Added
- **Zero-Downtime PQC Key Rotation (`qaegis.core.identity`):** Versioned `TrustKeyring` (`keyring.json`, `0o600`), `IdentityManager.rotate_keys()` with in-memory secret zeroization and optional PKCS#11/TPM2 sealing, automatic historical key resolution in `verify_reality_stamp(..., keyring=...)`, `qaegis rotate-keys` CLI, `qaegis verify-stamp --keyring`, and `qaegis_identity_key_rotations_total` Prometheus metric.
- **Interactive Zero-Friction Demo (`qaegis demo`):** Rich-powered live 5-subsystem pipeline (`src/qaegis/demo.py`) executing real NIST PQC, QRNG + Merkle stamping, Chameleon firewall escalation, ONNX AI-to-Qubit OpenQASM 3.0 compilation, and noisy QAOA with ZNE+TREX error mitigation (`--fast` mode for CI).
- **CycloneDX 1.6 CBOM Export:** `qaegis cbom --format cyclonedx` emitting standards-compliant CycloneDX 1.6 Cryptographic Bill of Materials with NIST OIDs and quantum security levels.
- **Production Observability & CI Hardening:** Ready-to-import Grafana v10+ dashboard (`deploy/grafana/qaegis-dashboard.json`), Prometheus alerting rules (`deploy/prometheus/alerts.yml`), CI Bandit (`ruff --select S`), wheel/sdist build verification (`python -m build`), and `>= 90%` test coverage enforcement.

## [0.3.0] - 2026-11-23

### Added
- **Distributed Merkle Root Gossip (`qaegis.modules.reality_stamp.gossip`):** Multi-node async P2P Merkle root cross-witnessing mesh over CurveZMQ with **ML-DSA-65** checkpoint signatures, split-view equivocation detection (`gossip.equivocation_detected` + `qaegis_gossip_equivocation_total`), SQLite migration v2 (`gossip_checkpoints`), and `qaegis gossip status` / `qaegis gossip verify-peer` CLI commands.
- **Federated Night-Mode QAOA Fleet Scheduling (`qaegis.modules.quantum_dreamer.federated`):** `FederatedScheduler` fleet coordinator performing exact structural isomorphism deduplication (`canonicalize_qubo` + variable permutation bitstring remapping), nightly QPU budget enforcement (`max_qpu_seconds_per_night`), **ML-DSA-65** signed policy broadcasts, and per-node local validation with automatic rollback guards.
- **Quantum Error Mitigation Pipelines (`qaegis.modules.quantum_dreamer.mitigation`):** Native Qiskit 2.x **ZNE** (unitary gate folding $U \to U(U^\dagger U)^k$ with Linear, Richardson, and Exponential extrapolation) and **TREX** (Pauli-X readout twirling + diagonal readout error calibration), wired into `QaoaSolver` and `qaegis dream --mitigation [none|zne|trex|both]`, achieving **92.6% expectation error reduction** on noisy `AerSimulator` benchmarks.

## [0.2.0] - 2026-11-23

### Added
- **Hardware Key Sealing (`qaegis.core.hardware_seal`):** Pluggable `HardwareSealer` protocol with real `PKCS11Sealer` (non-extractable AES-256 HSM/SoftHSM2 KEK envelope encryption via `python-pkcs11`), real Linux `TPM2Sealer` (PCR-bound `tpm2-tools` sealing on `/dev/tpmrm0`), `qaegis seal-identity --backend [pkcs11|tpm2]` CLI, and hardware readiness diagnostics in `qaegis doctor`.
- **Multi-Cloud QPU Backend Registry (`qaegis.modules.quantum_dreamer.backends`):** Extensible `QuantumBackendRegistry` adding **AWS Braket** (`AwsBraketBackend` with OpenQASM 3.0 compiler for `LocalSimulator` and remote `AwsDevice` ARNs) and **IonQ Cloud API v0.3** (`IonQBackend` with Qiskit-to-IonQ QIS gate compiler, job polling, calibration metadata, and honest local noisy fallback).
- **CurveZMQ Authenticated Event Bus (`qaegis.core.bus`):** Mutual Curve25519 encryption and ZAP allowlist authentication via `AsyncioAuthenticator`, `0o600` Curve25519 keypair persistence, and `qaegis_bus_auth_rejections_total` Prometheus metrics.

## [0.1.0] - 2026-11-23

### Added
- **Microkernel Core (`qaegis.core`):** Typed async EventBus (in-process + ZeroMQ), hierarchical Pydantic v2 YAML/ENV configuration, NIST PQC + X25519 device identity manager with `0o600` atomic key storage and CBOM export, SQLite WAL storage with schema migrations and SHA-256 hash-chained audit logs, Day/Night lifecycle state machine, structured `structlog` JSON logging, and Prometheus `/metrics` instrumentation.
- **Module 1 (`reality_stamp`):** Multi-source QRNG (HTTP QRNG + local Qiskit Hadamard QRNG + Linux CSPRNG) with XOR mixing, real NIST SP 800-22 & SP 800-90B validators, ML-DSA-65 (FIPS 204) & SLH-DSA-SHA2-128f (FIPS 205) signing, RFC 6962 domain-separated Merkle tree, and offline CLI verifier (`qaegis verify-stamp`).
- **Module 2 (`chameleon_fw`):** Real-time 8-feature traffic extractor, trainable `IsolationForest` + ONNX Runtime HNDL risk classifier, and 3-tier dynamic crypto-agility engine (`STANDARD`, `ELEVATED`, `QUANTUM_CRITICAL`) with Hybrid X25519 + ML-KEM-768 + AES-256-GCM + PQC signatures.
- **Module 3 (`qubit_compiler`):** PyTorch sensor-to-angle autoencoder with bounded $[-\pi, \pi]$ bottleneck and ONNX export, noise-aware Qiskit (OpenQASM 3.0) and PennyLane circuit builders, and exact QUBO/Ising mappers for Max-Cut, task scheduling, and resource allocation.
- **Module 4 (`quantum_dreamer`):** Day-Mode SQLite priority problem queue, Night-Mode Qiskit QAOA optimizer supporting `AerStatevector`, `AerNoisy`, and `IBM Quantum Runtime` (`SamplerV2`), and validation-gated policy updater with automatic rollback.
- **Module 5 (`quantum_entropy`):** Entangled-circuit probability distribution harvester XOR-mixed with verified QRNG, quantum-seeded MCTS planner, evolutionary mutator, LLM logit nucleus sampler, and Ollama / `llama.cpp` async bridge.
- **Edge Adapters & Operations:** Async `paho-mqtt` v2 bridge, graceful optional ROS 2 / DDS bridge, unified Typer + Rich CLI (`qaegis`), reproducible benchmark suite, hardened multi-arch Dockerfile, hardened systemd unit, GitHub Actions CI/CD, and MkDocs Material documentation site.
