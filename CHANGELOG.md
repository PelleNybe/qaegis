# Changelog

All notable changes to **Q-Aegis** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-23

### Added
- **Microkernel Core (`qaegis.core`):** Typed async EventBus (in-process + ZeroMQ), hierarchical Pydantic v2 YAML/ENV configuration, NIST PQC + X25519 device identity manager with `0o600` atomic key storage and CBOM export, SQLite WAL storage with schema migrations and SHA-256 hash-chained audit logs, Day/Night lifecycle state machine, structured `structlog` JSON logging, and Prometheus `/metrics` instrumentation.
- **Module 1 (`reality_stamp`):** Multi-source QRNG (HTTP QRNG + local Qiskit Hadamard QRNG + Linux CSPRNG) with XOR mixing, real NIST SP 800-22 & SP 800-90B validators, ML-DSA-65 (FIPS 204) & SLH-DSA-SHA2-128f (FIPS 205) signing, RFC 6962 domain-separated Merkle tree, and offline CLI verifier (`qaegis verify-stamp`).
- **Module 2 (`chameleon_fw`):** Real-time 8-feature traffic extractor, trainable `IsolationForest` + ONNX Runtime HNDL risk classifier, and 3-tier dynamic crypto-agility engine (`STANDARD`, `ELEVATED`, `QUANTUM_CRITICAL`) with Hybrid X25519 + ML-KEM-768 + AES-256-GCM + PQC signatures.
- **Module 3 (`qubit_compiler`):** PyTorch sensor-to-angle autoencoder with bounded $[-\pi, \pi]$ bottleneck and ONNX export, noise-aware Qiskit (OpenQASM 3.0) and PennyLane circuit builders, and exact QUBO/Ising mappers for Max-Cut, task scheduling, and resource allocation.
- **Module 4 (`quantum_dreamer`):** Day-Mode SQLite priority problem queue, Night-Mode Qiskit QAOA optimizer supporting `AerStatevector`, `AerNoisy`, and `IBM Quantum Runtime` (`SamplerV2`), and validation-gated policy updater with automatic rollback.
- **Module 5 (`quantum_entropy`):** Entangled-circuit probability distribution harvester XOR-mixed with verified QRNG, quantum-seeded MCTS planner, evolutionary mutator, LLM logit nucleus sampler, and Ollama / `llama.cpp` async bridge.
- **Edge Adapters & Operations:** Async `paho-mqtt` v2 bridge, graceful optional ROS 2 / DDS bridge, unified Typer + Rich CLI (`qaegis`), reproducible benchmark suite, hardened multi-arch Dockerfile, hardened systemd unit, GitHub Actions CI/CD, and MkDocs Material documentation site.
