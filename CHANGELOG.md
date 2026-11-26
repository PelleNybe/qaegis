# Changelog

All notable changes to **Q-Aegis** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2026-11-26

### Added
- **Ergonomic Async Python SDK (`qaegis.sdk.QAegisClient`):** High-level `from qaegis import QAegisClient` context manager unifying perception stamping (`stamp`, `verify_stamp`), post-quantum file signing (`sign_file`, `verify_file`), hybrid encryption (`encrypt`, `decrypt`, `protect`), ONNX/OpenQASM 3.0 tensor compilation (`compile_tensor`), QAOA Max-Cut optimization (`solve_maxcut`), and verified quantum randomness (`random_bytes`, `harvest_entropy`).
- **Post-Quantum Supply-Chain File Signing (`ArtifactSignatureBundle`):** Streaming 64 KiB dual-digest (`SHA-256` + `SHA3-256`) + QRNG nonce + `ML-DSA-65` / `SLH-DSA-SHA2-128f` detached file signing and historical `TrustKeyring` verification via `qaegis sign-file`, `qaegis verify-file`, `QAegisClient`, and the Web Mission-Control Dashboard (`/api/reality/sign-artifact`, `/api/reality/verify-artifact`).
- **Hybrid Post-Quantum File Encryption & Config Bootstrap CLI:** Added `qaegis encrypt`, `qaegis decrypt`, and `qaegis init-config --profile [developer|edge|fleet|airgap]` for immediate DevSecOps and developer adoption without boilerplate.

### Performance & Polish
- **10x Faster CLI Startup:** Deferred heavy quantum/ML module imports (`torch`, `qiskit`, `pennylane`, `onnxruntime`, `sklearn`) via PEP 562 lazy package exports and subcommand-scoped imports, cutting cold startup of cryptographic and configuration CLI commands from `~10.0 s` to `~1.0 s`.
- **Zero-Noise `stdout` & Resilient `stderr` Logging:** Silenced `liboqs-python` import-time `stdout` logger pollution in `qaegis.__init__`, routed `structlog` through a stream-resilient `_DynamicStderrHandler`, and suppressed third-party Qiskit transpiler/HTTP `INFO` log noise so piped commands (`qaegis cbom --format cyclonedx > cbom.json`) always emit pure JSON.
- **Deterministic 3-Tier Demo & Web UI Keyring Sort Fix:** Tuned `qaegis demo` Stage 3 traffic observations to deterministically demonstrate `STANDARD -> ELEVATED -> QUANTUM_CRITICAL` escalation, and fixed the keyring version sort comparator in `dashboard/static/app.js`.
- **Comprehensive Documentation & Manuals Overhaul:** Upgraded `README.md`, MkDocs site (`docs/`), all four production manuals (`docs/manuals/`), all five module `README.md`s, `CITATION.cff`, `SECURITY.md`, and `CONTRIBUTING.md`.

## [0.6.0] - 2026-11-24

### Added
- **Live Web Mission-Control Dashboard (`qaegis.dashboard`):** Full-featured, zero-CDN offline-capable 8-tab web application (`Mission Overview`, `Configuration Center`, `PQC Identity & CBOM`, `Proof of Reality & Gossip`, `Quantum Chameleon FW`, `AI-to-Qubit Compiler`, `Quantum Dreamer QAOA`, and `Quantum Entropy & Audit`) served via async `h11` HTTP/1.1 + Server-Sent Events (`/api/events/stream`).
- **Hot-Reloadable Full Configuration Center:** Inspect, validate via Pydantic v2, hot-apply in memory across all running services, and atomically persist every `QAegisConfig` parameter or raw YAML document directly from the browser (`/api/config`, `/api/config/yaml`, `/api/config/reset`), backed by SHA-256 hash-chained `config.updated` audit records.
- **Interactive Subsystem Control Plane & CLI Integration:** Added `qaegis dashboard [--host] [--port] [--auth-token]` and `qaegis run --dashboard [--dashboard-port]`, optional constant-time Bearer/`X-QAegis-Token` authentication, and SQLite WAL inspection queries (`list_audit_events`, `list_merkle_leaves`, `list_dream_problems`, `list_policy_snapshots`).

## [0.5.0] - 2026-11-24

### Security
- **Merkle Proof-to-Stamp Binding (`qaegis.modules.reality_stamp`):** Added canonical `compute_stamp_leaf_hash()` verification inside `verify_reality_stamp()` to prevent Merkle inclusion proof grafting / substitution attacks.
- **Quantum Chameleon Hardening (`qaegis.modules.chameleon_fw`):** Added bounded authenticated replay-attack protection, constant-time sender public-key verification, cipher-suite header enforcement, recipient node binding, and `TrustKeyring` support across sender key rotations.
- **Identity & Hardware Seal Hygiene (`qaegis.core.identity`, `qaegis.core.hardware_seal`):** Guarded retired `DeviceIdentity` instances against post-zeroization signing/decapsulation, made public bundle and archive writes atomic, securely overwrote temporary TPM 2.0 DEK files before unlink, expanded NIST FIPS 205 SLH-DSA OID mappings, added `IdentityManager.load_active(sealer=...)` and `--remove-plaintext` on `qaegis rotate-keys`, and removed hardcoded default PIN from `qaegis seal-identity`.
- **Federated & Gossip Trust Hardening:** Added `TrustKeyring` verification and target-node binding to `quantum_dreamer.federated`, restart hydration (`hydrate_from_storage()`) and peer keyring verification to `MerkleGossipNode`, and CI `softhsm2` provisioning for real PKCS#11 testing in GitHub Actions.

### Performance
- **11x–16x Faster QAOA Optimization (`qaegis.modules.quantum_dreamer.solvers`):** Replaced per-iteration QAOA transpilation with cached parameterized Qiskit `ParameterVector` circuits (`build_parameterized_qaoa_circuit`), reducing 4q/6q Max-Cut statevector solves from `4.71 s` / `5.31 s` down to `0.43 s` / `0.32 s` (1.0000 approximation ratio) and reusing `ErrorMitigationPipeline` TREX calibration across solves.
- **Batched ZNE/TREX & Vectorized Entropy:** Batched Pauli-X readout-twirled circuits into single `AerSimulator.run(...)` calls, vectorized `xor_mix_streams()` and `QuantumEntropyPool.next_gaussians()` in NumPy, and offloaded Qiskit QRNG/harvester execution to worker threads (`asyncio.to_thread`).

### Fixed & Improved
- **Concurrency & Reliability:** Serialized `StorageEngine.transaction()` with `asyncio.Lock`, serialized Merkle leaf anchoring with `RealityStampService._merkle_lock`, added `EventBus` ZMQ loopback event-ID deduplication and `destroy(linger=0)` teardown, isolated failing `LifecycleManager` hooks via `lifecycle.hook_error` events, and added `verify_dream_problem_integrity()` / `verify_policy_snapshots()` into `qaegis doctor`.
- **Self-Contained ONNX Export & Config Validation:** Fused training `(mean, std)` standardization directly into exported `AngleEncoderPipeline` ONNX graphs, added JSON list/dict env-var parsing and cross-field Pydantic validators in `core.config`, added `resource_allocation` QUBO RPC in `QubitCompilerService`, and hardened `AsyncMqttBridge` disconnect ordering and error logging.

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
