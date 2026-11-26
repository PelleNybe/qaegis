# Operator's Manual

This manual guides site reliability engineers, DevSecOps teams, and field operators through deploying, securing, monitoring, and operating **Q-Aegis `v0.7.0`** in production.

---

## 1. Bootstrapping Configuration & `systemd` Deployment

1. Create a dedicated unprivileged system user and runtime directories:

   ```bash
   sudo useradd --system --home-dir /var/lib/qaegis --shell /usr/sbin/nologin qaegis
   sudo mkdir -p /etc/qaegis /var/lib/qaegis/data /var/lib/qaegis/keys
   sudo chown -R qaegis:qaegis /var/lib/qaegis
   sudo chmod 0700 /var/lib/qaegis/keys
   ```

2. Copy or generate the production configuration (`developer`, `edge`, `fleet`, or `airgap` presets):

   ```bash
   qaegis init-config --profile edge -o /tmp/qaegis.yaml
   sudo cp /tmp/qaegis.yaml /etc/qaegis/qaegis.yaml
   sudo chown root:qaegis /etc/qaegis/qaegis.yaml
   sudo chmod 0640 /etc/qaegis/qaegis.yaml
   ```

3. Install and enable the hardened systemd unit:

   ```bash
   sudo cp deploy/systemd/qaegis.service /etc/systemd/system/qaegis.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now qaegis.service
   sudo journalctl -u qaegis.service -f
   ```

The shipped unit enforces `NoNewPrivileges=yes`, `CapabilityBoundingSet=`, `ProtectSystem=strict`, `PrivateTmp=yes`, `UMask=0077`, and explicit memory/CPU ceilings (`MemoryMax=2G`, `CPUQuota=200%`).

---

## 2. Live Web Mission-Control Dashboard & Hot Configuration

Q-Aegis ships an offline-ready 8-tab browser control plane (`qaegis dashboard` or `qaegis run --dashboard`) powered by async HTTP/1.1 + Server-Sent Events (SSE):

```bash
# Local loopback Mission Control (no token required on 127.0.0.1 by default)
qaegis dashboard --host 127.0.0.1 --port 8080

# Authenticated remote / SSH-tunneled Mission Control (constant-time Bearer check)
QAEGIS_DASHBOARD_TOKEN="$(openssl rand -hex 32)" qaegis dashboard --host 127.0.0.1 --port 8080
```

From the **Configuration Center** tab, operators can edit every subsystem parameter or raw YAML, validate against the full Pydantic v2 schema, apply live in memory without dropping connections, and persist atomically (`0o600`) with SHA-256 audit logging.

---

## 3. PQC Key Lifecycle, Hardware Sealing & Supply-Chain Operations

- **Initial Key Generation:** `qaegis init-identity --config /etc/qaegis/qaegis.yaml` creates `device_identity.secret.json` (`0o600`), `device_identity.public.json` (`0o644`), and `keyring.json` (`0o600`).
- **Zero-Downtime Key Rotation (`qaegis rotate-keys`):** Rotate `ML-DSA-65`, `SLH-DSA`, `ML-KEM-768`, and `X25519` keys while preserving offline verification of all prior Reality Stamps and detached file signatures via `keyring.json`:

  ```bash
  sudo -u qaegis /opt/qaegis/.venv/bin/qaegis rotate-keys --config /etc/qaegis/qaegis.yaml
  sudo -u qaegis /opt/qaegis/.venv/bin/qaegis rotate-keys --seal-backend pkcs11 --token-label qaegis --remove-plaintext --config /etc/qaegis/qaegis.yaml
  ```

- **Post-Quantum Supply-Chain Signing & Hybrid File Encryption:**

  ```bash
  # Detached dual-hash (SHA-256 + SHA3-256) + ML-DSA-65 signing for models, firmware, or SBOMs
  qaegis sign-file release_bundle.tar.zst -o release_bundle.tar.zst.sig.json -c /etc/qaegis/qaegis.yaml
  qaegis verify-file release_bundle.tar.zst release_bundle.tar.zst.sig.json --keyring /var/lib/qaegis/keys/keyring.json

  # Hybrid X25519 + ML-KEM-768 + AES-256-GCM + ML-DSA-65 file encryption
  qaegis encrypt fleet_credentials.json -o fleet_credentials.enc.json --recipient peer_identity.public.json --tier QUANTUM_CRITICAL
  qaegis decrypt fleet_credentials.enc.json -o fleet_credentials.json --sender sender_identity.public.json
  ```

- **CycloneDX 1.6 & Native CBOM Export:**

  ```bash
  qaegis cbom --format cyclonedx --config /etc/qaegis/qaegis.yaml > /var/lib/qaegis/cbom.cdx.json
  ```

- **Hardware Sealing (PKCS#11 HSM / SoftHSM2 or Linux TPM 2.0):**

  ```bash
  qaegis seal-identity --backend pkcs11 --token-label qaegis --pin "$QAEGIS_PKCS11_PIN" --config /etc/qaegis/qaegis.yaml
  qaegis seal-identity --backend tpm2 --pcr-spec sha256:0,7 --config /etc/qaegis/qaegis.yaml
  ```

- **CurveZMQ Peer Allowlists & Merkle Gossip Verification:**

  ```bash
  qaegis gossip status --config /etc/qaegis/qaegis.yaml
  qaegis gossip verify-peer peer_checkpoint.json peer_identity.public.json --config /etc/qaegis/qaegis.yaml
  ```

---

## 4. Configuring Multi-Cloud Night-Mode QPU Credentials

Never store cloud QPU API tokens in `qaegis.yaml` or Git. Inject IBM Quantum, AWS Braket, or IonQ credentials via a root-owned `0o600` systemd override:

```bash
sudo systemctl edit qaegis.service
```

```ini
[Service]
Environment="IBM_QUANTUM_TOKEN=<your-ibm-quantum-api-token>"
Environment="IONQ_API_KEY=<your-ionq-api-key>"
Environment="QAEGIS_BRAKET_DEVICE_ARN=arn:aws:braket:us-east-1::device/qpu/ionq/Aria-1"
Environment="QAEGIS_QUANTUM_DREAMER__BACKEND_TYPE=ibm_runtime"
Environment="QAEGIS_QUANTUM_DREAMER__MITIGATION_MODE=both"
```

---

## 5. Prometheus Monitoring, Grafana & Alerting

When `telemetry.enabled: true`, Q-Aegis exports Prometheus metrics on `http://127.0.0.1:9108/metrics`:

| Metric | Type | Operational Guidance |
| :--- | :--- | :--- |
| `qaegis_qrng_health_checks_total{passed="false"}` | Counter | **Page immediately** if rate > 0 over 5m (entropy source failure or tampering). |
| `qaegis_gossip_equivocation_total` | Counter | **Page immediately** — peer signed conflicting Merkle roots for the same tree size. |
| `qaegis_bus_auth_rejections_total` | Counter | **Alert immediately** on unauthorized CurveZMQ peer ZAP handshake attempts. |
| `qaegis_chameleon_tier_transitions_total{tier="QUANTUM_CRITICAL"}` | Counter | Alert security operations on anomalous `QUANTUM_CRITICAL` spikes. |
| `qaegis_dreamer_policy_updates_total{outcome="rolled_back"}` | Counter | Investigate if consecutive Night-Mode QAOA candidates fail held-out validation. |
| `qaegis_crypto_operation_duration_seconds` | Histogram | Alert if p95 `ML-DSA-65` signing latency exceeds 10 ms on target edge hardware. |
| `qaegis_identity_key_rotations_total` | Counter | Audit scheduled zero-downtime key rotations across the fleet. |

Import `deploy/grafana/qaegis-dashboard.json` into Grafana v10+ and load `deploy/prometheus/alerts.yml` into Prometheus `rule_files`.

---

## 6. Incident Response Procedures

### Suspected Database or Audit Chain Tampering
Run `qaegis doctor --config /etc/qaegis/qaegis.yaml`. If `Audit Hash Chain Valid`, `Dream Queue Integrity`, or `Policy Snapshots Integrity` reports `False`, isolate the node from the network, preserve `/var/lib/qaegis/data/qaegis.db*` (`-wal` and `-shm` included) for forensics, and verify exported Reality Stamps and artifact bundles offline (`qaegis verify-stamp`, `qaegis verify-file`).

### Compromised Device Private Key
1. Revoke the compromised `key_id` / `primary_sig_fingerprint` at upstream verifiers and remove the node's Curve25519 Z85 key from fleet `zmq_allowed_peer_keys`.
2. Re-provision a clean host image and execute `qaegis rotate-keys --seal-backend pkcs11 --remove-plaintext --config /etc/qaegis/qaegis.yaml` (or generate a fresh identity in a clean `keys_dir` if the prior identity was fully compromised).
3. Distribute the new `device_identity.public.json` bundle to authorized fleet peers.
