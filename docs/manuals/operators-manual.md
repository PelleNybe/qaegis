# Operator's Manual

This manual guides site reliability engineers and field operators through deploying, securing, monitoring, and operating **Q-Aegis** in production.

---

## 1. Production Deployment with `systemd`

1. Create a dedicated unprivileged system user and runtime directories:

   ```bash
   sudo useradd --system --home-dir /var/lib/qaegis --shell /usr/sbin/nologin qaegis
   sudo mkdir -p /etc/qaegis /var/lib/qaegis/data /var/lib/qaegis/keys
   sudo chown -R qaegis:qaegis /var/lib/qaegis
   sudo chmod 0700 /var/lib/qaegis/keys
   ```

2. Copy and customize the production configuration:

   ```bash
   sudo cp deploy/config/qaegis.example.yaml /etc/qaegis/qaegis.yaml
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

## 2. Managing PQC Key Lifecycle & Rotation

- **Initial Key Generation:** `qaegis init-identity --config /etc/qaegis/qaegis.yaml` creates `device_identity.secret.json` (`0o600`) and `device_identity.public.json` (`0o644`).
- **Scheduled Rotation:** Rotate keys cleanly without losing prior public key history:

  ```bash
  sudo -u qaegis /opt/qaegis/.venv/bin/qaegis init-identity --rotate --config /etc/qaegis/qaegis.yaml
  ```

  Previous public bundles are archived automatically under `keys/archived_<UTC>.public.json` so downstream verifiers can continue validating historical Reality Stamps.

- **Compliance Auditing (CBOM):**

  ```bash
  qaegis cbom --config /etc/qaegis/qaegis.yaml --output /var/lib/qaegis/cbom.json
  ```

---

## 3. Configuring Night-Mode QPU Credentials

Never store cloud QPU credentials inside `qaegis.yaml` or Git. Inject IBM Quantum Runtime credentials via a root-owned systemd drop-in override (`0o600`):

```bash
sudo systemctl edit qaegis.service
```

```ini
[Service]
Environment="IBM_QUANTUM_TOKEN=<your-ibm-quantum-api-token>"
Environment="QAEGIS_QUANTUM_DREAMER__BACKEND_TYPE=ibm_runtime"
Environment="QAEGIS_QUANTUM_DREAMER__IBM_BACKEND_NAME=ibm_brisbane"
```

Reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart qaegis.service
```

---

## 4. Prometheus Monitoring & Alerting

When `telemetry.enabled: true`, Q-Aegis exposes Prometheus metrics at `http://127.0.0.1:9108/metrics`:

| Metric | Type | Alerting Recommendation |
| :--- | :--- | :--- |
| `qaegis_qrng_health_checks_total{passed="false"}` | Counter | **Page immediately** if rate > 0 over 5m (potential entropy source failure or tampering). |
| `qaegis_chameleon_tier_transitions_total{tier="QUANTUM_CRITICAL"}` | Counter | Alert security team on unexpected spike in `QUANTUM_CRITICAL` upgrades. |
| `qaegis_dreamer_policy_updates_total{outcome="rolled_back"}` | Counter | Investigate if repeated Night-Mode rollbacks occur across consecutive cycles. |
| `qaegis_crypto_operation_duration_seconds` | Histogram | Alert if p95 ML-DSA-65 signing latency exceeds 10 ms on target edge hardware. |
| `qaegis_lifecycle_mode` | Gauge | Verify expected schedule transitions (`0=DAY`, `1=NIGHT`). |

---

## 5. Incident Response Procedures

### Suspected Audit Log Tampering
Run `qaegis doctor --config /etc/qaegis/qaegis.yaml`. If `Audit Hash Chain Valid` reports `False`, immediately isolate the node from the network, preserve `/var/lib/qaegis/data/qaegis.db*` (including `-wal` and `-shm` files) for forensic inspection, and verify exported Reality Stamps offline with `qaegis verify-stamp`.

### Compromised Device Private Key
1. Revoke the compromised node's public key fingerprint (`primary_sig_fingerprint`) at upstream verifiers.
2. Execute `qaegis init-identity --rotate` on a verified host image.
3. Re-distribute the new `device_identity.public.json` bundle.
