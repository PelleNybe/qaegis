# Troubleshooting Guide

Real-world diagnostics and resolutions for `liboqs`, PKCS#11 HSM / TPM 2.0 sealing, CurveZMQ authentication, multi-cloud quantum backends, entropy health checks, and the Web Mission-Control Dashboard.

---

## 1. `liboqs` Shared Library Not Found (`OSError: liboqs.so`)

**Symptom:** Importing `oqs` fails with `RuntimeError: No liboqs shared libraries found` or `OSError: liboqs.so: cannot open shared object file`.

**Resolution:**
1. Verify `liboqs.so` is installed in `/usr/local/lib`:
   ```bash
   ls -la /usr/local/lib/liboqs.so*
   ```
2. Refresh the dynamic linker cache:
   ```bash
   echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/liboqs.conf
   sudo ldconfig
   ldconfig -p | grep liboqs
   ```
3. In unprivileged environments where `sudo ldconfig` is unavailable, export `LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH`.

---

## 2. Algorithm Alias Differences Across `liboqs` Releases (`SLH-DSA`)

**Symptom:** Different `liboqs` builds name FIPS 205 mechanisms `SLH-DSA-SHA2-128f`, `SLH_DSA_PURE_SHA2_128F`, or `SPHINCS+-SHA2-128f-simple`.

**Resolution:** Q-Aegis automatically resolves aliases inside `qaegis.core.identity.resolve_oqs_sig_algorithm()`. Inspect mechanisms enabled in your local C library with:

```bash
python -c "import oqs; print([s for s in oqs.get_enabled_sig_mechanisms() if 'SLH' in s or 'ML-DSA' in s])"
```

---

## 3. `PermissionError: Insecure permissions ... expected 0o600`

**Symptom:** `IdentityManager.load()` refuses to read `device_identity.secret.json` or `keyring.json` after manual file copying.

**Resolution:** Restore strict owner-only permissions on the key directory and secret files:

```bash
chmod 0700 ./keys
chmod 0600 ./keys/device_identity.secret.json ./keys/keyring.json
```

---

## 4. PKCS#11 HSM / SoftHSM2 Token Slot or PIN Errors

**Symptom:** `qaegis seal-identity --backend pkcs11` reports `No initialized PKCS#11 token found` or `PinIncorrect`.

**Resolution:**
1. Check detected PKCS#11 shared libraries and slots via `qaegis doctor`.
2. Initialize a SoftHSM2 token for local development or testing:
   ```bash
   softhsm2-util --init-token --free --label qaegis --so-pin 87654321 --pin 123456
   QAEGIS_PKCS11_PIN="123456" qaegis seal-identity --backend pkcs11 --token-label qaegis
   ```
3. If your HSM shared library is in a custom path, pass `--pkcs11-lib /path/to/module.so` or set `identity.pkcs11_library` in `qaegis.yaml`.

---

## 5. Linux TPM 2.0 Resource Manager Access (`/dev/tpmrm0`)

**Symptom:** `TPM2Sealer` reports `/dev/tpmrm0` permission denied or unavailable.

**Resolution:** Ensure both `tpm2-tools` is installed and the `qaegis` user belongs to the `tss` group (`sudo usermod -aG tss qaegis`), then re-verify with `qaegis doctor`.

---

## 6. CurveZMQ Peer Handshake Rejected (`qaegis_bus_auth_rejections_total`)

**Symptom:** Fleet nodes do not receive events over ZeroMQ and `qaegis_bus_auth_rejections_total` increments.

**Resolution:** When `bus.zmq_security: curve` and `bus.zmq_allowed_peer_keys` is non-empty, ZAP authentication strictly enforces mutual Curve25519 allowlisting. Ensure every authorized peer's 40-character Z85 Curve25519 public key (`curve_identity.key` / `gossip_node.curve_public_key`) is listed in `bus.zmq_allowed_peer_keys`.

---

## 7. Web Mission-Control Dashboard `401 Unauthorized`

**Symptom:** Browser UI prompts for an authentication token or API calls return HTTP `401`.

**Resolution:** `QAEGIS_DASHBOARD_TOKEN` or `dashboard.auth_token` is enabled. Click **Auth Token** in the top-right header of the Web UI and enter your token, or pass `Authorization: Bearer <token>` / `X-QAegis-Token: <token>` for programmatic REST calls.

---

## 8. `EntropyHealthError` on NIST SP 800-22 / SP 800-90B Validation

**Symptom:** `MultiSourceQrng.harvest()` raises `EntropyHealthError`.

**Diagnostics:**
1. Under strict NIST SP 800-22 ($\alpha = 0.01$ across 4 tests), an ideal RNG has a $\approx 3.9\%$ single-batch false-rejection probability; `MultiSourceQrng.harvest()` automatically retries up to 3 times.
2. Persistent failures indicate a degraded network `qrng_http_url`. Set `reality_stamp.qrng_http_url: null` to rely on the local Qiskit Hadamard QRNG + Linux CSPRNG XOR mixer.

---

## 9. Cloud QPU Fallback (`aer_noisy_fallback` / `ionq:aer_noisy_fallback`)

**Symptom:** `qaegis dream` reports a `*_fallback` backend name instead of executing on remote hardware.

**Resolution:** Cloud credentials were not present in the process environment, so Q-Aegis executed transparently on local noisy Aer simulation. Export `IBM_QUANTUM_TOKEN` (for `ibm_runtime`), `IONQ_API_KEY` (for `ionq`), or `QAEGIS_BRAKET_DEVICE_ARN` + AWS credentials (for remote `aws_braket`).

---

## 10. Local Ollama Bridge Offline

**Symptom:** `OllamaQuantumBridge.check_health()` returns `(False, [])`.

**Resolution:** Confirm Ollama is listening on `quantum_entropy.ollama_base_url` (`curl -s http://127.0.0.1:11434/api/tags`) and pull your configured model (`ollama pull llama3.2`).
