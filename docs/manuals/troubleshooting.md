# Troubleshooting Guide

Real-world diagnostics for common `liboqs`, quantum backend, entropy validation, and permission errors.

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
3. In non-root virtual environments where `sudo ldconfig` is unavailable, export `LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH`.

---

## 2. Algorithm Name Mismatch Across `liboqs` Versions (`SLH-DSA`)

**Symptom:** Older or newer `liboqs` builds expose different naming conventions (`SLH-DSA-SHA2-128f` vs `SLH_DSA_PURE_SHA2_128F` vs `SPHINCS+-SHA2-128f-simple`).

**Resolution:** Q-Aegis automatically resolves aliases inside `qaegis.core.identity.resolve_oqs_sig_algorithm()`. Inspect what your installed `liboqs` binary supports with:

```bash
python -c "import oqs; print([s for s in oqs.get_enabled_sig_mechanisms() if 'SLH' in s or 'ML-DSA' in s])"
```

---

## 3. `PermissionError: Insecure permissions ... expected 0o600`

**Symptom:** `IdentityManager.load()` refuses to start after copying or backing up `device_identity.secret.json`.

**Resolution:** Restore strict owner-only permissions on the key directory and secret key file:

```bash
chmod 0700 /var/lib/qaegis/keys
chmod 0600 /var/lib/qaegis/keys/device_identity.secret.json
```

---

## 4. `EntropyHealthError` on NIST SP 800-22 / SP 800-90B Checks

**Symptom:** `MultiSourceQrng.harvest()` raises `EntropyHealthError` during stamping.

**Diagnostics:**
1. Inspect Prometheus counters: `qaegis_qrng_health_checks_total{passed="false"}`.
2. Note that under strict NIST SP 800-22 ($\alpha = 0.01$ across 4 independent tests), even a truly uniform RNG has a $\approx 3.9\%$ single-shot false-rejection probability; `MultiSourceQrng.harvest()` automatically retries up to 3 times.
3. Persistent failures indicate a malfunctioning or stuck external `qrng_http_url` endpoint. Test the endpoint directly or set `reality_stamp.qrng_http_url: null` to rely on the local Qiskit Hadamard QRNG + Linux CSPRNG XOR mixer.

---

## 5. IBM Quantum Runtime Queue Timeouts or Missing Token

**Symptom:** Night-Mode jobs report `backend_name: "aer_noisy_fallback"` instead of `ibm_runtime:<backend>`.

**Resolution:**
1. Ensure `IBM_QUANTUM_TOKEN` (or `QISKIT_IBM_TOKEN`) is exported in the process environment.
2. Verify `quantum_dreamer.ibm_channel` matches your account type (`ibm_quantum` or `ibm_cloud`).
3. Confirm the target QPU name (`ibm_backend_name`) is online in your IBM Quantum dashboard.

---

## 6. Local Ollama Bridge Connection Refused

**Symptom:** `OllamaQuantumBridge.check_health()` returns `(False, [])`.

**Resolution:**
1. Verify Ollama is listening on the configured `quantum_entropy.ollama_base_url` (default `http://127.0.0.1:11434`):
   ```bash
   curl -s http://127.0.0.1:11434/api/tags
   ```
2. Ensure your target model (`ollama pull llama3.2`) is downloaded before invoking `generate_with_quantum_seed()`.
