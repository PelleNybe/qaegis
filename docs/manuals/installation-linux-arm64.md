# Installation Manual: Linux (`x86_64`) & Edge ARM64 (Raspberry Pi 5)

This guide covers clean, reproducible installation of **Q-Aegis `v0.7.0`** on Ubuntu 22.04/24.04 (`x86_64`), Debian 12+, and 64-bit ARM edge hardware such as **Raspberry Pi 5** (Raspberry Pi OS 64-bit / Ubuntu Server ARM64).

---

## 1. System Prerequisites

Install system build dependencies required for compiling the `liboqs` shared C library, Python wheels, and optional PKCS#11 / TPM 2.0 hardware security integration:

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential \
  cmake \
  ninja-build \
  git \
  libssl-dev \
  python3 \
  python3-venv \
  python3-dev \
  pkg-config \
  softhsm2 \
  tpm2-tools
```

Verify Python is 3.11 or newer:

```bash
python3 --version
```

---

## 2. Build & Install `liboqs` Shared Library

Compiling `liboqs` with OpenSSL acceleration ensures native hardware crypto performance on both `x86_64` (AES-NI / AVX2) and `ARM64` (ARMv8 Crypto & SHA-3 Extensions on Cortex-A76 / Raspberry Pi 5):

```bash
git clone --depth 1 --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs
cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_USE_OPENSSL=ON \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DCMAKE_INSTALL_PREFIX=/usr/local
sudo ninja -C /tmp/liboqs/build install
sudo ldconfig
rm -rf /tmp/liboqs
```

!!! note "Raspberry Pi 5 / ARM64 Performance Tip"
    CMake automatically detects ARMv8 NEON and SHA3 extensions on Cortex-A76 (Raspberry Pi 5). Verify `/usr/local/lib/liboqs.so` is registered with `ldconfig -p | grep liboqs`.

---

## 3. Create Virtual Environment & Install CPU-Only PyTorch

To keep edge disk usage lean (avoiding multi-gigabyte CUDA binaries), **always** install CPU-only PyTorch first and pass `--no-cache-dir`:

```bash
git clone https://github.com/PelleNybe/qaegis.git
cd qaegis
python3 -m venv .venv
source .venv/bin/activate
pip install --no-cache-dir --upgrade pip
pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
```

On ARM64 (`aarch64`), PyTorch's default PyPI wheel is already CPU-only, so you may alternatively run:

```bash
pip install --no-cache-dir torch
```

---

## 4. Install Q-Aegis, Bootstrap Config & Verify Health

Install Q-Aegis in editable mode (or install the built `.whl` artifact for immutable production hosts):

```bash
pip install --no-cache-dir -e .
```

Bootstrap a deployment YAML configuration and run full diagnostics:

```bash
qaegis version
qaegis init-config --profile developer -o qaegis.yaml
qaegis init-identity -c qaegis.yaml
qaegis doctor -c qaegis.yaml
qaegis demo --fast
```

Expected `qaegis doctor` output confirms:

- `ML-KEM-768 Available: True`
- `ML-DSA-65 Available: True`
- `SLH-DSA Available: True`
- `SQLite WAL Schema Version: 2`
- `Audit Hash Chain Valid: True`
- `Dream Queue Integrity: True`
- `Policy Snapshots Integrity: True`
- `Registered Quantum Backends: aer_noisy, aer_statevector, aws_braket, ibm_runtime, ionq`

---

## 5. Multi-Arch Docker Build (`linux/amd64` + `linux/arm64`)

To build a hardened non-root container image directly from the repository:

```bash
docker build -f deploy/docker/Dockerfile -t qaegis:0.7.0 .
docker run --rm qaegis:0.7.0 doctor
```

For cross-platform builds using Docker Buildx:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f deploy/docker/Dockerfile \
  -t ghcr.io/pellenybe/qaegis:0.7.0 .
```
