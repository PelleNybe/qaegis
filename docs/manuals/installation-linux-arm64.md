# Installation Manual: Linux (`x86_64`) & Edge ARM64 (Raspberry Pi 5)

This guide covers clean, reproducible installation of **Q-Aegis** on Ubuntu 22.04/24.04 (`x86_64`) and 64-bit ARM edge hardware such as **Raspberry Pi 5** (Raspberry Pi OS 64-bit / Ubuntu Server ARM64).

---

## 1. System Prerequisites

Install system build dependencies required to compile the `liboqs` shared C library and Python wheels:

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
  pkg-config
```

Verify Python is 3.11 or newer:

```bash
python3 --version
```

---

## 2. Build & Install `liboqs` Shared Library

Compiling `liboqs` with OpenSSL acceleration ensures native hardware crypto performance on both x86_64 (AES-NI / AVX2) and ARM64 (ARMv8 Crypto Extensions on Raspberry Pi 5):

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

## 4. Install Q-Aegis & Verify Health

Install Q-Aegis in editable mode (or standard wheel mode for production):

```bash
pip install --no-cache-dir -e .
```

Verify all cryptographic primitives, quantum simulators, and SQLite WAL storage:

```bash
qaegis version
qaegis init-identity
qaegis doctor
```

Expected output confirms:
- `ML-KEM-768 Available: True`
- `ML-DSA-65 Available: True`
- `SLH-DSA Available: True`
- `SQLite WAL Schema Version: 1`
- `Audit Hash Chain Valid: True`

---

## 5. Multi-Arch Docker Build (`linux/amd64` + `linux/arm64`)

To build a hardened non-root container image directly from the repository:

```bash
docker build -f deploy/docker/Dockerfile -t qaegis:0.1.0 .
docker run --rm qaegis:0.1.0 doctor
```

For cross-platform builds using Docker Buildx:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f deploy/docker/Dockerfile \
  -t ghcr.io/pellenybe/qaegis:0.1.0 .
```
