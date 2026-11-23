# Multi-stage, multi-architecture (linux/amd64 + linux/arm64) hardened Dockerfile for Q-Aegis
# Stage 1: Compile liboqs shared library cleanly from official Open Quantum Safe source
FROM python:3.12-slim-bookworm AS liboqs-builder

ARG LIBOQS_VERSION=0.12.0

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    git \
    libssl-dev \
    ninja-build \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "${LIBOQS_VERSION}" https://github.com/open-quantum-safe/liboqs.git /src/liboqs \
    && cmake -S /src/liboqs -B /src/liboqs/build -GNinja \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_USE_OPENSSL=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
    && ninja -C /src/liboqs/build install

# Stage 2: Build Python wheel environment with CPU-only PyTorch
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    LD_LIBRARY_PATH=/usr/local/lib \
    QAEGIS_DATA_DIR=/var/lib/qaegis/data \
    QAEGIS_KEYS_DIR=/var/lib/qaegis/keys \
    QAEGIS_DB_PATH=/var/lib/qaegis/data/qaegis.db

RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=liboqs-builder /usr/local/lib/liboqs.so* /usr/local/lib/
COPY --from=liboqs-builder /usr/local/include/oqs /usr/local/include/oqs
RUN ldconfig

WORKDIR /app

COPY pyproject.toml LICENSE README.md ./
COPY src ./src

# Install CPU-only PyTorch first to keep edge container footprint lean, then install Q-Aegis
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
    && python -m pip install --no-cache-dir .

# Create dedicated unprivileged user and restricted runtime directories
RUN groupadd --system --gid 10001 qaegis \
    && useradd --system --uid 10001 --gid qaegis --home-dir /var/lib/qaegis --shell /usr/sbin/nologin qaegis \
    && mkdir -p /var/lib/qaegis/data /var/lib/qaegis/keys /etc/qaegis \
    && chown -R qaegis:qaegis /var/lib/qaegis /etc/qaegis /app \
    && chmod 0700 /var/lib/qaegis/keys

USER qaegis

EXPOSE 9108

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD ["qaegis", "doctor"]

ENTRYPOINT ["qaegis"]
CMD ["run"]
