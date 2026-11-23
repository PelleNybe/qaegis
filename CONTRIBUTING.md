# Contributing to Q-Aegis

Thank you for your interest in contributing to **Q-Aegis**! We welcome pull requests covering new quantum backends, PQC cipher integrations, Edge-AI adapters, benchmarks, and documentation improvements.

## Development Environment Setup

```bash
git clone https://github.com/PelleNybe/qaegis.git
cd qaegis
python3 -m venv .venv
source .venv/bin/activate
pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
pip install --no-cache-dir -e ".[dev,docs]"
```

Ensure `liboqs` is installed on your system; see [docs/manuals/installation-linux-arm64.md](docs/manuals/installation-linux-arm64.md).

## Engineering Standards

Every pull request must satisfy all CI verification gates:

1. **Zero Placeholders or Mocks:** No `TODO`, `FIXME`, `NotImplementedError`, stubbed cryptography, or simulated PQC/quantum shortcuts in `src/`.
2. **Strict Typing:** `mypy --strict src` must report zero errors.
3. **Formatting & Linting:** `ruff check src tests benchmarks` and `ruff format --check src tests benchmarks` must pass with zero warnings.
4. **Tests:** `pytest --cov=qaegis` must pass across `unit`, `crypto`, `quantum`, and `integration` test suites.
5. **Documentation:** `mkdocs build --strict` must pass with zero broken links or warnings.
6. **License Compatibility:** All added dependencies must be compatible with Apache License 2.0.

## Commit Style

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat(chameleon_fw): add ML-KEM-1024 cipher suite option`
- `fix(reality_stamp): handle short buffers in adaptive proportion test`
- `docs(manuals): update Raspberry Pi 5 liboqs build flags`
- `test(quantum): add 6-qubit noisy QAOA convergence test`

## Pull Request Process

1. Fork the repository and create a feature branch from `main`.
2. Implement your change with unit and integration tests.
3. Run the local quality suite:
   ```bash
   ruff check src tests benchmarks
   ruff format --check src tests benchmarks
   mypy --strict src
   pytest
   mkdocs build --strict
   ```
4. Open a Pull Request using the repository template.
