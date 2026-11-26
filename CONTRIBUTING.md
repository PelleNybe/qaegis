# Contributing to Q-Aegis

Thank you for your interest in contributing to **Q-Aegis**! We welcome pull requests covering new quantum backends, PQC hardware sealers, Edge-AI adapters, Web Dashboard widgets, benchmarks, and documentation improvements.

## Development Environment Setup

```bash
git clone https://github.com/PelleNybe/qaegis.git
cd qaegis
python3 -m venv .venv
source .venv/bin/activate
pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
pip install --no-cache-dir -e ".[dev,docs]"
```

Ensure `liboqs` (and optionally `softhsm2` for PKCS#11 HSM sealing tests) is installed on your system; see [docs/manuals/installation-linux-arm64.md](docs/manuals/installation-linux-arm64.md).

## Engineering Standards

Every pull request must satisfy all CI verification gates:

1. **Zero Placeholders, Mocks, or Asserts in Production Code:** No `TODO`, `FIXME`, `NotImplementedError`, bare `pass`, `assert` (`S101`), stubbed cryptography, or fake quantum results anywhere in `src/`.
2. **100% English Only:** All source code, HTML/CSS/JS, docstrings, CLI text, tests, manuals, and commit messages must be written in clear English.
3. **Strict Typing:** `mypy --strict src` must report zero issues across all source modules.
4. **Formatting, Linting & Security:** `ruff check src tests benchmarks`, `ruff check --select S src`, and `ruff format --check src tests benchmarks` must pass with zero violations.
5. **Test Suite & Coverage:** `pytest --cov=qaegis --cov-fail-under=90` must pass 100% with at least 90% total statement + branch coverage.
6. **Documentation:** `mkdocs build --strict` must pass with zero broken links or warnings.
7. **License Compatibility:** All added dependencies must be compatible with Apache License 2.0.

## Commit Style

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat(sdk): add async context manager facade in QAegisClient`
- `fix(telemetry): route default structlog handler dynamically to stderr`
- `docs(manuals): document post-quantum sign-file and encrypt workflows`
- `test(integration): verify key rotation across detached file signatures`

## Pull Request Process

1. Fork the repository and create a feature branch from `main`.
2. Implement your change with unit and integration tests.
3. Run the complete local quality gate suite:
   ```bash
   ruff format --check src tests benchmarks
   ruff check src tests benchmarks
   ruff check --select S src
   mypy --strict src
   pytest --cov=qaegis --cov-fail-under=90
   mkdocs build --strict
   ```
4. Open a Pull Request using the repository template.
