## Summary

Describe the changes introduced in this pull request and link any related issue.

## Verification Checklist

- [ ] `ruff check src tests benchmarks` passes with zero warnings
- [ ] `ruff format --check src tests benchmarks` passes
- [ ] `mypy --strict src` passes with zero errors
- [ ] `pytest` passes (including `crypto` and `quantum` tests)
- [ ] No placeholders (`TODO`, `FIXME`, `NotImplementedError`) or mock cryptography introduced
- [ ] Documentation updated where applicable
