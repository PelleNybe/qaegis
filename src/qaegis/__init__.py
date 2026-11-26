"""Q-Aegis: Quantum-Secured Autonomous Edge-AI Platform."""

from __future__ import annotations

import logging as _logging

# Prevent liboqs-python from attaching an unconditional StreamHandler(sys.stdout) on import,
# which otherwise pollutes JSON stdout commands (`qaegis cbom`) and closed pytest capture streams.
_logging.getLogger("oqs.oqs").disabled = True

__version__ = "0.7.0"


def __getattr__(name: str) -> object:
    if name == "QAegisClient":
        from qaegis.sdk import QAegisClient

        return QAegisClient
    raise AttributeError(f"module 'qaegis' has no attribute '{name}'")


__all__ = ["QAegisClient", "__version__"]
