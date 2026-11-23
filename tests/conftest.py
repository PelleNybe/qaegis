"""Shared pytest fixtures for the Q-Aegis test suite."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from qaegis.core.bus import EventBus
from qaegis.core.config import QAegisConfig
from qaegis.core.identity import DeviceIdentity, IdentityManager
from qaegis.core.lifecycle import LifecycleManager
from qaegis.core.storage import StorageEngine
from qaegis.core.telemetry import QAegisMetrics


@pytest.fixture()
def qaegis_config(tmp_path: Path) -> QAegisConfig:
    """Provide an isolated Q-Aegis configuration rooted in `tmp_path`."""
    cfg = QAegisConfig(
        node_id="qaegis-test-node",
        data_dir=tmp_path / "data",
        keys_dir=tmp_path / "keys",
        db_path=tmp_path / "data" / "qaegis.db",
    )
    cfg.ensure_directories()
    return cfg


@pytest.fixture()
def metrics() -> QAegisMetrics:
    """Provide an isolated Prometheus metrics registry per test."""
    return QAegisMetrics()


@pytest.fixture()
def device_identity(qaegis_config: QAegisConfig) -> DeviceIdentity:
    """Generate a fresh real PQC + X25519 device identity for tests."""
    mgr = IdentityManager(
        keys_dir=qaegis_config.keys_dir,
        node_id=qaegis_config.node_id,
        config=qaegis_config.identity,
    )
    return mgr.generate()


@pytest.fixture()
async def event_bus(qaegis_config: QAegisConfig, metrics: QAegisMetrics) -> AsyncIterator[EventBus]:
    """Provide a started EventBus that shuts down cleanly after each test."""
    bus = EventBus(config=qaegis_config.bus, metrics=metrics)
    await bus.start()
    try:
        yield bus
    finally:
        await bus.stop()


@pytest.fixture()
async def storage(qaegis_config: QAegisConfig) -> AsyncIterator[StorageEngine]:
    """Provide an initialized WAL-mode SQLite StorageEngine."""
    engine = StorageEngine(qaegis_config.db_path)
    await engine.initialize()
    try:
        yield engine
    finally:
        await engine.close()


@pytest.fixture()
def lifecycle(
    event_bus: EventBus,
    qaegis_config: QAegisConfig,
    metrics: QAegisMetrics,
) -> LifecycleManager:
    """Provide a LifecycleManager bound to the test EventBus."""
    return LifecycleManager(bus=event_bus, config=qaegis_config.lifecycle, metrics=metrics)
