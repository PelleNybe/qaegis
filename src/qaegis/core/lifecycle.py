"""Day-Mode (real-time edge) vs Night-Mode (batch QPU) asynchronous lifecycle state machine."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from enum import StrEnum

import psutil
from pydantic import BaseModel, Field

from qaegis.core.bus import EventBus
from qaegis.core.config import LifecycleConfig
from qaegis.core.telemetry import QAegisMetrics, get_logger

logger = get_logger(__name__)


class OperatingMode(StrEnum):
    """Explicit operational states of the Q-Aegis microkernel."""

    DAY = "DAY"
    TRANSITIONING_TO_NIGHT = "TRANSITIONING_TO_NIGHT"
    NIGHT = "NIGHT"
    TRANSITIONING_TO_DAY = "TRANSITIONING_TO_DAY"
    SHUTDOWN = "SHUTDOWN"


_MODE_METRIC_MAP: dict[OperatingMode, float] = {
    OperatingMode.DAY: 0.0,
    OperatingMode.NIGHT: 1.0,
    OperatingMode.TRANSITIONING_TO_NIGHT: 2.0,
    OperatingMode.TRANSITIONING_TO_DAY: 2.0,
    OperatingMode.SHUTDOWN: -1.0,
}


class ModeTransitionRecord(BaseModel):
    """Structured audit record for a lifecycle mode change."""

    previous_mode: OperatingMode
    new_mode: OperatingMode
    reason: str
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))


LifecycleHook = Callable[[ModeTransitionRecord], Awaitable[None]]


class LifecycleManager:
    """Coordinates Day-Mode real-time edge operations and Night-Mode quantum batch windows."""

    def __init__(
        self,
        bus: EventBus,
        config: LifecycleConfig | None = None,
        metrics: QAegisMetrics | None = None,
    ) -> None:
        self._bus = bus
        self._config = config or LifecycleConfig()
        self._metrics = metrics or QAegisMetrics()
        self._mode: OperatingMode = OperatingMode(self._config.default_mode)
        self._lock = asyncio.Lock()
        self._history: list[ModeTransitionRecord] = []
        self._on_enter_night: list[LifecycleHook] = []
        self._on_enter_day: list[LifecycleHook] = []
        self._idle_since: datetime | None = None
        self._metrics.lifecycle_mode.set(_MODE_METRIC_MAP[self._mode])

    @property
    def mode(self) -> OperatingMode:
        """Return the current lifecycle mode."""
        return self._mode

    @property
    def history(self) -> list[ModeTransitionRecord]:
        """Return an immutable snapshot of mode transitions."""
        return list(self._history)

    def register_night_hook(self, hook: LifecycleHook) -> None:
        """Register an async callback executed whenever Night Mode starts."""
        self._on_enter_night.append(hook)

    def register_day_hook(self, hook: LifecycleHook) -> None:
        """Register an async callback executed whenever Day Mode resumes."""
        self._on_enter_day.append(hook)

    def is_within_night_window(self, now: datetime | None = None) -> bool:
        """Return True if the given UTC timestamp falls inside the configured Night Mode window."""
        ts = now or datetime.now(UTC)
        hour = ts.hour
        start = self._config.night_window_start_hour
        end = self._config.night_window_end_hour
        if start <= end:
            return start <= hour < end
        return hour >= start or hour < end

    async def enter_night_mode(self, reason: str = "manual_trigger") -> ModeTransitionRecord:
        """Transition safely from DAY mode into NIGHT mode and trigger batch hooks."""
        async with self._lock:
            if self._mode == OperatingMode.SHUTDOWN:
                raise RuntimeError("Cannot enter NIGHT mode after SHUTDOWN")
            if self._mode == OperatingMode.NIGHT:
                return ModeTransitionRecord(
                    previous_mode=OperatingMode.NIGHT,
                    new_mode=OperatingMode.NIGHT,
                    reason="already_in_night_mode",
                )

            prev = self._mode
            self._mode = OperatingMode.TRANSITIONING_TO_NIGHT
            self._metrics.lifecycle_mode.set(_MODE_METRIC_MAP[self._mode])

            self._mode = OperatingMode.NIGHT
            self._metrics.lifecycle_mode.set(_MODE_METRIC_MAP[self._mode])
            record = ModeTransitionRecord(
                previous_mode=prev,
                new_mode=OperatingMode.NIGHT,
                reason=reason,
            )
            self._history.append(record)

        await self._publish_transition(record)
        await self._run_hooks(self._on_enter_night, record, phase="night")
        logger.info("lifecycle_entered_night", reason=reason, previous_mode=prev.value)
        return record

    async def enter_day_mode(self, reason: str = "manual_trigger") -> ModeTransitionRecord:
        """Transition safely from NIGHT mode back to low-latency DAY mode."""
        async with self._lock:
            if self._mode == OperatingMode.SHUTDOWN:
                raise RuntimeError("Cannot enter DAY mode after SHUTDOWN")
            if self._mode == OperatingMode.DAY:
                return ModeTransitionRecord(
                    previous_mode=OperatingMode.DAY,
                    new_mode=OperatingMode.DAY,
                    reason="already_in_day_mode",
                )

            prev = self._mode
            self._mode = OperatingMode.TRANSITIONING_TO_DAY
            self._metrics.lifecycle_mode.set(_MODE_METRIC_MAP[self._mode])

            self._mode = OperatingMode.DAY
            self._idle_since = None
            self._metrics.lifecycle_mode.set(_MODE_METRIC_MAP[self._mode])
            record = ModeTransitionRecord(
                previous_mode=prev,
                new_mode=OperatingMode.DAY,
                reason=reason,
            )
            self._history.append(record)

        await self._publish_transition(record)
        await self._run_hooks(self._on_enter_day, record, phase="day")
        logger.info("lifecycle_entered_day", reason=reason, previous_mode=prev.value)
        return record

    async def _run_hooks(
        self,
        hooks: list[LifecycleHook],
        record: ModeTransitionRecord,
        phase: str,
    ) -> None:
        """Execute registered lifecycle hooks with per-hook fault isolation."""
        for hook in list(hooks):
            try:
                await hook(record)
            except Exception as exc:
                hook_name = getattr(hook, "__qualname__", repr(hook))
                logger.exception("lifecycle_hook_failed", phase=phase, hook=hook_name)
                await self._bus.publish(
                    topic="lifecycle.hook_error",
                    source="core.lifecycle",
                    payload={
                        "phase": phase,
                        "hook": hook_name,
                        "error": str(exc),
                        "mode": record.new_mode.value,
                    },
                )

    async def evaluate_auto_transition(
        self,
        now: datetime | None = None,
        cpu_percent: float | None = None,
    ) -> ModeTransitionRecord | None:
        """Evaluate scheduled night window and host CPU idle threshold for auto-transition."""
        ts = now or datetime.now(UTC)
        cpu = cpu_percent if cpu_percent is not None else float(psutil.cpu_percent(interval=None))

        if self._mode == OperatingMode.DAY:
            if self.is_within_night_window(ts):
                return await self.enter_night_mode(reason="scheduled_night_window")
            if cpu <= self._config.idle_cpu_threshold_pct:
                if self._idle_since is None:
                    self._idle_since = ts
                elapsed = (ts - self._idle_since).total_seconds()
                if elapsed >= self._config.idle_duration_seconds:
                    return await self.enter_night_mode(reason="host_idle_threshold")
            else:
                self._idle_since = None
        elif (
            self._mode == OperatingMode.NIGHT
            and not self.is_within_night_window(ts)
            and cpu > self._config.idle_cpu_threshold_pct
        ):
            return await self.enter_day_mode(reason="host_activity_resumed")
        return None

    async def shutdown(self) -> ModeTransitionRecord:
        """Mark the microkernel as shutting down."""
        async with self._lock:
            prev = self._mode
            self._mode = OperatingMode.SHUTDOWN
            self._metrics.lifecycle_mode.set(_MODE_METRIC_MAP[self._mode])
            record = ModeTransitionRecord(
                previous_mode=prev,
                new_mode=OperatingMode.SHUTDOWN,
                reason="shutdown",
            )
            self._history.append(record)
        await self._publish_transition(record)
        logger.info("lifecycle_shutdown", previous_mode=prev.value)
        return record

    async def _publish_transition(self, record: ModeTransitionRecord) -> None:
        await self._bus.publish(
            topic="lifecycle.mode_changed",
            source="core.lifecycle",
            payload=record.model_dump(mode="json"),
        )
