"""Async SQLite (WAL mode) persistent store with schema migrations and hash-chained audit logs."""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiosqlite
import orjson
from pydantic import BaseModel, Field

from qaegis.core.telemetry import get_logger

logger = get_logger(__name__)

GENESIS_HASH = "0" * 64

MIGRATIONS: list[tuple[int, str]] = [
    (
        1,
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            event_type TEXT NOT NULL,
            actor TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS merkle_leaves (
            leaf_index INTEGER PRIMARY KEY AUTOINCREMENT,
            stamp_id TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            leaf_hash TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            signature_b64 TEXT NOT NULL,
            public_key_fingerprint TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS dream_problems (
            problem_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            priority INTEGER NOT NULL,
            status TEXT NOT NULL,
            problem_type TEXT NOT NULL,
            qubo_json TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            solution_json TEXT,
            row_hash TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_dream_problems_status_priority
            ON dream_problems (status, priority DESC, created_at ASC);

        CREATE TABLE IF NOT EXISTS policy_snapshots (
            version INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            policy_name TEXT NOT NULL,
            weights_json TEXT NOT NULL,
            validation_score REAL NOT NULL,
            baseline_score REAL NOT NULL,
            active INTEGER NOT NULL DEFAULT 0,
            source_problem_id TEXT,
            snapshot_hash TEXT NOT NULL
        );
        """,
    ),
    (
        2,
        """
        CREATE TABLE IF NOT EXISTS gossip_checkpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            peer_node_id TEXT NOT NULL,
            tree_size INTEGER NOT NULL,
            merkle_root TEXT NOT NULL,
            timestamp_utc TEXT NOT NULL,
            sig_alg TEXT NOT NULL,
            signature_b64 TEXT NOT NULL,
            public_key_fingerprint TEXT NOT NULL,
            verified_at_utc TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'VERIFIED'
        );

        CREATE INDEX IF NOT EXISTS idx_gossip_peer_size
            ON gossip_checkpoints (peer_node_id, tree_size DESC);
        """,
    ),
]


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class AuditRecord(BaseModel):
    """Tamper-evident hash-chained audit record."""

    seq: int
    created_at: datetime
    event_type: str
    actor: str
    payload: dict[str, Any]
    prev_hash: str
    entry_hash: str


class DreamProblemRecord(BaseModel):
    """Persisted combinatorial optimization problem queued during Day Mode."""

    problem_id: str
    created_at: datetime
    updated_at: datetime
    priority: int = Field(ge=0, le=100)
    status: str
    problem_type: str
    qubo: dict[str, Any]
    metadata: dict[str, Any]
    solution: dict[str, Any] | None = None
    row_hash: str


class PolicySnapshotRecord(BaseModel):
    """Versioned AI policy weight snapshot with validation metadata."""

    version: int
    created_at: datetime
    policy_name: str
    weights: dict[str, float]
    validation_score: float
    baseline_score: float
    active: bool
    source_problem_id: str | None = None
    snapshot_hash: str


class StorageEngine:
    """Async SQLite storage engine configured in WAL mode with atomic transactions."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._conn: aiosqlite.Connection | None = None

    @property
    def db_path(self) -> Path:
        return self._db_path

    async def initialize(self) -> None:
        """Open SQLite in WAL mode and apply pending schema migrations."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = await aiosqlite.connect(self._db_path)
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA journal_mode=WAL;")
        await conn.execute("PRAGMA synchronous=NORMAL;")
        await conn.execute("PRAGMA foreign_keys=ON;")
        await conn.execute("PRAGMA busy_timeout=5000;")
        self._conn = conn
        await self._apply_migrations()
        logger.info("storage_initialized", db_path=str(self._db_path))

    async def close(self) -> None:
        """Close the database connection cleanly."""
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    def _require_conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("StorageEngine is not initialized; call await initialize() first")
        return self._conn

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[aiosqlite.Connection]:
        """Provide an explicit atomic SQLite transaction context."""
        conn = self._require_conn()
        await conn.execute("BEGIN IMMEDIATE;")
        try:
            yield conn
            await conn.commit()
        except Exception:
            await conn.rollback()
            raise

    async def _apply_migrations(self) -> None:
        conn = self._require_conn()
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );
            """
        )
        await conn.commit()

        cursor = await conn.execute("SELECT version FROM schema_migrations;")
        applied = {int(row["version"]) for row in await cursor.fetchall()}

        for version, ddl in MIGRATIONS:
            if version in applied:
                continue
            await conn.executescript(ddl)
            await conn.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?);",
                (version, datetime.now(UTC).isoformat()),
            )
            await conn.commit()
            logger.info("storage_migration_applied", version=version)

    async def get_schema_version(self) -> int:
        """Return the highest applied migration version."""
        conn = self._require_conn()
        cursor = await conn.execute("SELECT MAX(version) AS v FROM schema_migrations;")
        row = await cursor.fetchone()
        return int(row["v"]) if row is not None and row["v"] is not None else 0

    async def append_audit_event(
        self,
        event_type: str,
        actor: str,
        payload: dict[str, Any],
    ) -> AuditRecord:
        """Append a hash-chained audit entry inside an atomic transaction."""
        now = datetime.now(UTC)
        created_at_iso = now.isoformat()
        payload_bytes = orjson.dumps(payload, option=orjson.OPT_SORT_KEYS)
        payload_json = payload_bytes.decode("utf-8")

        async with self.transaction() as conn:
            cursor = await conn.execute(
                "SELECT entry_hash FROM audit_events ORDER BY seq DESC LIMIT 1;"
            )
            last_row = await cursor.fetchone()
            prev_hash = str(last_row["entry_hash"]) if last_row is not None else GENESIS_HASH

            hash_input = (
                f"{prev_hash}|{created_at_iso}|{event_type}|{actor}|{payload_json}".encode()
            )
            entry_hash = _sha256_hex(hash_input)

            insert_cur = await conn.execute(
                """
                INSERT INTO audit_events (
                    created_at, event_type, actor, payload_json, prev_hash, entry_hash
                ) VALUES (?, ?, ?, ?, ?, ?);
                """,
                (created_at_iso, event_type, actor, payload_json, prev_hash, entry_hash),
            )
            seq = int(insert_cur.lastrowid or 0)

        return AuditRecord(
            seq=seq,
            created_at=now,
            event_type=event_type,
            actor=actor,
            payload=payload,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )

    async def verify_audit_chain(self) -> tuple[bool, int]:
        """Recompute and verify the entire SHA-256 hash chain in `audit_events`."""
        conn = self._require_conn()
        cursor = await conn.execute(
            """
            SELECT seq, created_at, event_type, actor, payload_json, prev_hash, entry_hash
            FROM audit_events
            ORDER BY seq ASC;
            """
        )
        rows = list(await cursor.fetchall())
        expected_prev = GENESIS_HASH
        for row in rows:
            if str(row["prev_hash"]) != expected_prev:
                return (False, int(row["seq"]))
            hash_input = (
                f"{row['prev_hash']}|{row['created_at']}|{row['event_type']}|"
                f"{row['actor']}|{row['payload_json']}"
            ).encode()
            computed = _sha256_hex(hash_input)
            if computed != str(row["entry_hash"]):
                return (False, int(row["seq"]))
            expected_prev = computed
        return (True, len(rows))

    async def save_merkle_leaf(
        self,
        stamp_id: str,
        leaf_hash: str,
        algorithm: str,
        payload_json: str,
        signature_b64: str,
        public_key_fingerprint: str,
    ) -> int:
        """Persist a signed Proof-of-Reality Merkle leaf and return its 0-based index."""
        now_iso = datetime.now(UTC).isoformat()
        async with self.transaction() as conn:
            cursor = await conn.execute(
                """
                INSERT INTO merkle_leaves (
                    stamp_id, created_at, leaf_hash, algorithm,
                    payload_json, signature_b64, public_key_fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    stamp_id,
                    now_iso,
                    leaf_hash,
                    algorithm,
                    payload_json,
                    signature_b64,
                    public_key_fingerprint,
                ),
            )
            rowid = int(cursor.lastrowid or 1)
        return rowid - 1

    async def list_merkle_leaf_hashes(self) -> list[str]:
        """Return all persisted Merkle leaf hex hashes ordered by insertion."""
        conn = self._require_conn()
        cursor = await conn.execute("SELECT leaf_hash FROM merkle_leaves ORDER BY leaf_index ASC;")
        rows = list(await cursor.fetchall())
        return [str(r["leaf_hash"]) for r in rows]

    async def enqueue_dream_problem(
        self,
        problem_id: str,
        priority: int,
        problem_type: str,
        qubo: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> DreamProblemRecord:
        """Queue a Day-Mode combinatorial optimization problem for Night-Mode solving."""
        now = datetime.now(UTC)
        now_iso = now.isoformat()
        meta = metadata or {}
        qubo_json = orjson.dumps(qubo, option=orjson.OPT_SORT_KEYS).decode("utf-8")
        meta_json = orjson.dumps(meta, option=orjson.OPT_SORT_KEYS).decode("utf-8")
        row_hash = _sha256_hex(f"{problem_id}|{priority}|{problem_type}|{qubo_json}".encode())

        async with self.transaction() as conn:
            await conn.execute(
                """
                INSERT INTO dream_problems (
                    problem_id, created_at, updated_at, priority, status,
                    problem_type, qubo_json, metadata_json, solution_json, row_hash
                ) VALUES (?, ?, ?, ?, 'PENDING', ?, ?, ?, NULL, ?);
                """,
                (
                    problem_id,
                    now_iso,
                    now_iso,
                    priority,
                    problem_type,
                    qubo_json,
                    meta_json,
                    row_hash,
                ),
            )
        return DreamProblemRecord(
            problem_id=problem_id,
            created_at=now,
            updated_at=now,
            priority=priority,
            status="PENDING",
            problem_type=problem_type,
            qubo=qubo,
            metadata=meta,
            solution=None,
            row_hash=row_hash,
        )

    async def fetch_pending_dream_problems(self, limit: int = 16) -> list[DreamProblemRecord]:
        """Fetch highest-priority pending Night-Mode optimization problems."""
        conn = self._require_conn()
        cursor = await conn.execute(
            """
            SELECT * FROM dream_problems
            WHERE status = 'PENDING'
            ORDER BY priority DESC, created_at ASC
            LIMIT ?;
            """,
            (limit,),
        )
        rows = list(await cursor.fetchall())
        return [self._row_to_dream_record(r) for r in rows]

    async def update_dream_problem_solution(
        self,
        problem_id: str,
        status: str,
        solution: dict[str, Any] | None,
    ) -> None:
        """Record the solver outcome for a queued dream problem."""
        now_iso = datetime.now(UTC).isoformat()
        sol_json = (
            orjson.dumps(solution, option=orjson.OPT_SORT_KEYS).decode("utf-8")
            if solution is not None
            else None
        )
        async with self.transaction() as conn:
            await conn.execute(
                """
                UPDATE dream_problems
                SET status = ?, updated_at = ?, solution_json = ?
                WHERE problem_id = ?;
                """,
                (status, now_iso, sol_json, problem_id),
            )

    async def save_policy_snapshot(
        self,
        policy_name: str,
        weights: dict[str, float],
        validation_score: float,
        baseline_score: float,
        active: bool,
        source_problem_id: str | None = None,
    ) -> PolicySnapshotRecord:
        """Persist a versioned AI policy weight snapshot and optionally mark it active."""
        now = datetime.now(UTC)
        now_iso = now.isoformat()
        weights_json = orjson.dumps(weights, option=orjson.OPT_SORT_KEYS).decode("utf-8")
        snap_hash = _sha256_hex(
            f"{policy_name}|{weights_json}|{validation_score:.8f}|{now_iso}".encode()
        )
        async with self.transaction() as conn:
            if active:
                await conn.execute(
                    "UPDATE policy_snapshots SET active = 0 WHERE policy_name = ?;",
                    (policy_name,),
                )
            cursor = await conn.execute(
                """
                INSERT INTO policy_snapshots (
                    created_at, policy_name, weights_json, validation_score,
                    baseline_score, active, source_problem_id, snapshot_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    now_iso,
                    policy_name,
                    weights_json,
                    validation_score,
                    baseline_score,
                    1 if active else 0,
                    source_problem_id,
                    snap_hash,
                ),
            )
            version = int(cursor.lastrowid or 0)
        return PolicySnapshotRecord(
            version=version,
            created_at=now,
            policy_name=policy_name,
            weights=weights,
            validation_score=validation_score,
            baseline_score=baseline_score,
            active=active,
            source_problem_id=source_problem_id,
            snapshot_hash=snap_hash,
        )

    async def get_active_policy(self, policy_name: str) -> PolicySnapshotRecord | None:
        """Fetch the currently active policy snapshot for `policy_name`."""
        conn = self._require_conn()
        cursor = await conn.execute(
            """
            SELECT * FROM policy_snapshots
            WHERE policy_name = ? AND active = 1
            ORDER BY version DESC LIMIT 1;
            """,
            (policy_name,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return PolicySnapshotRecord(
            version=int(row["version"]),
            created_at=datetime.fromisoformat(str(row["created_at"])),
            policy_name=str(row["policy_name"]),
            weights=dict(orjson.loads(row["weights_json"])),
            validation_score=float(row["validation_score"]),
            baseline_score=float(row["baseline_score"]),
            active=bool(row["active"]),
            source_problem_id=str(row["source_problem_id"])
            if row["source_problem_id"] is not None
            else None,
            snapshot_hash=str(row["snapshot_hash"]),
        )

    @staticmethod
    def _row_to_dream_record(row: aiosqlite.Row) -> DreamProblemRecord:
        return DreamProblemRecord(
            problem_id=str(row["problem_id"]),
            created_at=datetime.fromisoformat(str(row["created_at"])),
            updated_at=datetime.fromisoformat(str(row["updated_at"])),
            priority=int(row["priority"]),
            status=str(row["status"]),
            problem_type=str(row["problem_type"]),
            qubo=dict(orjson.loads(row["qubo_json"])),
            metadata=dict(orjson.loads(row["metadata_json"])),
            solution=dict(orjson.loads(row["solution_json"]))
            if row["solution_json"] is not None
            else None,
            row_hash=str(row["row_hash"]),
        )

    async def save_gossip_checkpoint(
        self,
        peer_node_id: str,
        tree_size: int,
        merkle_root: str,
        timestamp_utc: str,
        sig_alg: str,
        signature_b64: str,
        public_key_fingerprint: str,
        status: str = "VERIFIED",
    ) -> int:
        """Persist a verified peer Merkle root checkpoint from the gossip mesh."""
        verified_at = datetime.now(UTC).isoformat()
        async with self.transaction() as conn:
            cursor = await conn.execute(
                """
                INSERT INTO gossip_checkpoints (
                    peer_node_id, tree_size, merkle_root, timestamp_utc,
                    sig_alg, signature_b64, public_key_fingerprint, verified_at_utc, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    peer_node_id,
                    tree_size,
                    merkle_root,
                    timestamp_utc,
                    sig_alg,
                    signature_b64,
                    public_key_fingerprint,
                    verified_at,
                    status,
                ),
            )
            return int(cursor.lastrowid or 0)

    async def get_peer_checkpoint_at_size(
        self,
        peer_node_id: str,
        tree_size: int,
    ) -> dict[str, Any] | None:
        """Return an existing verified checkpoint for `peer_node_id` at exact `tree_size`."""
        conn = self._require_conn()
        cursor = await conn.execute(
            """
            SELECT * FROM gossip_checkpoints
            WHERE peer_node_id = ? AND tree_size = ? AND status = 'VERIFIED'
            ORDER BY id ASC LIMIT 1;
            """,
            (peer_node_id, tree_size),
        )
        row = await cursor.fetchone()
        return dict(row) if row is not None else None

    async def list_gossip_checkpoints(
        self,
        peer_node_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """List persisted peer Merkle checkpoints ordered by newest first."""
        conn = self._require_conn()
        if peer_node_id is not None:
            cursor = await conn.execute(
                """
                SELECT * FROM gossip_checkpoints
                WHERE peer_node_id = ?
                ORDER BY tree_size DESC, id DESC;
                """,
                (peer_node_id,),
            )
        else:
            cursor = await conn.execute("SELECT * FROM gossip_checkpoints ORDER BY id DESC;")
        rows = list(await cursor.fetchall())
        return [dict(r) for r in rows]
