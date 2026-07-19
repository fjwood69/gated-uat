"""orchestrator/isolation.py — run-ID allocation and durable registry.

Every resource in a gated-uat run is namespaced by a canonical UUID4 run_id
(§6). This module allocates run_ids transactionally so no two concurrent runs
(on the same filesystem) ever share one.

run_id format: canonical UUID4 (8-4-4-4-12 hex, version 4 variant 2).
Arbitrary text is rejected to prevent accidental unsafe slugs reaching GitHub
repo names, branch names, and container names.

For resource-safe slugs: use run_id_slug(run_id) — strips dashes, prepends
"r", safe for branch/repo/container names.

Cross-host safety in P2+: GitHub repo-name uniqueness is a second layer (§6,
§5.2); a networked registry is the named deploy-tier (§11, not built here).
"""

from __future__ import annotations

import platform
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

DEFAULT_REGISTRY_PATH = Path.home() / ".gated-uat" / "registry.db"

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


class RunState(str, Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    REAPED = "reaped"
    FAILED = "failed"


_TERMINAL_STATES: frozenset[RunState] = frozenset(
    {RunState.COMPLETED, RunState.REAPED, RunState.FAILED}
)

# _init_schema retry budget: two processes racing to set journal_mode=WAL on a fresh registry can
# see a non-busy-handled "database is locked". Idempotent init -> bounded retry + linear backoff.
_INIT_SCHEMA_RETRIES = 8
_INIT_SCHEMA_BACKOFF_S = 0.05


class AllocationError(RuntimeError):
    """run_id already exists — double-allocation attempt rejected."""


class RunStateError(RuntimeError):
    """Invalid state transition (releasing unknown or already-terminal run)."""


def validate_run_id(run_id: str) -> None:
    """Raise ValueError if *run_id* is not a canonical UUID4."""
    if not _UUID4_RE.match(run_id):
        raise ValueError(
            f"run_id must be a canonical UUID4 "
            f"(8-4-4-4-12 hex, version 4 variant 2), got: {run_id!r}"
        )


def run_id_slug(run_id: str) -> str:
    """Derive a resource-safe slug from a canonical UUID4 run_id.

    Strips dashes and prepends "r" so the result is safe for use as a
    GitHub repo suffix, branch name, or container name:
    ``r<32 lowercase hex chars>``
    """
    validate_run_id(run_id)
    return "r" + run_id.replace("-", "").lower()


class Registry:
    """Durable transactional run-ID registry backed by SQLite (WAL mode).

    Each public method opens and closes its own connection so the instance is
    safe to use from multiple threads without additional locking.
    """

    def __init__(self, path: Path = DEFAULT_REGISTRY_PATH) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def allocate(self, *, run_id: str | None = None) -> str:
        """Atomically allocate a new run_id.

        Generates a UUID4 when *run_id* is None. Validates UUID4 format for
        explicit *run_id* values. Raises :exc:`AllocationError` if the run_id
        already exists (prevents double-allocation).
        """
        rid = run_id if run_id is not None else str(uuid.uuid4())
        validate_run_id(rid)
        now = datetime.now(timezone.utc).isoformat()
        host = platform.node()
        conn = self._connect()
        try:
            conn.execute("BEGIN EXCLUSIVE")
            conn.execute(
                "INSERT INTO run_registry (run_id, created_at, state, control_host)"
                " VALUES (?, ?, ?, ?)",
                (rid, now, RunState.ACTIVE.value, host),
            )
            conn.execute("COMMIT")
        except sqlite3.IntegrityError as exc:
            conn.execute("ROLLBACK")
            raise AllocationError(f"run_id already allocated: {rid}") from exc
        finally:
            conn.close()
        return rid

    def release(self, run_id: str, *, state: RunState = RunState.COMPLETED) -> None:
        """Transition *run_id* to a terminal state.

        Raises :exc:`RunStateError` if:
        - *run_id* does not exist in the registry, or
        - *run_id* is already in a terminal state.
        Raises :exc:`ValueError` for non-terminal target states.
        """
        if state not in _TERMINAL_STATES:
            raise ValueError(f"release() requires a terminal state, got {state!r}")

        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT state FROM run_registry WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                raise RunStateError(f"run_id not found in registry: {run_id!r}")
            current = RunState(row[0])
            if current in _TERMINAL_STATES:
                conn.execute("ROLLBACK")
                raise RunStateError(f"run_id {run_id!r} is already in terminal state {current!r}")
            conn.execute(
                "UPDATE run_registry SET state = ? WHERE run_id = ?",
                (state.value, run_id),
            )
            conn.execute("COMMIT")
        except (AllocationError, RunStateError):
            raise
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def is_active(self, run_id: str) -> bool:
        """True if *run_id* exists and is in the ACTIVE state."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT 1 FROM run_registry WHERE run_id = ? AND state = ?",
                (run_id, RunState.ACTIVE.value),
            ).fetchone()
            return row is not None
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        # WAL mode is set once in _init_schema and persists in the DB file;
        # subsequent connections inherit it without an explicit PRAGMA.
        conn = sqlite3.connect(str(self._path), isolation_level=None, timeout=10.0)
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        # Two control PROCESSES can construct a Registry on the same path CONCURRENTLY (the §9.7
        # race). Switching journal_mode=WAL needs a write lock, and — unlike an ordinary statement —
        # ``PRAGMA journal_mode=WAL`` returns SQLITE_BUSY *immediately* without invoking the busy
        # handler, so ``busy_timeout`` does NOT cover it: a loser sees "database is locked" on a
        # contended host (observed on a 2-core CI runner, not the many-core dev host). The init is
        # IDEMPOTENT (WAL is a no-op once set; CREATE TABLE IF NOT EXISTS), so retry a bounded
        # number of times with a short backoff, then fail closed — never a half-init registry.
        last_exc: sqlite3.OperationalError | None = None
        for attempt in range(_INIT_SCHEMA_RETRIES):
            conn = sqlite3.connect(str(self._path), timeout=30.0)
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS run_registry (
                        run_id        TEXT PRIMARY KEY,
                        created_at    TEXT NOT NULL,
                        state         TEXT NOT NULL DEFAULT 'active',
                        control_host  TEXT NOT NULL
                    )
                    """
                )
                conn.commit()
                return
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower():
                    raise  # a real error, not the WAL-set race — do not mask it
                last_exc = exc
            finally:
                conn.close()
            time.sleep(_INIT_SCHEMA_BACKOFF_S * (attempt + 1))  # linear backoff off the contention
        raise RuntimeError(
            "could not initialise the run registry schema after "
            f"{_INIT_SCHEMA_RETRIES} attempts (persistent 'database is locked')") from last_exc
