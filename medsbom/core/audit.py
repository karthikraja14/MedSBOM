# Copyright 2024 MedSBOM Contributors
# SPDX-License-Identifier: Apache-2.0

"""Audit trail — append-only SQLite log for regulatory compliance evidence."""

from __future__ import annotations

import logging
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path

from medsbom.core.models import AuditEntry

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path.home() / ".medsbom" / "audit.db"

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS audit_log (
    entry_id   TEXT PRIMARY KEY,
    scan_id    TEXT NOT NULL,
    action     TEXT NOT NULL,
    timestamp  TEXT NOT NULL,
    actor      TEXT NOT NULL DEFAULT 'medsbom-cli',
    details    TEXT NOT NULL DEFAULT ''
);
"""

# Append-only: no UPDATE or DELETE triggers
CREATE_TRIGGER_SQL = """
CREATE TRIGGER IF NOT EXISTS prevent_audit_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'Audit log is append-only. Updates are not permitted.');
END;
"""

CREATE_DELETE_TRIGGER_SQL = """
CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'Audit log is append-only. Deletes are not permitted.');
END;
"""


class AuditTrail:
    """Append-only audit trail stored in SQLite."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or DEFAULT_DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the audit database schema."""
        conn = self._connect()
        try:
            conn.execute(CREATE_TABLE_SQL)
            conn.execute(CREATE_TRIGGER_SQL)
            conn.execute(CREATE_DELETE_TRIGGER_SQL)
            conn.commit()
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        """Create a new database connection."""
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def log(
        self,
        scan_id: str,
        action: str,
        actor: str = "medsbom-cli",
        details: str = "",
    ) -> AuditEntry:
        """Append an audit entry. Returns the created entry."""
        entry = AuditEntry(
            entry_id=str(uuid.uuid4()),
            scan_id=scan_id,
            action=action,
            timestamp=datetime.now(UTC),
            actor=actor,
            details=details,
        )

        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO audit_log (entry_id, scan_id, action, timestamp, actor, details) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    entry.entry_id,
                    entry.scan_id,
                    entry.action,
                    entry.timestamp.isoformat(),
                    entry.actor,
                    entry.details,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        logger.info("Audit logged: %s — %s", action, scan_id)
        return entry

    def get_entries(
        self,
        scan_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEntry]:
        """Retrieve audit entries, optionally filtered by scan_id."""
        conn = self._connect()
        try:
            if scan_id:
                rows = conn.execute(
                    "SELECT * FROM audit_log"
                    " WHERE scan_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                    (scan_id, limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
            return [self._row_to_entry(r) for r in rows]
        finally:
            conn.close()

    def count(self, scan_id: str | None = None) -> int:
        """Count total audit entries."""
        conn = self._connect()
        try:
            if scan_id:
                row = conn.execute(
                    "SELECT COUNT(*) FROM audit_log WHERE scan_id = ?", (scan_id,)
                ).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()
            return row[0] if row else 0
        finally:
            conn.close()

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> AuditEntry:
        """Convert a database row to an AuditEntry."""
        return AuditEntry(
            entry_id=row["entry_id"],
            scan_id=row["scan_id"],
            action=row["action"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            actor=row["actor"],
            details=row["details"],
        )
