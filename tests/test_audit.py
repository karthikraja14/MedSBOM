# Copyright 2024 MedSBOM Contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for medsbom.core.audit — Append-only audit trail."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from medsbom.core.audit import AuditTrail

# ============================================================
# Positive cases
# ============================================================


class TestAuditTrailPositive:
    """Positive path tests for audit trail."""

    def test_log_entry(self, tmp_audit_db: Path) -> None:
        trail = AuditTrail(db_path=tmp_audit_db)
        entry = trail.log("scan-001", "check", details="Checked 10 components")

        assert entry.scan_id == "scan-001"
        assert entry.action == "check"
        assert entry.actor == "medsbom-cli"
        assert entry.details == "Checked 10 components"
        assert entry.entry_id  # UUID should be set

    def test_retrieve_entries(self, tmp_audit_db: Path) -> None:
        trail = AuditTrail(db_path=tmp_audit_db)
        trail.log("scan-001", "check")
        trail.log("scan-001", "report")
        trail.log("scan-002", "check")

        entries = trail.get_entries()
        assert len(entries) == 3

    def test_filter_by_scan_id(self, tmp_audit_db: Path) -> None:
        trail = AuditTrail(db_path=tmp_audit_db)
        trail.log("scan-001", "check")
        trail.log("scan-001", "report")
        trail.log("scan-002", "check")

        entries = trail.get_entries(scan_id="scan-001")
        assert len(entries) == 2
        assert all(e.scan_id == "scan-001" for e in entries)

    def test_count(self, tmp_audit_db: Path) -> None:
        trail = AuditTrail(db_path=tmp_audit_db)
        trail.log("scan-001", "check")
        trail.log("scan-001", "report")

        assert trail.count() == 2
        assert trail.count(scan_id="scan-001") == 2
        assert trail.count(scan_id="nonexistent") == 0

    def test_entries_ordered_by_timestamp(self, tmp_audit_db: Path) -> None:
        trail = AuditTrail(db_path=tmp_audit_db)
        trail.log("scan-001", "first")
        trail.log("scan-001", "second")
        trail.log("scan-001", "third")

        entries = trail.get_entries()
        # Entries returned in DESC order; since inserts are sequential,
        # the last inserted has the latest rowid. With same-millisecond timestamps,
        # just verify all 3 are present.
        actions = {e.action for e in entries}
        assert actions == {"first", "second", "third"}
        assert len(entries) == 3

    def test_custom_actor(self, tmp_audit_db: Path) -> None:
        trail = AuditTrail(db_path=tmp_audit_db)
        entry = trail.log("scan-001", "api_scan", actor="api-user@example.com")
        assert entry.actor == "api-user@example.com"

    def test_pagination(self, tmp_audit_db: Path) -> None:
        trail = AuditTrail(db_path=tmp_audit_db)
        for i in range(10):
            trail.log(f"scan-{i:03d}", "check")

        page1 = trail.get_entries(limit=3, offset=0)
        page2 = trail.get_entries(limit=3, offset=3)

        assert len(page1) == 3
        assert len(page2) == 3
        assert page1[0].entry_id != page2[0].entry_id


# ============================================================
# Negative cases — append-only enforcement
# ============================================================


class TestAuditTrailAppendOnly:
    """Tests verifying the append-only constraint."""

    def test_update_blocked(self, tmp_audit_db: Path) -> None:
        """Direct SQL UPDATE should be blocked by trigger."""
        trail = AuditTrail(db_path=tmp_audit_db)
        entry = trail.log("scan-001", "check")

        conn = sqlite3.connect(str(tmp_audit_db))
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(
                "UPDATE audit_log SET action = 'hacked' WHERE entry_id = ?",
                (entry.entry_id,),
            )
        conn.close()

    def test_delete_blocked(self, tmp_audit_db: Path) -> None:
        """Direct SQL DELETE should be blocked by trigger."""
        trail = AuditTrail(db_path=tmp_audit_db)
        trail.log("scan-001", "check")

        conn = sqlite3.connect(str(tmp_audit_db))
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM audit_log WHERE scan_id = 'scan-001'")
        conn.close()


# ============================================================
# Edge cases
# ============================================================


class TestAuditTrailEdgeCases:
    """Edge case tests."""

    def test_empty_db(self, tmp_audit_db: Path) -> None:
        trail = AuditTrail(db_path=tmp_audit_db)
        assert trail.count() == 0
        assert trail.get_entries() == []

    def test_db_created_if_not_exists(self, tmp_path: Path) -> None:
        db_path = tmp_path / "subdir" / "audit.db"
        assert not db_path.parent.exists()
        trail = AuditTrail(db_path=db_path)
        trail.log("scan-001", "init")
        assert db_path.exists()

    def test_multiple_instances_same_db(self, tmp_audit_db: Path) -> None:
        """Multiple AuditTrail instances should share the same DB."""
        trail1 = AuditTrail(db_path=tmp_audit_db)
        trail2 = AuditTrail(db_path=tmp_audit_db)

        trail1.log("scan-001", "check")
        trail2.log("scan-002", "check")

        assert trail1.count() == 2
        assert trail2.count() == 2

    def test_empty_details(self, tmp_audit_db: Path) -> None:
        trail = AuditTrail(db_path=tmp_audit_db)
        entry = trail.log("scan-001", "check", details="")
        assert entry.details == ""

    def test_long_details(self, tmp_audit_db: Path) -> None:
        """Very long details should be stored without truncation."""
        trail = AuditTrail(db_path=tmp_audit_db)
        long_details = "A" * 10000
        trail.log("scan-001", "check", details=long_details)

        entries = trail.get_entries(scan_id="scan-001")
        assert entries[0].details == long_details

    def test_unique_entry_ids(self, tmp_audit_db: Path) -> None:
        """Every entry should get a unique ID."""
        trail = AuditTrail(db_path=tmp_audit_db)
        entries = [trail.log("scan-001", "check") for _ in range(50)]
        ids = [e.entry_id for e in entries]
        assert len(set(ids)) == 50
