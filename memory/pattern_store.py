"""
Persistent finding patterns database.

Stores and retrieves vulnerability patterns across scan sessions
to enable trend detection and regression checking.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Optional

import aiosqlite

logger = logging.getLogger("hunterengine.memory.patterns")


class PatternStore:
    """SQLite-backed store for vulnerability patterns across sessions."""

    def __init__(self, db_path: str = "data/memory.db") -> None:
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    async def _get_db(self) -> aiosqlite.Connection:
        db = await aiosqlite.connect(self.db_path)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detector TEXT NOT NULL,
                pattern_hash TEXT NOT NULL,
                title TEXT,
                url TEXT,
                severity TEXT,
                confidence REAL,
                first_seen REAL,
                last_seen REAL,
                occurrences INTEGER DEFAULT 1,
                data TEXT,
                UNIQUE(detector, pattern_hash)
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time REAL,
                total_findings INTEGER,
                findings_by_severity TEXT,
                target TEXT
            )
        """)
        await db.commit()
        return db

    async def store_findings(self, findings: list[dict]) -> None:
        """Store findings, updating existing patterns or creating new ones."""
        db = await self._get_db()
        try:
            now = time.time()
            for finding in findings:
                pattern_hash = self._hash_finding(finding)
                existing = await db.execute(
                    "SELECT id, occurrences FROM patterns WHERE detector = ? AND pattern_hash = ?",
                    (finding.get("detector", ""), pattern_hash),
                )
                row = await existing.fetchone()

                if row:
                    await db.execute(
                        "UPDATE patterns SET last_seen = ?, occurrences = ?, confidence = ? WHERE id = ?",
                        (now, row[1] + 1, finding.get("confidence", 0), row[0]),
                    )
                else:
                    await db.execute(
                        """INSERT INTO patterns
                           (detector, pattern_hash, title, url, severity, confidence, first_seen, last_seen, data)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            finding.get("detector", ""),
                            pattern_hash,
                            finding.get("title", ""),
                            finding.get("url", ""),
                            finding.get("severity", ""),
                            finding.get("confidence", 0),
                            now, now,
                            json.dumps(finding),
                        ),
                    )
            await db.commit()
        finally:
            await db.close()

    async def get_recurring_patterns(self, min_occurrences: int = 2) -> list[dict]:
        """Get patterns that have been seen multiple times."""
        db = await self._get_db()
        try:
            cursor = await db.execute(
                "SELECT * FROM patterns WHERE occurrences >= ? ORDER BY occurrences DESC",
                (min_occurrences,),
            )
            rows = await cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]
        finally:
            await db.close()

    async def get_patterns_by_detector(self, detector: str) -> list[dict]:
        """Get all patterns from a specific detector."""
        db = await self._get_db()
        try:
            cursor = await db.execute(
                "SELECT * FROM patterns WHERE detector = ? ORDER BY last_seen DESC",
                (detector,),
            )
            rows = await cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]
        finally:
            await db.close()

    async def record_scan(self, target: str, findings: list[dict]) -> None:
        """Record a scan in the history."""
        db = await self._get_db()
        try:
            severity_counts: dict[str, int] = {}
            for f in findings:
                sev = f.get("severity", "unknown")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            await db.execute(
                "INSERT INTO scan_history (scan_time, total_findings, findings_by_severity, target) VALUES (?, ?, ?, ?)",
                (time.time(), len(findings), json.dumps(severity_counts), target),
            )
            await db.commit()
        finally:
            await db.close()

    async def get_scan_history(self, target: Optional[str] = None, limit: int = 20) -> list[dict]:
        """Get scan history, optionally filtered by target."""
        db = await self._get_db()
        try:
            if target:
                cursor = await db.execute(
                    "SELECT * FROM scan_history WHERE target = ? ORDER BY scan_time DESC LIMIT ?",
                    (target, limit),
                )
            else:
                cursor = await db.execute(
                    "SELECT * FROM scan_history ORDER BY scan_time DESC LIMIT ?",
                    (limit,),
                )
            rows = await cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]
        finally:
            await db.close()

    @staticmethod
    def _hash_finding(finding: dict) -> str:
        """Create a stable hash for deduplication across scans."""
        import hashlib
        key = f"{finding.get('detector', '')}:{finding.get('url', '')}:{finding.get('parameter', '')}:{finding.get('title', '')}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]
