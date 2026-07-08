"""
Endpoint memory.

Tracks discovered endpoints across scan sessions to detect
new attack surface, removed endpoints, and structural changes.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Optional

import aiosqlite

logger = logging.getLogger("hunterengine.memory.endpoints")


class EndpointMemory:
    """Persistent endpoint tracking across scan sessions."""

    def __init__(self, db_path: str = "data/memory.db") -> None:
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    async def _get_db(self) -> aiosqlite.Connection:
        db = await aiosqlite.connect(self.db_path)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS endpoints (
                url TEXT PRIMARY KEY,
                first_seen REAL,
                last_seen REAL,
                method TEXT DEFAULT 'GET',
                status_code INTEGER,
                content_length INTEGER,
                times_seen INTEGER DEFAULT 1
            )
        """)
        await db.commit()
        return db

    async def store(self, urls: set[str]) -> None:
        """Store current scan's endpoints, updating existing records."""
        db = await self._get_db()
        now = time.time()
        try:
            for url in urls:
                existing = await db.execute("SELECT times_seen FROM endpoints WHERE url = ?", (url,))
                row = await existing.fetchone()
                if row:
                    await db.execute(
                        "UPDATE endpoints SET last_seen = ?, times_seen = ? WHERE url = ?",
                        (now, row[0] + 1, url),
                    )
                else:
                    await db.execute(
                        "INSERT INTO endpoints (url, first_seen, last_seen) VALUES (?, ?, ?)",
                        (url, now, now),
                    )
            await db.commit()
        finally:
            await db.close()

    async def find_new(self, current_urls: set[str]) -> set[str]:
        """Find URLs in the current scan that have never been seen before."""
        db = await self._get_db()
        try:
            cursor = await db.execute("SELECT url FROM endpoints")
            rows = await cursor.fetchall()
            known = {row[0] for row in rows}
            return current_urls - known
        finally:
            await db.close()

    async def find_disappeared(self, current_urls: set[str]) -> set[str]:
        """Find URLs that were previously seen but are missing in the current scan."""
        db = await self._get_db()
        try:
            # Only flag endpoints seen at least twice (to avoid false positives from flaky discovery)
            cursor = await db.execute("SELECT url FROM endpoints WHERE times_seen >= 2")
            rows = await cursor.fetchall()
            known = {row[0] for row in rows}
            return known - current_urls
        finally:
            await db.close()

    async def get_all(self) -> list[dict]:
        """Get all stored endpoints."""
        db = await self._get_db()
        try:
            cursor = await db.execute("SELECT * FROM endpoints ORDER BY last_seen DESC")
            rows = await cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]
        finally:
            await db.close()

    async def get_stats(self) -> dict:
        """Get endpoint memory statistics."""
        db = await self._get_db()
        try:
            total = await db.execute("SELECT COUNT(*) FROM endpoints")
            total_count = (await total.fetchone())[0]

            recurring = await db.execute("SELECT COUNT(*) FROM endpoints WHERE times_seen >= 2")
            recurring_count = (await recurring.fetchone())[0]

            return {
                "total_endpoints": total_count,
                "recurring_endpoints": recurring_count,
            }
        finally:
            await db.close()
