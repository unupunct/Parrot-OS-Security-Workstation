"""Persistent application notifications (shown in the notification centre)."""
from __future__ import annotations

from ..database.repository import Database


class NotificationService:
    """Writes notifications; the UI listens via `changed`."""

    def __init__(self, db: Database) -> None:
        self._db = db
        self.listeners: list = []

    def add(self, title: str, body: str = "", level: str = "info") -> None:
        self._db.execute("INSERT INTO notifications(level, title, body) VALUES (?,?,?)", (level, title, body))
        for cb in list(self.listeners):
            cb()

    def unread(self) -> int:
        return self._db.query_one("SELECT COUNT(*) n FROM notifications WHERE read = 0")["n"]

    def recent(self, n: int = 30) -> list[dict]:
        return [dict(r) for r in self._db.query("SELECT * FROM notifications ORDER BY id DESC LIMIT ?", (n,))]

    def mark_all_read(self) -> None:
        self._db.execute("UPDATE notifications SET read = 1")
        for cb in list(self.listeners):
            cb()
