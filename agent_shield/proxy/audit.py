"""MITM 审计代理：SQLite 审计存储。"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path


class AuditStore:
    """把代理审计事件写入 SQLite（谁、何时、调了什么、检测到什么、如何处理）。"""

    def __init__(self, path: str | Path = ":memory:"):
        self.path = str(path)
        # FastAPI 事件循环可能在其他线程访问连接（TestClient 线程模型），
        # 因此允许跨线程使用并自行加锁。
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._lock = threading.Lock()
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                ts REAL,
                direction TEXT,
                model TEXT,
                action TEXT,
                detections TEXT,
                detail TEXT
            )
            """
        )
        self._conn.commit()

    def record_event(
        self,
        direction: str,
        model: str,
        action: str,
        detections: list | None = None,
        detail: str = "",
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?)",
                (
                    uuid.uuid4().hex,
                    time.time(),
                    direction,
                    model,
                    action,
                    json.dumps(detections or [], ensure_ascii=False),
                    detail,
                ),
            )
            self._conn.commit()

    def latest(self, n: int = 20) -> list[dict]:
        return self.list_events(limit=n)

    def list_events(self, *, limit: int = 100, since_ts: float | None = None) -> list[dict]:
        """按时间倒序返回审计事件（可选 since_ts 下限）。"""
        with self._lock:
            if since_ts is not None:
                rows = self._conn.execute(
                    """
                    SELECT id, ts, direction, model, action, detections, detail
                    FROM audit_events
                    WHERE ts >= ?
                    ORDER BY ts DESC
                    LIMIT ?
                    """,
                    (since_ts, max(1, limit)),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT id, ts, direction, model, action, detections, detail
                    FROM audit_events
                    ORDER BY ts DESC
                    LIMIT ?
                    """,
                    (max(1, limit),),
                ).fetchall()
        cols = ["id", "ts", "direction", "model", "action", "detections", "detail"]
        out: list[dict] = []
        for row in rows:
            item = dict(zip(cols, row))
            try:
                item["detections"] = json.loads(item["detections"] or "[]")
            except json.JSONDecodeError:
                item["detections"] = []
            out.append(item)
        return out

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]

    def close(self) -> None:
        self._conn.close()
