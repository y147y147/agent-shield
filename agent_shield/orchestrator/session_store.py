"""Phase C3：自主审计会话持久化（SQLite）。"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from agent_shield.models import AuditSessionReport
from agent_shield.orchestrator.report import session_report_to_markdown
from agent_shield.paths import default_session_db_path


def target_spec_to_dict(spec: Any) -> dict[str, Any]:
    """将 AuditTargetSpec 序列化为可 JSON 存储的 dict（剔除运行时对象）。"""
    if hasattr(spec, "model_dump"):
        data = spec.model_dump(
            exclude={"audit_store", "event_sink", "transport", "judge_llm"},
        )
    elif isinstance(spec, dict):
        data = dict(spec)
    else:
        data = {"kind": str(spec)}
    for key in ("audit_store", "event_sink", "transport", "judge_llm"):
        data.pop(key, None)
    return data


class AuditSessionStore:
    """持久化 AuditSessionReport 会话终报。"""

    def __init__(self, path: str | Path | None = None):
        self.path = str(path if path is not None else default_session_db_path())
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._lock = threading.Lock()
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_sessions (
                id TEXT PRIMARY KEY,
                ts REAL NOT NULL,
                mode TEXT NOT NULL,
                target_spec TEXT NOT NULL,
                task TEXT NOT NULL,
                report_json TEXT NOT NULL,
                markdown TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                vectors_covered INTEGER NOT NULL
            )
            """
        )
        self._conn.commit()

    def save_session(
        self,
        report: AuditSessionReport,
        *,
        target_spec: dict[str, Any] | Any,
        task: str,
        session_id: str | None = None,
    ) -> str:
        """写入一条会话记录，返回 session id。"""
        sid = session_id or uuid.uuid4().hex[:12]
        spec_dict = target_spec if isinstance(target_spec, dict) else target_spec_to_dict(target_spec)
        report_json = json.dumps(report.model_dump(), ensure_ascii=False)
        markdown = session_report_to_markdown(report)
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO audit_sessions
                (id, ts, mode, target_spec, task, report_json, markdown, risk_level, vectors_covered)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sid,
                    time.time(),
                    report.mode,
                    json.dumps(spec_dict, ensure_ascii=False),
                    task,
                    report_json,
                    markdown,
                    report.risk_level,
                    int(report.vectors_covered),
                ),
            )
            self._conn.commit()
        return sid

    def list_sessions(self, *, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, ts, mode, target_spec, task, risk_level, vectors_covered
                FROM audit_sessions
                ORDER BY ts DESC
                LIMIT ?
                """,
                (max(1, limit),),
            ).fetchall()
        cols = ["id", "ts", "mode", "target_spec", "task", "risk_level", "vectors_covered"]
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(zip(cols, row))
            try:
                item["target_spec"] = json.loads(item["target_spec"])
            except json.JSONDecodeError:
                item["target_spec"] = {}
            out.append(item)
        return out

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, ts, mode, target_spec, task, report_json, markdown, risk_level, vectors_covered
                FROM audit_sessions WHERE id = ?
                """,
                (session_id,),
            ).fetchone()
        if row is None:
            return None
        cols = [
            "id",
            "ts",
            "mode",
            "target_spec",
            "task",
            "report_json",
            "markdown",
            "risk_level",
            "vectors_covered",
        ]
        item = dict(zip(cols, row))
        try:
            item["target_spec"] = json.loads(item["target_spec"])
        except json.JSONDecodeError:
            item["target_spec"] = {}
        try:
            item["report"] = json.loads(item["report_json"])
        except json.JSONDecodeError:
            item["report"] = {}
        return item

    def load_report(self, session_id: str) -> AuditSessionReport:
        """从库中加载并校验 AuditSessionReport。"""
        item = self.get_session(session_id)
        if item is None:
            raise KeyError(f"session not found: {session_id}")
        return AuditSessionReport.model_validate(json.loads(item["report_json"]))

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM audit_sessions").fetchone()[0]

    def close(self) -> None:
        self._conn.close()
