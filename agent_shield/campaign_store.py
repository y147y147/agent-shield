"""Phase 3 中间结果入库：把红队战役战报持久化到 sqlite（可累积、做趋势/文档）。

背景：campaign 战报目前只临时输出到终端/JSON/Markdown，跑完即丢。为了"全程数字进
文档、可跨跑累积观察趋势"，把每次 run-campaign 的聚合结果落一个 sqlite 库。
设计沿用 ```AttackMemory``` 的轻量 sqlite 范式（threading.Lock + 无 ORM），表结构：

- ``campaign_runs(id, ts, cfg_json, summary_json, markdown)``：一次战役的配置、摘要、Markdown 快照；
- ``campaign_rows(run_id, target, module, cells, mean_rate, median_rate, aggr_rate, successes, total)``：
  该次战役逐 (目标, 模块) 的聚合行，供 SQL 聚合/趋势图。
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from agent_shield.paths import user_data_dir


def default_campaign_db_path() -> Path:
    """战役战报库默认路径（跨平台：~/.agent-shield/campaign_runs.db）。"""
    return user_data_dir() / "campaign_runs.db"


class CampaignStore:
    """持久化战役战报（sqlite）：record_run / latest / list_runs / close。"""

    def __init__(self, path: str | Path | None = None):
        self.path = str(path if path is not None else default_campaign_db_path())
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._lock = threading.Lock()
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS campaign_runs (
                run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                cfg_json TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                markdown TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS campaign_rows (
                run_id INTEGER NOT NULL,
                target TEXT NOT NULL,
                module TEXT NOT NULL,
                cells INTEGER NOT NULL,
                mean_rate REAL NOT NULL,
                median_rate REAL NOT NULL,
                aggr_rate REAL NOT NULL,
                successes INTEGER NOT NULL,
                total INTEGER NOT NULL
            )
            """
        )
        self._conn.commit()

    # ------------------------------------------------------------------ 写
    def record_run(self, report, cfg) -> int:
        """把一次战役战报入库，返回 run_id。

        report：agent_shield.campaign.CampaignReport；cfg：CampaignConfig。
        """
        cfg_dict = {
            "targets": [getattr(t, "label", str(t)) for t in getattr(cfg, "targets", [])],
            "modules": list(getattr(cfg, "module_names", lambda: [])()),
            "rounds": getattr(cfg, "rounds", None),
            "concurrency": getattr(cfg, "concurrency", None),
            "seed": getattr(cfg, "seed", None),
            "defense": getattr(cfg, "defense", None),
            "task": getattr(cfg, "task", ""),
            "num_variants": getattr(cfg, "num_variants", None),
        }
        cfg_json = json.dumps(cfg_dict, ensure_ascii=False)
        summary = json.dumps(report.summary(), ensure_ascii=False, indent=2)
        markdown = report.to_markdown()
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO campaign_runs (ts, cfg_json, summary_json, markdown) VALUES (?, ?, ?, ?)",
                (time.time(), cfg_json, summary, markdown),
            )
            run_id = int(cur.lastrowid)
            rows = report.per_target_rows()
            self._conn.executemany(
                """
                INSERT INTO campaign_rows
                    (run_id, target, module, cells, mean_rate, median_rate, aggr_rate, successes, total)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        run_id, r["target"], r["module"], r["cells"], r["mean_rate"],
                        r["median_rate"], r["aggr_rate"], r["successes"], r["total"],
                    )
                    for r in rows
                ],
            )
            self._conn.commit()
        return run_id

    # ------------------------------------------------------------------ 读
    def list_runs(self, limit: int = 10) -> list[dict]:
        """返回最近 limit 次战役的摘要（不含 rows/markdown）。"""
        rows = self._conn.execute(
            "SELECT run_id, ts, cfg_json, summary_json FROM campaign_runs ORDER BY run_id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {
                "run_id": int(id_), "ts": ts,
                "cfg": json.loads(cfg) if cfg else {},
                "summary": json.loads(s) if s else {},
            }
            for id_, ts, cfg, s in rows
        ]

    def latest(self, run_id: int | None = None) -> dict | None:
        """取指定（或最新）战役的完整快照（含 markdown 与逐行聚合）。"""
        if run_id is None:
            row = self._conn.execute(
                "SELECT run_id, ts, cfg_json, summary_json, markdown FROM campaign_runs ORDER BY run_id DESC LIMIT 1"
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT run_id, ts, cfg_json, summary_json, markdown FROM campaign_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        if row is None:
            return None
        id_, ts, cfg, summary, md = row
        lines = self._conn.execute(
            "SELECT target, module, cells, mean_rate, median_rate, aggr_rate, successes, total "
            "FROM campaign_rows WHERE run_id = ? ORDER BY target, module",
            (id_,),
        ).fetchall()
        rows = [
            {
                "target": t, "module": m, "cells": c, "mean_rate": mr,
                "median_rate": mdr, "aggr_rate": ar, "successes": s, "total": tot,
            }
            for t, m, c, mr, mdr, ar, s, tot in lines
        ]
        return {
            "run_id": int(id_), "ts": ts,
            "cfg": json.loads(cfg) if cfg else {},
            "summary": json.loads(summary) if summary else {},
            "markdown": md, "rows": rows,
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> CampaignStore:
        return self

    def __exit__(self, *exc) -> None:
        self.close()