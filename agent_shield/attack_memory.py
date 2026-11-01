"""攻击指纹记忆库（WS-B Phase 1）：持久化黑名单式"记忆"，让重放命中快路径拦截。

背景与设计（见 docs/plan-v2.md WS-B）：
- WAF 规则记忆："帮防线记住它见过哪些攻击载荷"。标准规则/启发式平时兜底，
  但当**基准规则被放宽**（某次防线改动误伤、或新增编码变体）时，指纹库仍能
  凭"历史命中过的载荷"直接拦截 —— 冷数据落 sqlite，热攻击走内存快路径。
- 存续语义：同一攻击隔新会话重放，只要载荷指纹还在库内，注入检测器在
  快路径即命中，不依赖下次是否还能被规则覆盖。

实现：sqlite 表 ``attack_mem(payload, ts, hits)``，主键为完整载荷文本（我们自己的
攻击载荷，非用户机密），并冗余一行 sha256 指纹供需要"只比对哈希"的地方使用。
API 提供：
- record / record_many：把确认有效的攻击载荷入库（upsert，累计命中数）；
- is_known(payload)：精确命中；
- known_in(text)：快路径 —— 返回 text 中命中的已知载荷（子串匹配，注入即靠
  把载荷原样放进工具输出来生效）。
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from pathlib import Path

from agent_shield.paths import default_attack_mem_path


class AttackMemory:
    """持久化的攻击载荷记忆库（sqlite + 内存快路径缓存）。"""

    def __init__(self, path: str | Path | None = None):
        self.path = str(path if path is not None else default_attack_mem_path())
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._lock = threading.Lock()
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS attack_mem (
                payload TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL,
                ts REAL NOT NULL,
                hits INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        self._conn.commit()
        self._known: set[str] = set()
        self._refresh_cache()

    @staticmethod
    def fingerprint_of(payload: str) -> str:
        """载荷的稳定指纹（sha256 前 16 hex，识别不变载荷）。"""
        return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:16]

    def _refresh_cache(self) -> None:
        rows = self._conn.execute("SELECT payload FROM attack_mem").fetchall()
        self._known = {r[0] for r in rows}

    # ------------------------------------------------------------------ 写
    def record(self, payload: str) -> None:
        """把一条攻击载荷入库（存在则累计 hits，不产生重复行）。"""
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO attack_mem (payload, fingerprint, ts, hits) VALUES (?, ?, ?, 1)
                ON CONFLICT(payload) DO UPDATE SET hits = hits + 1, ts = excluded.ts
                """,
                (payload, self.fingerprint_of(payload), time.time()),
            )
            self._conn.commit()
        self._known.add(payload)

    def record_many(self, payloads: list[str]) -> int:
        """批量入库，返回实际新增数（调用方可用作"学到几条"）。"""
        before = len(self._known)
        for p in payloads:
            if not p:
                continue
            self.record(p)
        return len(self._known) - before

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM attack_mem")
            self._conn.commit()
        self._known.clear()

    # ------------------------------------------------------------------ 读/快路径
    def is_known(self, payload: str) -> bool:
        """精确命中：该载荷是否已在库中（按原文，不按子串）。"""
        return payload in self._known

    def known_in(self, text: str) -> str | None:
        """快路径：text 中是否包含任一已知攻击载荷；返回命中的那条。

        注入攻击靠"把载荷原样混入第三方工具输出"生效，所以工具输出里通常
        完整包含载荷文本 → 子串匹配即以 O(已知库) 完成命中，无需解析结构。
        """
        for p in self._known:
            if p in text:
                return p
        return None

    def size(self) -> int:
        return len(self._known)

    def close(self) -> None:
        with self._lock:
            self._conn.close()