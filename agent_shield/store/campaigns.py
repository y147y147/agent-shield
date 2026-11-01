"""M1 数据层：SQLite 六表 schema（计划书 §5）+ campaign 落库 + findings 状态机。

表结构（§5 原文映射，另加汇总/隔离字段）：
- campaigns：任务批次（config JSON、summary、markdown 快照、user_id/tenant_id/job_id 隔离边界）
- attack_runs：每次攻击（模块 × 变体 × 目标 × 加固档位）
- traces：完整轨迹（steps/blocked_calls/final_blocked/final_block_reason/intent_flag）
- verdicts：判定明细（score/reason/blind_spot/capability_score）
- costs：成本计量（model/tokens/unit_price/total_cost）
- findings：发现汇总（修复闭环状态机 open → patched → verified）

与既有 ``campaign_store.CampaignStore``（Phase 3 战役聚合战报）并存不冲突：
本模块记录**逐 run 明细**，是攻击智能体闭环（入库 → 纠错 → 修复 → 回归）的数据地基。
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from agent_shield.models import AttackResult
from agent_shield.paths import user_data_dir

SCHEMA_VERSION = 1


def default_attack_db_path() -> Path:
    """攻击智能体库默认路径（跨平台：~/.agent-shield/attack-agent.db）。"""
    return user_data_dir() / "attack-agent.db"


def _trace_to_dict(trace: Any) -> dict[str, Any]:
    """把 AgentTrace 序列化为纯 dict（pydantic 模型递归转 dict + JSON 兜底）。"""
    if trace is None:
        return {}
    if hasattr(trace, "model_dump"):
        try:
            return json.loads(_safe_dumps(trace.model_dump()))
        except json.JSONDecodeError:
            return {}
    if isinstance(trace, dict):
        return dict(trace)
    return {"raw": str(trace)}


def _safe_dumps(obj: Any) -> str:
    """JSON 序列化兜底：递归把 pydantic 模型/含 get 的对象转成纯 dict，其余转字符串。"""

    def convert(x: Any) -> Any:
        if hasattr(x, "model_dump"):
            return convert(x.model_dump())
        if hasattr(x, "model_dump_json"):
            return convert(x.model_dump())
        if isinstance(x, dict):
            return {k: convert(v) for k, v in x.items()}
        if isinstance(x, (list, tuple)):
            return [convert(v) for v in x]
        if isinstance(x, (str, int, float, bool)) or x is None:
            return x
        return str(x)

    try:
        return json.dumps(convert(obj), ensure_ascii=False)
    except (TypeError, ValueError):
        return json.dumps({"unserializable": True, "raw": str(obj)}, ensure_ascii=False)


class FindingStatus:
    """findings 状态机常量：open（已发现）→ patched（已修复）→ verified（回归通过）。"""

    OPEN = "open"
    PATCHED = "patched"
    VERIFIED = "verified"

    # 合法迁移白名单：只允许这些 (from, to) 对，其余抛 ValueError
    _ALLOWED: set[tuple[str, str]] = {
        (OPEN, PATCHED),
        (OPEN, VERIFIED),  # 修复前即回归通过（无盲区场景）
        (PATCHED, VERIFIED),
        (PATCHED, OPEN),  # 修复未达标，回退重试
        (VERIFIED, OPEN),  # 新发现回归漂移，重开
    }

    @classmethod
    def transition(cls, current: str, target: str) -> None:
        """校验状态迁移；非法迁移抛 ValueError（不含同级 no-op）。"""
        if current == target:
            return
        if (current, target) not in cls._ALLOWED:
            raise ValueError(f"非法 findings 状态迁移: {current} → {target}")


class FindingView:
    """findings 行视图（不可变读取）。"""

    def __init__(self, row: dict[str, Any]):
        self.module = str(row.get("module", ""))
        self.status = str(row.get("status", FindingStatus.OPEN))
        self.asr_bare = row.get("asr_bare")
        self.asr_defended = row.get("asr_defended")
        self.capability_delta = row.get("capability_delta")
        self.defense_hits = row.get("defense_hits")
        self.repair_notes = row.get("repair_notes")
        self.campaign_id = row.get("campaign_id")

    def as_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "status": self.status,
            "asr_bare": self.asr_bare,
            "asr_defended": self.asr_defended,
            "capability_delta": self.capability_delta,
            "defense_hits": self.defense_hits,
            "repair_notes": self.repair_notes,
            "campaign_id": self.campaign_id,
        }


class Store:
    """攻击智能体 SQLite 数据层：campaign 落库 + findings 状态机（M1 决策门）。"""

    def __init__(self, path: str | Path | None = None):
        self.path = str(path if path is not None else default_attack_db_path())
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.Lock()
        self._create_schema()

    # ------------------------------------------------------------------ schema
    def _create_schema(self) -> None:
        """幂等建库：PRAGMA user_version 记录版本，重复初始化不报错。"""
        with self._lock:
            version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS campaigns (
                    id TEXT PRIMARY KEY,
                    ts REAL NOT NULL,
                    user_id INTEGER NOT NULL DEFAULT 0,
                    tenant_id INTEGER NOT NULL DEFAULT 0,
                    job_id TEXT NOT NULL DEFAULT '',
                    config TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'completed',
                    summary TEXT NOT NULL,
                    markdown TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS attack_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT NOT NULL,
                    ts REAL NOT NULL,
                    module TEXT NOT NULL,
                    variant TEXT NOT NULL DEFAULT '',
                    target TEXT NOT NULL DEFAULT '',
                    defense INTEGER NOT NULL DEFAULT 0,
                    verdict TEXT NOT NULL DEFAULT '',
                    asr REAL NOT NULL DEFAULT 0,
                    successes INTEGER NOT NULL DEFAULT 0,
                    blocked INTEGER NOT NULL DEFAULT 0,
                    failed INTEGER NOT NULL DEFAULT 0,
                    total INTEGER NOT NULL DEFAULT 0,
                    duration_ms INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS traces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER NOT NULL,
                    module TEXT NOT NULL,
                    case_name TEXT NOT NULL DEFAULT '',
                    steps TEXT NOT NULL,
                    blocked_calls TEXT NOT NULL,
                    final_blocked INTEGER NOT NULL DEFAULT 0,
                    final_block_reason TEXT,
                    intent_flag INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS verdicts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER NOT NULL,
                    module TEXT NOT NULL,
                    case_name TEXT NOT NULL DEFAULT '',
                    verdict TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL DEFAULT '',
                    score REAL,
                    reason TEXT NOT NULL DEFAULT '',
                    blind_spot INTEGER NOT NULL DEFAULT 0,
                    capability_score REAL
                );

                CREATE TABLE IF NOT EXISTS costs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER NOT NULL,
                    model TEXT NOT NULL DEFAULT '',
                    prompt_tokens INTEGER NOT NULL DEFAULT 0,
                    completion_tokens INTEGER NOT NULL DEFAULT 0,
                    total_tokens INTEGER NOT NULL DEFAULT 0,
                    unit_price REAL NOT NULL DEFAULT 0,
                    total_cost REAL NOT NULL DEFAULT 0,
                    llm_calls INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS findings (
                    module TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL DEFAULT '',
                    target TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'open',
                    asr_bare REAL,
                    asr_defended REAL,
                    capability_delta REAL,
                    defense_hits TEXT NOT NULL DEFAULT '[]',
                    repair_notes TEXT NOT NULL DEFAULT ''
                );
                """
            )
            if version < SCHEMA_VERSION:
                self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------ 写
    def record_campaign(self, report: Any, cfg: Any, *, user_id: int = 0,
                        tenant_id: int = 0, job_id: str = "",
                        status: str = "completed",
                        summary_override: dict[str, Any] | None = None) -> str:
        """把一次战役战报入库，返回 campaign_id。

        report：agent_shield.campaign.CampaignReport；cfg：CampaignConfig。
        status：completed（正常完成）| aborted（M5 成本门禁刹停，summary 携带告警）。
        summary_override：显式摘要（M5 超限刹停时 report 不可用，直接落告警摘要）。
        """
        cid = uuid.uuid4().hex[:12]
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
        if summary_override is not None:
            summary = summary_override
        else:
            summary = getattr(report, "summary", lambda: {})() or {}
        markdown = getattr(report, "to_markdown", lambda: "")() or ""
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO campaigns (id, ts, user_id, tenant_id, job_id, config, status, summary, markdown)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cid, time.time(), int(user_id), int(tenant_id), str(job_id),
                    _safe_dumps(cfg_dict), str(status), _safe_dumps(summary), markdown,
                ),
            )
            self._conn.commit()
        return cid

    def total_cost_since(self, timestamp: float) -> float:
        """跨 campaign 汇总 ``timestamp`` 之后的已花费（USD）—— M5 每日总预算用。

        costs 无时间戳列，经 attack_runs.ts 关联求和（runs 是逐格/逐 attempt 的费用载体）。
        """
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COALESCE(SUM(c.total_cost), 0) FROM costs c
                JOIN attack_runs r ON c.run_id = r.id
                WHERE r.ts >= ?
                """,
                (float(timestamp),),
            ).fetchone()
        return float(row[0] or 0.0)

    def record_cost_alert(self, campaign_id: str, kind: str, limit_usd: float,
                          spent_usd: float, *, model: str = "") -> int:
        """落一条成本门禁告警（M5 决策门：超限刹停后 costs 表可查）。

        语义：插一行 attack_runs（module=``__cost_budget__``，verdict=``aborted``），
        costs 行 model 标注 ``budget-alert:<kind>``，unit_price 记限额、total_cost 记已花。
        不加新列，兼容既有 schema（SCHEMA_VERSION 不变）。
        """
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO attack_runs
                    (campaign_id, ts, module, variant, target, defense, verdict,
                     asr, successes, blocked, failed, total, duration_ms)
                VALUES (?, ?, '__cost_budget__', ?, 'budget', 0, 'aborted', 0, 0, 0, 0, 0, 0)
                """,
                (campaign_id, time.time(), str(kind)),
            )
            run_id = int(cur.lastrowid)
            self._conn.execute(
                """
                INSERT INTO costs
                    (run_id, model, prompt_tokens, completion_tokens, total_tokens,
                     unit_price, total_cost, llm_calls)
                VALUES (?, ?, 0, 0, 0, ?, ?, 0)
                """,
                (run_id, f"budget-alert:{kind}", float(limit_usd or 0.0), round(float(spent_usd), 6)),
            )
            self._conn.commit()
        return run_id

    def record_attack_result(self, result: AttackResult, *, campaign_id: str,
                             target: str = "", defense: bool = False,
                             variant: str = "", user_id: int = 0, job_id: str = "") -> int:
        """把一次攻击结果（AttackResult，含逐 case 的 trace/verdict/cost）落库，返回 run_id。"""
        total = max(1, result.total)
        asr = result.successes / total
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO attack_runs
                    (campaign_id, ts, module, variant, target, defense, verdict,
                     asr, successes, blocked, failed, total, duration_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    campaign_id, time.time(), result.module, variant, target,
                    1 if defense else 0,
                    "success" if result.successes > 0 else ("blocked" if result.blocked > 0 else "failed"),
                    round(asr, 6), result.successes, result.blocked, result.failed,
                    result.total, result.duration_ms,
                ),
            )
            run_id = int(cur.lastrowid)

            # traces + verdicts + costs：逐 case 明细
            total_prompt = total_completion = total_tokens = total_calls = 0
            total_cost = 0.0
            model = ""
            for case in result.cases:
                trace = case.trace
                if trace is not None:
                    total_prompt += int(getattr(trace, "prompt_tokens", 0) or 0)
                    total_completion += int(getattr(trace, "completion_tokens", 0) or 0)
                    total_tokens += int(getattr(trace, "total_tokens", 0) or 0)
                    total_calls += int(getattr(trace, "llm_calls", 0) or 0)
                    total_cost += float(getattr(trace, "estimated_cost_usd", 0.0) or 0.0)
                    if not model:
                        model = str(getattr(trace, "model", "") or "")
                trace_dict = _trace_to_dict(trace)
                steps = _safe_dumps(trace_dict.get("steps", []))
                blocked = _safe_dumps(
                    [bc for step in trace_dict.get("steps", []) for bc in step.get("blocked_calls", [])]
                )
                self._conn.execute(
                    """
                    INSERT INTO traces
                        (run_id, module, case_name, steps, blocked_calls,
                         final_blocked, final_block_reason, intent_flag)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id, result.module, case.name, steps, blocked,
                        1 if trace_dict.get("final_blocked") else 0,
                        trace_dict.get("final_block_reason"),
                        1 if trace_dict.get("intent_flag") else 0,
                    ),
                )
                self._conn.execute(
                    """
                    INSERT INTO verdicts
                        (run_id, module, case_name, verdict, severity, score, reason,
                         blind_spot, capability_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id, result.module, case.name, str(case.verdict.value), str(case.severity.value),
                        _verdict_score(case.verdict.value), "; ".join(case.evidence[:5]),
                        1 if int(getattr(result.module, "defense_blind_spot", 0) or 0) else 0,
                        None,  # 能力分由 M2/M3 的 Judge 能力侧写入
                    ),
                )
            self._conn.execute(
                """
                INSERT INTO costs
                    (run_id, model, prompt_tokens, completion_tokens, total_tokens,
                     unit_price, total_cost, llm_calls)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id, model, total_prompt, total_completion, total_tokens,
                    0.0, round(total_cost, 6), total_calls,  # 单价表 M5 成本门禁接入
                ),
            )
            self._conn.commit()
        return run_id

    def upsert_finding(self, result: AttackResult, *, campaign_id: str, target: str = "",
                       defense: bool = False) -> str:
        """按模块汇总攻击结果 upsert findings（asr_bare/asr_defended 合并更新）。"""
        module = result.module
        asr = result.successes / max(1, result.total)
        hits: list[str] = []
        for case in result.cases:
            trace_dict = _trace_to_dict(case.trace)
            if trace_dict.get("final_blocked"):
                hits.append(f"final_blocked:{trace_dict.get('final_block_reason', '') or 'guard'}")
            for step in trace_dict.get("steps", []):
                for bc in step.get("blocked_calls", []):
                    hits.append(f"{bc.get('tool', '')}:{bc.get('reason', '')}")
        hits = list(dict.fromkeys(hits))  # 去重保序

        with self._lock:
            row = self._conn.execute(
                "SELECT campaign_id, status, asr_bare, asr_defended FROM findings WHERE module = ?",
                (module,),
            ).fetchone()
            if row is None:
                bare = round(asr, 6) if not defense else None
                defended = round(asr, 6) if defense else None
                self._conn.execute(
                    """
                    INSERT INTO findings (module, campaign_id, target, status, asr_bare, asr_defended, defense_hits)
                    VALUES (?, ?, ?, 'open', ?, ?, ?)
                    """,
                    (module, campaign_id, target, bare, defended, _safe_dumps(hits)),
                )
            else:
                _prev_cid, prev_status, prev_bare, prev_defended = row
                bare = prev_bare if prev_bare is not None else (round(asr, 6) if not defense else None)
                defended = prev_defended if prev_defended is not None else (round(asr, 6) if defense else None)
                merged_hits = self._merge_defense_hits(module, hits)
                self._conn.execute(
                    """
                    UPDATE findings
                    SET campaign_id = CASE WHEN campaign_id = '' THEN ? ELSE campaign_id END,
                        target = ?, status = ?, asr_bare = ?, asr_defended = ?, defense_hits = ?
                    WHERE module = ?
                    """,
                    (campaign_id, target, prev_status, bare, defended, merged_hits, module),
                )
            self._conn.commit()
        return module

    def _merge_defense_hits(self, module: str, hits: list[str]) -> str:
        """合并既有 defense_hits JSON 与新增命中（去重保序，调用方持锁）。"""
        row = self._conn.execute(
            "SELECT defense_hits FROM findings WHERE module = ?", (module,)
        ).fetchone()
        existing: list[str] = []
        if row and row[0]:
            try:
                existing = json.loads(row[0])
            except json.JSONDecodeError:
                existing = []
        return _safe_dumps(list(dict.fromkeys(existing + hits)))

    # ------------------------------------------------------------------ 读
    def list_campaigns(self, limit: int = 10) -> list[dict[str, Any]]:
        """最近 limit 次战役摘要（不含 markdown/rows）。"""
        rows = self._conn.execute(
            "SELECT id, ts, user_id, tenant_id, job_id, config, status, summary "
            "FROM campaigns ORDER BY ts DESC LIMIT ?",
            (max(1, limit),),
        ).fetchall()
        out = []
        for r in rows:
            out.append({
                "id": r[0], "ts": r[1], "user_id": r[2], "tenant_id": r[3], "job_id": r[4],
                "config": json.loads(r[5]) if r[5] else {},
                "status": r[6], "summary": json.loads(r[7]) if r[7] else {},
            })
        return out

    def get_campaign(self, campaign_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT id, ts, user_id, tenant_id, job_id, config, status, summary, markdown "
            "FROM campaigns WHERE id = ?",
            (campaign_id,),
        ).fetchone()
        if row is None:
            return None
        cid, ts, user_id, tenant_id, job_id, config, status, summary, markdown = row
        item = {
            "id": cid, "ts": ts, "user_id": user_id, "tenant_id": tenant_id, "job_id": job_id,
            "config": json.loads(config) if config else {},
            "status": status,
            "summary": json.loads(summary) if summary else {},
            "markdown": markdown or "",
        }
        runs = self._conn.execute(
            "SELECT id, module, variant, target, defense, verdict, asr, successes, blocked, failed, total, duration_ms "
            "FROM attack_runs WHERE campaign_id = ? ORDER BY id",
            (campaign_id,),
        ).fetchall()
        item["runs"] = [
            {
                "id": r[0], "module": r[1], "variant": r[2], "target": r[3],
                "defense": bool(r[4]), "verdict": r[5], "asr": r[6], "successes": r[7],
                "blocked": r[8], "failed": r[9], "total": r[10], "duration_ms": r[11],
            }
            for r in runs
        ]
        return item

    def get_run(self, run_id: int) -> dict[str, Any] | None:
        """run 级明细：attack_runs 行 + 该 run 的 traces / verdicts / costs（M4 结果视图）。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT id, campaign_id, module, variant, target, defense, verdict, asr, "
                "successes, blocked, failed, total, duration_ms FROM attack_runs WHERE id = ?",
                (run_id,),
            ).fetchone()
            if row is None:
                return None
            run: dict[str, Any] = {
                "id": row[0], "campaign_id": row[1], "module": row[2], "variant": row[3],
                "target": row[4], "defense": bool(row[5]), "verdict": row[6], "asr": row[7],
                "successes": row[8], "blocked": row[9], "failed": row[10], "total": row[11],
                "duration_ms": row[12],
            }
            run["traces"] = [
                {
                    "id": t[0], "module": t[1], "case_name": t[2],
                    "steps": json.loads(t[3]) if t[3] else [],
                    "blocked_calls": json.loads(t[4]) if t[4] else [],
                    "final_blocked": bool(t[5]), "final_block_reason": t[6],
                    "intent_flag": bool(t[7]),
                }
                for t in self._conn.execute(
                    "SELECT id, module, case_name, steps, blocked_calls, final_blocked, "
                    "final_block_reason, intent_flag FROM traces WHERE run_id = ? ORDER BY id",
                    (run_id,),
                ).fetchall()
            ]
            run["verdicts"] = [
                {
                    "id": v[0], "module": v[1], "case_name": v[2], "verdict": v[3],
                    "severity": v[4], "score": v[5], "reason": v[6],
                    "blind_spot": bool(v[7]), "capability_score": v[8],
                }
                for v in self._conn.execute(
                    "SELECT id, module, case_name, verdict, severity, score, reason, "
                    "blind_spot, capability_score FROM verdicts WHERE run_id = ? ORDER BY id",
                    (run_id,),
                ).fetchall()
            ]
            run["costs"] = [
                {
                    "id": c[0], "model": c[1], "prompt_tokens": c[2],
                    "completion_tokens": c[3], "total_tokens": c[4],
                    "unit_price": c[5], "total_cost": c[6], "llm_calls": c[7],
                }
                for c in self._conn.execute(
                    "SELECT id, model, prompt_tokens, completion_tokens, total_tokens, "
                    "unit_price, total_cost, llm_calls FROM costs WHERE run_id = ? ORDER BY id",
                    (run_id,),
                ).fetchall()
            ]
            return run

    def get_finding(self, module: str) -> FindingView | None:
        row = self._conn.execute(
            "SELECT module, campaign_id, target, status, asr_bare, asr_defended, "
            "capability_delta, defense_hits, repair_notes FROM findings WHERE module = ?",
            (module,),
        ).fetchone()
        if row is None:
            return None
        try:
            hits = json.loads(row[7]) if row[7] else []
        except json.JSONDecodeError:
            hits = []
        return FindingView({
            "module": row[0], "campaign_id": row[1], "target": row[2], "status": row[3],
            "asr_bare": row[4], "asr_defended": row[5], "capability_delta": row[6],
            "defense_hits": hits, "repair_notes": row[8],
        })

    def list_findings(self, limit: int = 100) -> list[FindingView]:
        rows = self._conn.execute(
            "SELECT module, campaign_id, target, status, asr_bare, asr_defended, "
            "capability_delta, defense_hits, repair_notes FROM findings ORDER BY status, module LIMIT ?",
            (max(1, limit),),
        ).fetchall()
        out = []
        for row in rows:
            try:
                hits = json.loads(row[7]) if row[7] else []
            except json.JSONDecodeError:
                hits = []
            out.append(FindingView({
                "module": row[0], "campaign_id": row[1], "target": row[2], "status": row[3],
                "asr_bare": row[4], "asr_defended": row[5], "capability_delta": row[6],
                "defense_hits": hits, "repair_notes": row[8],
            }))
        return out

    # ------------------------------------------------------------------ findings 状态机
    def set_finding_status(self, module: str, status: str, *, notes: str = "") -> FindingView:
        """按状态机规则迁移 finding；非法迁移抛 ValueError（M1 决策门：能标三态）。"""
        current = self.get_finding(module)
        if current is None:
            raise KeyError(f"finding 不存在: {module}")
        FindingStatus.transition(current.status, status)
        with self._lock:
            self._conn.execute(
                "UPDATE findings SET status = ?, repair_notes = ? WHERE module = ?",
                (status, notes, module),
            )
            self._conn.commit()
        return self.get_finding(module)  # type: ignore[return-value]

    def count_findings(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0])


    def record_matrix_row(
        self,
        row: dict[str, Any],
        *,
        campaign_id: str,
        target: str = "",
    ) -> str:
        """把 benchmark 矩阵行（含 vulnerable/defended 双侧 ASR）落库为 findings。"""
        module = str(row["module"])
        bare = float(row.get("vulnerable_success_rate", 0.0) or 0.0)
        defended = float(row.get("defended_success_rate", 0.0) or 0.0)
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO findings (module, campaign_id, target, status, asr_bare, asr_defended, defense_hits)
                VALUES (?, ?, ?, 'open', ?, ?, '[]')
                ON CONFLICT(module) DO UPDATE SET
                    asr_bare = excluded.asr_bare,
                    asr_defended = excluded.asr_defended,
                    target = excluded.target
                """,
                (module, campaign_id, target, bare, defended),
            )
            self._conn.commit()
        return module


def _verdict_score(verdict: str) -> float:
    """判定分数映射：success=1.0 / blocked=0.0 / failed=0.0（能力分另算）。"""
    return 1.0 if verdict == "success" else 0.0
