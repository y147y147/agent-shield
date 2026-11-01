"""M1 数据层：SQLite 落库（计划书 §5 六表）+ findings 状态机。

与既有 ``agent_shield.campaign_store``（仅存战役聚合战报，2 张表）职责不同：
本模块承载「LLM 攻击智能体」产品化所需的完整闭环数据 —— 逐 run 的
traces / verdicts / costs 明细与 findings 修复闭环状态机，供 M2（self_improve）、
M3（repair）、M4（Web 控制台）直接复用。schema 预留 user_id / tenant_id / job_id
隔离字段（§6），本地单机时均为 0。
"""

from __future__ import annotations

from agent_shield.store.campaigns import (
    FindingStatus,
    FindingView,
    Store,
    default_attack_db_path,
)

__all__ = [
    "FindingStatus",
    "FindingView",
    "Store",
    "default_attack_db_path",
]
