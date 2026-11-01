"""M3 修复闭环：防线命中定位 → 修复建议 → 三连测回归（决策门自动化）。"""

from __future__ import annotations

from agent_shield.repair.cases import (
    BlindSpotCase,
    TargetSpec,
    get_blind_spot,
    list_blind_spots,
)
from agent_shield.repair.loop import (
    RepairConfig,
    RepairGate,
    RepairReport,
    collect_defense_hits,
    evaluate_gates,
    locate_defense_hits,
    run_repair,
)

__all__ = [
    "BlindSpotCase",
    "RepairConfig",
    "RepairGate",
    "RepairReport",
    "TargetSpec",
    "collect_defense_hits",
    "evaluate_gates",
    "get_blind_spot",
    "list_blind_spots",
    "locate_defense_hits",
    "run_repair",
]
