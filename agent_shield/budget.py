"""M5 成本门禁：模型单价表（可配置）+ 费用换算 + 任务/日预算门禁（超限刹停）。

计划书 §7（成本计量与门禁）落地：
1. 计量：每次真实模型调用记 prompt/completion tokens（trace 已含，costs 表已落库）；
2. 换算：内置单价表 PRICING（deepseek-chat/reasoner、qwen-plus 等；价格单位 = 每 token，
   数值与既有 usage.py 三档完全一致避免回归），``set_pricing`` 运行时覆盖（单价可配置）；
3. 门禁：:class:`CostBudget` —— 每任务预算上限 + 每日总预算（跨 campaign 求和，经
   ``Store.total_cost_since`` 注入），累计超限抛 :class:`CostBudgetExceeded` 刹停，
   由调用方捕获后落库 aborted 战役 + costs 告警（``Store.record_cost_alert``）；
4. 隔离：user_id/tenant_id 预留（M5 仅预留，不实现多租户配额）；
5. 硬约束：API key 由用户自带、不经助手处理、不明文入库（沿用既有约定）。

CLI 预算参数以「元」为单位（计划书 §7③"单模块 1 轮 ≤N 元"），内部换算 USD。
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

# --------------------------------------------------------------------------- #
# 单价表（USD / token；每 1K token 费用 = 单价 × 1000）
# --------------------------------------------------------------------------- #
# 与 usage.py 旧三档对齐：gpt-4 → (0.03, 0.06)；deepseek* → (0.00014, 0.00028)；
# 其余 → DEFAULT_PRICE (0.001, 0.002)。此处细化到模型名，便于 set_pricing 定向覆盖。
PRICING: dict[str, tuple[float, float]] = {
    "deepseek-chat": (0.00014, 0.00028),
    "deepseek-reasoner": (0.00014, 0.00028),
    "qwen-plus": (0.001, 0.002),
}
DEFAULT_PRICE: tuple[float, float] = (0.001, 0.002)  # 未知模型通用单价

# set_pricing 覆盖前保留出厂档，reset_pricing 可还原
_BUILTIN_PRICING: dict[str, tuple[float, float]] = dict(PRICING)

# CLI 元 → USD 汇率（固定常量，仅用于预算换算；精确费用以 API 回包 usage 计价）
USD_PER_CNY = 0.14


def set_pricing(model: str, input_price: float, output_price: float) -> None:
    """运行时覆盖某个模型的单价（每 token，USD）—— 单价可配置（§7②）。"""
    PRICING[model.strip().lower()] = (float(input_price), float(output_price))


def reset_pricing() -> None:
    """还原出厂单价表（测试/恢复用）。"""
    PRICING.clear()
    PRICING.update(dict(_BUILTIN_PRICING))


def _lookup_price(model: str) -> tuple[float, float]:
    """取某模型的单价：精确 → 既有 gpt-4/deepseek 子串规则 → 默认档。"""
    m = (model or "").lower()
    if m in PRICING:
        return PRICING[m]
    if "gpt-4" in m:
        return (0.03, 0.06)
    if "deepseek" in m:
        return PRICING["deepseek-chat"]
    return DEFAULT_PRICE


def estimate_cost_usd(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    """粗算一次调用的费用（USD）；未知模型按通用单价。"""
    inp, out = _lookup_price(model)
    return (int(prompt_tokens) * inp + int(completion_tokens) * out) / 1000.0


def cny_to_usd(yuan: float) -> float:
    """预算换算：元 → USD（固定汇率常量，仅门禁预算用）。"""
    return float(yuan or 0.0) * USD_PER_CNY


def today_start_ts() -> float:
    """当日 00:00 的 epoch 秒（每日总预算的统计起点）。"""
    lt = time.localtime()
    return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1))


# --------------------------------------------------------------------------- #
# 门禁
# --------------------------------------------------------------------------- #
class CostBudgetExceeded(Exception):
    """成本门禁超限：任务被刹停；由调用方捕获后落库 aborted 战役 + costs 告警。"""

    def __init__(self, kind: str, limit: float, spent: float) -> None:
        self.kind = kind  # "task" | "daily"
        self.limit = float(limit)
        self.spent = float(spent)
        super().__init__(f"成本门禁超限({kind}): 已花 ${self.spent:.6f} > 预算 ${self.limit:.6f}")

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "limit_usd": round(self.limit, 6),
                "spent_usd": round(self.spent, 6), "message": str(self)}


@dataclass
class CostBudget:
    """任务级成本门禁：累计已花费用，超限抛 :class:`CostBudgetExceeded` 并置 exceeded。

    - task_budget_usd：本次任务的预算上限（None=不限）；
    - daily_budget_usd：每日总预算上限（含库中今日已用；None=不限）；
    - initial_daily_spent：构造时经 ``Store.total_cost_since(today_start_ts())`` 注入
      的跨 campaign 今日已用（daily 预算只在有持久库时才有意义）。
    """

    task_budget_usd: float | None = None
    daily_budget_usd: float | None = None
    initial_daily_spent: float = 0.0
    task_spent: float = 0.0
    daily_spent: float = 0.0
    exceeded: bool = False
    exceeded_kind: str | None = None
    exceeded_limit: float = 0.0

    def __post_init__(self) -> None:
        self.daily_spent = float(self.initial_daily_spent or 0.0)

    @property
    def enabled(self) -> bool:
        return self.task_budget_usd is not None or self.daily_budget_usd is not None

    def spend(self, cost: float, *, model: str = "") -> float:
        """记一笔费用并检查门禁；超限抛 CostBudgetExceeded 并置 exceeded 标志。"""
        cost = float(cost or 0.0)
        if cost < 0:
            cost = 0.0
        self.task_spent += cost
        self.daily_spent += cost
        if self.task_budget_usd is not None and self.task_spent > self.task_budget_usd:
            self._raise_exceeded("task", self.task_budget_usd, self.task_spent)
        if self.daily_budget_usd is not None and self.daily_spent > self.daily_budget_usd:
            self._raise_exceeded("daily", self.daily_budget_usd, self.daily_spent)
        return cost

    def spend_trace(self, trace: Any) -> float:
        """把一条轨迹（AgentTrace）的估算费用入账（trace.estimated_cost_usd）。"""
        cost = float(getattr(trace, "estimated_cost_usd", 0.0) or 0.0)
        return self.spend(cost, model=str(getattr(trace, "model", "") or ""))

    def spend_result(self, result: Any) -> float:
        """把一次攻击结果（AttackResult）全部 case 的轨迹费用入账。"""
        total = 0.0
        for case in getattr(result, "cases", []):
            trace = getattr(case, "trace", None)
            if trace is not None:
                total += self.spend_trace(trace)
        return total

    def _raise_exceeded(self, kind: str, limit: float, spent: float) -> None:
        self.exceeded = True
        self.exceeded_kind = kind
        self.exceeded_limit = float(limit)
        raise CostBudgetExceeded(kind, limit, spent)
