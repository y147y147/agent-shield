"""E3：指挥官 LLM 调用用量聚合（token / 估算费用）。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_shield.models import ChatMessage
from agent_shield.runtime.llm import LLMClient, LLMResponse


@dataclass
class LLMUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
        }


@dataclass
class UsageAccumulator:
    """会话级指挥官用量累计。"""

    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0
    per_call: list[dict[str, Any]] = field(default_factory=list)

    def record(self, usage: LLMUsage | dict[str, int] | None, *, model: str = "") -> None:
        if usage is None:
            return
        if isinstance(usage, dict):
            u = LLMUsage(
                prompt_tokens=int(usage.get("prompt_tokens") or 0),
                completion_tokens=int(usage.get("completion_tokens") or 0),
                total_tokens=int(usage.get("total_tokens") or 0),
            )
        else:
            u = usage
        self.calls += 1
        self.prompt_tokens += u.prompt_tokens
        self.completion_tokens += u.completion_tokens
        self.total_tokens += u.total_tokens or (u.prompt_tokens + u.completion_tokens)
        cost = estimate_cost_usd(model, u)
        self.estimated_cost_usd += cost
        self.per_call.append(
            {
                "model": model,
                "usage": u.to_dict(),
                "estimated_cost_usd": round(cost, 6),
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "calls": self.calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "estimated_cost_usd": round(self.estimated_cost_usd, 6),
            "per_call": list(self.per_call),
        }


def estimate_tokens_from_messages(messages: list[ChatMessage]) -> int:
    chars = sum(len(m.content or "") for m in messages)
    return max(1, chars // 4)


def estimate_cost_usd(model: str, usage: LLMUsage) -> float:
    """粗算费用（USD）；未知模型按通用单价。"""
    m = (model or "").lower()
    if "gpt-4" in m:
        inp, out = 0.03, 0.06
    elif "deepseek" in m:
        inp, out = 0.00014, 0.00028
    else:
        inp, out = 0.001, 0.002
    return (usage.prompt_tokens * inp + usage.completion_tokens * out) / 1000.0


class UsageTrackingPlanner:
    """包装指挥官 LLM，累计每次 chat 的 token 用量。"""

    def __init__(self, inner: LLMClient, accumulator: UsageAccumulator | None = None) -> None:
        self._inner = inner
        self.accumulator = accumulator or UsageAccumulator()

    @property
    def name(self) -> str:
        return getattr(self._inner, "name", "wrapped")

    async def chat(self, messages: list[ChatMessage], tools: list) -> LLMResponse:
        response = await self._inner.chat(messages, tools)
        usage = response.usage
        if usage is None and hasattr(self._inner, "last_usage"):
            usage = getattr(self._inner, "last_usage", None)
        if usage is None:
            est = estimate_tokens_from_messages(messages)
            usage = LLMUsage(
                prompt_tokens=est,
                completion_tokens=20,
                total_tokens=est + 20,
            ).to_dict()
        model = getattr(self._inner, "model", self.name)
        self.accumulator.record(usage, model=str(model))
        return response
