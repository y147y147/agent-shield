"""核心数据模型：Agent 轨迹、攻击用例、结果与评分。"""

from __future__ import annotations

import time
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# Agent 运行时轨迹
# --------------------------------------------------------------------------- #
class ChatMessage(BaseModel):
    """一条对话消息。role 使用 Literal 便于直接序列化为 API 载荷。"""

    role: str  # "system" | "user" | "assistant" | "tool"
    content: str | None = None
    # 工具结果消息：对应哪次工具调用
    tool_call_id: str | None = None
    name: str | None = None
    # assistant 消息发起的工具调用（OpenAI 协议需要回传）
    tool_calls: list[ToolCall] | None = None

    @classmethod
    def system(cls, content: str) -> ChatMessage:
        return cls(role="system", content=content)

    @classmethod
    def user(cls, content: str) -> ChatMessage:
        return cls(role="user", content=content)

    @classmethod
    def assistant(cls, content: str | None, tool_calls: list[ToolCall] | None = None) -> ChatMessage:
        return cls(role="assistant", content=content, tool_calls=tool_calls)

    @classmethod
    def tool(cls, content: str, tool_call_id: str, name: str | None = None) -> ChatMessage:
        return cls(role="tool", content=content, tool_call_id=tool_call_id, name=name)


class ToolCall(BaseModel):
    """一次工具调用请求。"""

    id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class BlockedCall(BaseModel):
    """被防护层拦截的工具调用（审计用）。"""

    tool_call_id: str
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""


class TraceStep(BaseModel):
    """Agent 循环中的一轮：发送的消息 -> 工具调用 -> 工具输出 / 最终回答。"""

    messages: list[ChatMessage] = Field(default_factory=list)
    tool_calls: list[ToolCall] = Field(default_factory=list)
    tool_outputs: list[ChatMessage] = Field(default_factory=list)
    blocked_calls: list[BlockedCall] = Field(default_factory=list)
    final_answer: str | None = None


class AgentTrace(BaseModel):
    """一次 Agent 任务的完整执行轨迹（取证/评分的数据基础）。"""

    task: str
    started_at: float = Field(default_factory=time.time)
    duration_ms: int = 0
    steps: list[TraceStep] = Field(default_factory=list)
    final_answer: str | None = None

    def all_tool_calls(self) -> list[ToolCall]:
        return [tc for step in self.steps for tc in step.tool_calls]

    def all_tool_outputs(self) -> list[ChatMessage]:
        return [msg for step in self.steps for msg in step.tool_outputs]

    def blocked_calls(self) -> list[BlockedCall]:
        return [bc for step in self.steps for bc in step.blocked_calls]

    def has_tool_call(self, name: str, **fragments: str) -> bool:
        """是否调用过指定工具，且参数中包含全部给定片段（fragment 子串匹配）。"""
        for tc in self.all_tool_calls():
            if tc.name != name:
                continue
            if all(frag in str(tc.arguments.get(k, "")) for k, frag in fragments.items()):
                return True
        return False

    def has_final_text(self, needle: str) -> bool:
        return bool(self.final_answer and needle in self.final_answer)


# --------------------------------------------------------------------------- #
# 攻击结果与评分
# --------------------------------------------------------------------------- #
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackVerdict(str, Enum):
    SUCCESS = "success"  # 攻击生效
    BLOCKED = "blocked"  # 攻击被防护层拦截
    FAILED = "failed"  # 攻击未生效


class AttackCase(BaseModel):
    """一次攻击尝试（一个载荷变体对目标的一次执行）。"""

    module: str = ""
    name: str = ""
    payload: str = ""
    verdict: AttackVerdict = AttackVerdict.FAILED
    severity: Severity = Severity.INFO
    evidence: list[str] = Field(default_factory=list)
    trace: AgentTrace | None = None


class AttackResult(BaseModel):
    """一个攻击模块对目标的一次完整测试结果。"""

    module: str
    description: str = ""
    atlas_id: str | None = None
    owasp_asi: str | None = None
    cases: list[AttackCase] = Field(default_factory=list)
    duration_ms: int = 0

    @property
    def total(self) -> int:
        return len(self.cases)

    @property
    def successes(self) -> int:
        return sum(1 for c in self.cases if c.verdict == AttackVerdict.SUCCESS)

    @property
    def blocked(self) -> int:
        return sum(1 for c in self.cases if c.verdict == AttackVerdict.BLOCKED)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.cases if c.verdict == AttackVerdict.FAILED)

    @property
    def success_rate(self) -> float:
        return self.successes / self.total if self.total else 0.0

    @property
    def criticals(self) -> int:
        return sum(1 for c in self.cases if c.severity == Severity.CRITICAL)

    def summary(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "atlas_id": self.atlas_id,
            "owasp_asi": self.owasp_asi,
            "total": self.total,
            "successes": self.successes,
            "blocked": self.blocked,
            "failed": self.failed,
            "success_rate": round(self.success_rate, 4),
            "criticals": self.criticals,
            "duration_ms": self.duration_ms,
        }
