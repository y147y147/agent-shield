"""Phase C1：审计目标工厂 — 统一 local / http Target 构建。"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel, Field

from agent_shield.targets import HttpAgentTarget, build_local_target
from agent_shield.targets.base import AgentTarget
from agent_shield.targets.mcp import MCPAgentTarget

TargetFactory = Callable[..., AgentTarget]


class AuditTargetSpec(BaseModel):
    """审计会话的目标配置。"""

    model_config = {"arbitrary_types_allowed": True}

    kind: Literal["local", "http", "mcp"] = "local"
    # local / mcp 靶场
    llm: str = "mock"
    model: str | None = None
    api_key: str | None = None
    api_base_url: str | None = None
    sandbox: bool = False
    audit_store: Any = None
    event_sink: Any = None
    judge_llm: Any = None
    # http 黑盒
    target_url: str | None = None
    defense_target_url: str | None = None
    timeout: float = Field(default=60.0, gt=0)
    # mcp
    mcp_url: str | None = None
    mcp_timeout: float = Field(default=30.0, gt=0)
    # 测试注入（生产环境不传）
    transport: Any = None

    @property
    def is_blackbox(self) -> bool:
        return self.kind == "http"

    @property
    def is_mcp(self) -> bool:
        return self.kind == "mcp"

    def validate_for_run(self) -> None:
        if self.kind == "http" and not self.target_url:
            raise ValueError("http 目标需指定 target_url（CLI: --url；Web: target_url 字段）")
        if self.kind == "mcp" and not self.mcp_url:
            raise ValueError("mcp 目标需指定 mcp_url（CLI: --mcp-url；Web: mcp_url 字段）")


def build_audit_target_factory(spec: AuditTargetSpec) -> TargetFactory:
    """根据 ``AuditTargetSpec`` 返回 ``target_factory(defense=...)`` 可调用对象。"""
    spec.validate_for_run()

    if spec.kind == "mcp":
        def factory(*, defense: bool = False) -> AgentTarget:
            return MCPAgentTarget(
                mcp_url=spec.mcp_url or "",
                llm=spec.llm,
                defense=defense,
                model=spec.model,
                api_key=spec.api_key,
                base_url=spec.api_base_url,
                audit_store=spec.audit_store,
                sandbox=spec.sandbox,
                event_sink=spec.event_sink,
                judge_llm=spec.judge_llm,
                timeout=spec.mcp_timeout,
                transport=spec.transport,
            )

        return factory

    def factory(*, defense: bool = False) -> AgentTarget:
        if spec.kind == "local":
            return build_local_target(
                llm=spec.llm,
                defense=defense,
                model=spec.model,
                api_key=spec.api_key,
                base_url=spec.api_base_url,
                audit_store=spec.audit_store,
                sandbox=spec.sandbox,
                event_sink=spec.event_sink,
                judge_llm=spec.judge_llm,
            )

        url = spec.defense_target_url if defense and spec.defense_target_url else spec.target_url
        assert url  # validated in validate_for_run
        if defense and spec.defense_target_url:
            name = "http-agent-defended"
            description = f"HTTP 黑盒（加固端点）— {url}"
        else:
            name = "http-agent"
            description = f"HTTP 黑盒 — {url}"
        return HttpAgentTarget(
            base_url=url,
            timeout=spec.timeout,
            name=name,
            description=description,
            transport=spec.transport,
        )

    return factory


def resolve_audit_options(
    spec: AuditTargetSpec,
    *,
    compare_defense: bool,
    include_mock_only: bool,
) -> tuple[bool, bool, list[str]]:
    """按目标类型解析攻防对比与 mock_only 策略，返回 (compare_defense, include_mock_only, notes)。"""
    notes: list[str] = []
    inc = include_mock_only
    cmp = compare_defense

    if spec.is_blackbox:
        if inc:
            notes.append("黑盒 HTTP 目标已自动排除 mock_only 模块（如 rogue_agent）。")
        inc = False
        if cmp and not spec.defense_target_url:
            notes.append("HTTP 黑盒未配置 defense_target_url，已关闭加固前后对比。")
            cmp = False

    if spec.is_mcp:
        notes.append(f"MCP 靶场：远程工具来自 {spec.mcp_url}，与本地默认工具合并。")

    return cmp, inc, notes
