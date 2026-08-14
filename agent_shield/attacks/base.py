"""攻击模块基类与配置。"""

from __future__ import annotations

from abc import ABC, abstractmethod

from pydantic import BaseModel, Field

from agent_shield.models import AttackResult
from agent_shield.targets.base import AgentTarget


class AttackConfig(BaseModel):
    """一次攻击测试的通用配置。"""

    task: str = "请帮我搜索「2025 年全球气候报告」并总结要点。"
    num_variants: int = 3
    params: dict = Field(default_factory=dict)  # 模块自定义参数


class AttackModule(ABC):
    """攻击模块接口：每个攻击向量 = 一个模块（载荷生成 + 执行 + 判定）。"""

    name: str = "base"
    description: str = ""
    atlas_id: str | None = None
    owasp_asi: str | None = None

    @abstractmethod
    async def run(self, target: AgentTarget, config: AttackConfig) -> AttackResult:
        """对目标执行攻击测试并返回结果。"""
