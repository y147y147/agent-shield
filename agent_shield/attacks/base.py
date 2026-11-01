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
    # C1 载荷库：同一 seed 下扩展/采样可复现；None 表示用 YAML 家族自带 seed。
    seed: int | None = None
    # C1/B5：限制/扩展编码面（如 ["plain"] 则只跑原文；None 表示用 YAML 各 variant 声明）。
    encodings: list[str] | None = None
    # C2 变异器：True 时用 mutator 确定性扩展到 num_variants 条（含编码变换+去重）。
    mutate: bool = False
    # C3 自适应绕过：按防护反馈逐轮换编码重试（见 agent_shield/attacks/adaptive.py）。
    adaptive: bool = False
    adaptive_rounds: int = 3
    adaptive_budget: int = 9


def effective_payload_options(config: AttackConfig) -> tuple[int | None, list[str] | None, bool]:
    """从 AttackConfig 解析载荷选项，顶层字段优先，回退到 params（兼容编排层透传）。"""
    params = config.params or {}
    seed = config.seed if config.seed is not None else params.get("seed")
    encodings = config.encodings if config.encodings is not None else params.get("encodings")
    mutate = bool(config.mutate or params.get("mutate", False))
    if seed is not None:
        seed = int(seed)
    if encodings is not None:
        encodings = [str(e) for e in encodings]
    return seed, encodings, mutate


def effective_adaptive_options(config: AttackConfig) -> tuple[bool, int, int]:
    """解析自适应选项，顶层字段优先，回退到 params。"""
    params = config.params or {}
    adaptive = bool(config.adaptive or params.get("adaptive", False))
    rounds = config.adaptive_rounds
    if params.get("adaptive_rounds") is not None:
        rounds = int(params["adaptive_rounds"])
    budget = config.adaptive_budget
    if params.get("adaptive_budget") is not None:
        budget = int(params["adaptive_budget"])
    return adaptive, max(1, rounds), max(1, budget)


class AttackModule(ABC):
    """攻击模块接口：每个攻击向量 = 一个模块（载荷生成 + 执行 + 判定）。"""

    name: str = "base"
    description: str = ""
    atlas_id: str | None = None
    owasp_asi: str | None = None
    # 需要控制智能体内部状态才能模拟的攻击（如 ASI-10 内部失控）：
    # 对黑盒真实 API 模型不可测，仅在本地 Mock 靶场生效。
    mock_only: bool = False
    # 已知防线盲区：攻击路径落在防线"允许集"内（如工作目录内读取）或
    # 走无守卫的通道（如 final_answer），加固后 ASR 仍可能 > 0。
    # 基准评测据此把"加固后全 0"的断言只作用于可拦截模块（如实报告盲区）。
    defense_blind_spot: bool = False

    @abstractmethod
    async def run(self, target: AgentTarget, config: AttackConfig) -> AttackResult:
        """对目标执行攻击测试并返回结果。"""
