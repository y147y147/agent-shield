"""LangChain 工具适配与 target 构建入口。

注意事项：
- 依赖惰性导入：``runtime.tools`` / ``defenses`` 若在包加载早期被首次触碰会触发
  既有循环导入（``runtime.tools -> defenses -> tool_integrity -> runtime.tools``）。
  因此这里顶层不 import 它们，全部在函数体内惰性导入，保证 ``import agent_shield``
  与任意导入顺序下都安全（Phase 4 红线：未装 / 随便 import 不炸）。
- ``available`` / ``langchain_import_error``：外部判框架是否可用，未装 langchain 时
  相关 target / 测试自动跳过。
"""

from __future__ import annotations

from typing import Any


def available() -> bool:
    """LangChain v1 create_agent 是否可用（可选依赖）。"""
    try:
        import langchain  # noqa: F401
        import langchain_core  # noqa: F401
        from langchain.agents import create_agent  # noqa: F401

        return True
    except Exception:
        return False


def langchain_import_error() -> str:
    return (
        "LangChain v1（create_agent）未安装；"
        '请 `pip install "agent-shield[langchain]"` 后重试'
    )


def _ensure_langchain() -> None:
    if not available():
        raise ImportError(langchain_import_error())


def build_langchain_target(
    llm: str = "mock",
    defense: bool = False,
    model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    tools: Any = None,
    judge_llm: Any = None,
    system_prompt: str | None = None,
    max_steps: int = 12,
) -> Any:
    """构建"跑在真实 LangChain create_agent（LangGraph）上"的靶场目标。

    签名对齐 ``agent_shield.targets.local.build_local_target``，便于攻击模块 / campaign
    无差别调用（``llm`` 支持 mock / openai-compat）。

    - llm="mock"：LangChainMockModel（包装现有 MockLLM 决策引擎）离线确定；
    - llm="openai-compat"：langchain-openai ``ChatOpenAI`` 接真实模型；
    - defense=True：在 LangChain 工具执行前后挂与 LocalAgentTarget **同一套** guardrails
      （注入检测器 + 策略引擎 + 预算 + 行为层），注入检测器信号集可经 ``signals`` 定制
      （弱防护用 ``redteam.weak_signals``）。
    """
    from agent_shield.frameworks.langchain.target import build_langchain_executor

    _ensure_langchain()
    return build_langchain_executor(
        llm=llm,
        defense=defense,
        model=model,
        api_key=api_key,
        base_url=base_url,
        tools=tools,
        judge_llm=judge_llm,
        system_prompt=system_prompt,
        max_steps=max_steps,
    )