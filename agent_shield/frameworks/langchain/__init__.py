"""LangChain 适配：把 AgentShield 的靶场 / 工具 / 防御接到真实 LangChain AgentExecutor 上。

目标（Phase 4 最小可验证版）：
- **真实框架面**：用 LangChain 的 ``AgentExecutor`` + ``create_tool_calling_agent`` 跑智能体，
  工具用 ``StructuredTool`` 表达，agent 循环消息用 ``BaseMessage``（System/Human/AI/Tool）。
- **复用现有资产**：攻击模块、`MockLLM` / `OpenAICompatLLM`、注入检测器等防御防、`AgentTrace`
  评估口径均不重造 —— 本适配只把"AgentShield 工具带"武装成 LangChain 工具，并把防御钩子
  挂在工具执行前后。
- **离线可回归**：``llm="mock"`` 且 target 内仍走确定性决策；未安装 langchain 时本模块
  import 不炸（见 ``available``）。

本模块只依赖 ``langchain`` / ``langchain_core`` 的可选导入，调用前应先判 ``available()``。
"""

from __future__ import annotations

from agent_shield.frameworks.langchain.tools import (
    available,
    build_langchain_target,
    langchain_import_error,
)

__all__ = ["available", "build_langchain_target", "langchain_import_error"]