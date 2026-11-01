"""外部 Agent 框架适配层（可选的扩展能力）。

目前仅含 LangChain（``agent_shield.frameworks.langchain``）。这是"用真实框架跑
AgentShield 靶场"的桥：把 AgentShield 的 AgentTarget / 工具 / 防御防挂在真实框架上，
仍复用现有攻击模块与倒置回归 —— 离线 mock 可跑，真实模型可选。

框架依赖均放在可选分组（如 ``[langchain]``），**非硬依赖**：未安装时 `import agent_shield`
照常可用，相关 target / 测试自动跳过（见各框架子包的 ``available`` 守卫）。
"""