# 架构说明

## 分层

```
CLI (agent_shield/cli.py)
  └─ attacks/           攻击模块（插件化）
       └─ targets/      Target 适配层 —— 攻击框架与任意智能体的统一接口
            └─ runtime/ 智能体运行时（工具调用循环）
                 ├─ llm/     LLM 客户端（Mock / OpenAI 兼容）
                 ├─ tools/   工具注册表与内置工具
                 └─ defenses/ 防护层 GuardRail（策略检查 + 输出清洗）
```

## 关键抽象

### AgentTarget（targets/base.py）

攻击框架与"被测对象"之间的唯一接口：

```python
class AgentTarget(ABC):
    async def run(self, task: str) -> AgentTrace   # 执行任务，返回完整轨迹
    def inject_tool_payload(self, tool, payload)    # 模拟攻击者控制的工具内容
```

好处：未来接入 HTTP Agent、LangChain Agent、MCP Server 只需新增一个 Target 实现，
攻击模块完全不需要改动。

### AgentRuntime（runtime/agent.py）

通用的工具调用循环，是**防护层的注入点**（所有 GuardRail 钩子均为 async）：

```
用户输入 ──► await guardrails.sanitize_user_input(task)   # 直接注入防御
LLM 决定下一步
  ├─ 无工具调用 → 最终回答，结束
  └─ 有工具调用 → 对每个调用:
       1. await guardrails.check_tool_call(call)       # 策略引擎：拦截则记录 BlockedCall
       2. await tools.execute(call)                    # 执行工具
       3. await guardrails.sanitize_tool_output(...)   # 注入检测器：清洗输出
       4. 结果回填对话，继续下一轮
```

每一轮都落一条 TraceStep（消息、工具调用、工具输出、拦截记录），
这是攻击判定、取证与审计的数据基础。`AgentTrace.executed_tool_calls()`
只统计"真正执行成功"的调用（有工具输出），被策略拦截的调用不计入 ——
攻击判定因此不会把"被拦截的尝试"误判为攻击成功。

### GuardRail（defenses/base.py）

```python
class GuardRail(ABC):
    async def check_tool_call(self, call) -> ToolCallDecision   # allow / deny
    async def sanitize_tool_output(self, call, output) -> str    # 工具输出清洗
    async def sanitize_user_input(self, text) -> str             # 用户输入清洗
```

内置实现：
- `InjectionDetector`：规则快路径（正则信号 → 按行脱敏）；
- `LLMJudgeDetector`：慢路径，用另一个 LLM 判定（隔离的固定格式提示词 + 缓存）；
- `PolicyEngine`：类 WAF 规则，危险工具失败关闭（fail-closed）。

新增防御手段 = 实现 GuardRail 并加入列表，运行时零改动。

### MITM 审计代理（proxy/）

不修改智能体代码，把代理插在"智能体 ↔ LLM API"之间：

- 入站 /v1/chat/completions → 检测工具输出中的注入信号；
- audit：只记录；sanitize：记录 + 清洗后转发；block：记录 + 403；
- 全部事件写入 SQLite（AuditStore），GET /audit/latest 可查。

### MCP 连接器（connectors/mcp.py）

最小 JSON-RPC 客户端（initialize / tools/list / tools/call，HTTP transport），
把远程 MCP server 的工具接入 ToolRegistry —— MCP 工具的输出同样经过
注入检测与策略防护（MCP server 是攻击者可控的，见 AML.T0104 工具投毒）。

### AttackModule（attacks/base.py）

```python
class AttackModule(ABC):
    name / description / atlas_id / owasp_asi
    async def run(self, target, config) -> AttackResult
```

模块 = 载荷生成 + 执行 + 判定三段式；用 `@register` 注册进全局表。

## 数据流（间接注入示例）

```
attacker payload ──> inject_tool_payload("web_search", payload)
                         │
                         ▼
target.run(task) ──> AgentRuntime 循环
                         │
         web_search 返回: 正常内容 + [页面正文摘录] payload
                         │
         ┌───────────────┴─────────────────────┐
         │ 无防护                              │ 有防护
         │                                     │
         ▼                                     ▼
  payload 直通 LLM ──► LLM 执行指令 ──► run_command(touch ...)
                                              │
         judge: has_tool_call(run_command, command=marker)
         ──► SUCCESS (Critical)        ──► 指令被 REDACTED → FAILED
                                         或 调用被拦截 → BLOCKED
```

## 设计取舍

- **MockLLM 的意义**：真实 LLM 对间接注入的响应具有随机性，无法做确定性 CI。
  MockLLM 用规则复现"模型把工具输出中的指令当权威指令执行"这一缺陷，
  使攻防闭环 100% 可复现。真实模型路径（OpenAICompatLLM）用于量化真实成功率。
- **失败关闭（fail-closed）策略**：危险工具（如 run_command）默认拒绝，
  仅放行白名单命令 —— 与真实 WAF/沙箱的设计一致。
- **判定不依赖防御模块**：攻击模块的 judge 只看轨迹事实（是否执行了标记命令），
  避免"自己测自己"的循环论证。

## 相关文档

- [自主安全审计智能体 — 执行文档](autonomous-audit-agent.md) —— 在现有武器库之上补「规划与决策层」
  （Plan-and-Execute → ReAct）的缺口对照、接口草案与验收标准。当前仓库尚未实现
  Orchestrator；靶场 `AgentRuntime` 的 tool-calling 循环与审计指挥官循环是两层概念。
