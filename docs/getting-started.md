# 使用指南

## 安装

```bash
cd agent-shield
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## 一分钟体验（离线）

```bash
agent-shield demo
```

输出：脆弱靶场被间接注入攻陷（成功率 100%，Critical）→ 启用防护后全部失败（0%）。

## 常用命令

```bash
agent-shield modules                          # 查看可用攻击模块
agent-shield attack                           # 间接注入（默认）
agent-shield attack -m direct_injection       # 直接注入
agent-shield attack -m privilege_escalation   # 越权
agent-shield attack --defense                 # 防护后重跑
agent-shield attack --defense --judge-model deepseek-chat   # 再加 LLM-as-Judge 检测
agent-shield attack -n 5 --json report.json   # 5 个变体 + 输出 JSON 报告
```

`attack` 命令在发现漏洞（存在 success 用例）时以退出码 1 结束 —— 可接入 CI
做"智能体上线前安全检查"。

## MITM 审计代理

```bash
# 离线演示（Mock 上游，不需要 API Key）
agent-shield proxy --port 8090 --mock-upstream
# 生产：转发到真实上游
agent-shield proxy --port 8090 --upstream https://api.deepseek.com/v1

# 然后把智能体的 LLM Base URL 指向 http://127.0.0.1:8090/v1
# 审计事件：GET http://127.0.0.1:8090/audit/latest 或直接查 SQLite
sqlite3 proxy_audit.db "select * from audit_events order by ts desc limit 10;"
```

模式：`--mode audit`（只记录）/ `sanitize`（记录+清洗，默认）/ `block`（记录+拦截 403）。

## MCP 审计

```bash
agent-shield mcp --url http://127.0.0.1:8080/mcp    # 列出 MCP server 暴露的工具
```

代码接入（工具输出自动流过防护层）：

```python
from agent_shield.connectors.mcp import connect_mcp
from agent_shield.targets import build_local_target

client, registry = await connect_mcp("http://127.0.0.1:8080/mcp")
target = build_local_target(llm="mock", defense=True, tools=registry)
trace = await target.run("请搜索并总结")
```

## 打真实模型

```bash
export OPENAI_API_KEY=sk-xxx
# DeepSeek
agent-shield attack --llm openai-compat --model deepseek-chat \
    --base-url https://api.deepseek.com/v1 -n 5
# 本地 Ollama
agent-shield attack --llm openai-compat --model qwen2.5:7b \
    --base-url http://localhost:11434/v1 -n 5
```

## 基准评测（一键矩阵）

```bash
agent-shield benchmark                 # 7 个攻击向量 × 加固前后成功率
agent-shield benchmark --markdown bench.md --json bench.json
agent-shield benchmark --llm openai-compat --model deepseek-chat   # 真实模型
```

## Web 审计看板

```bash
# 先让代理/运行时产生审计事件（SQLite）
agent-shield proxy --port 8090 --mock-upstream --db proxy_audit.db
# 再开看板
agent-shield dashboard --db proxy_audit.db --port 8085
# 浏览器打开 http://127.0.0.1:8085（自动刷新 5s）
```

## HTTP 黑盒靶场（远程测试）

```bash
agent-shield http-agent --port 8000 --defense      # 起一个 HTTP 智能体服务
# 另一端用 HttpAgentTarget 黑盒测试（无法注入工具内容，走任务型攻击）：
```

```python
import httpx
from agent_shield.attacks import AttackConfig, DirectInjectionAttack
from agent_shield.targets import HttpAgentTarget

target = HttpAgentTarget("http://127.0.0.1:8000")
result = await DirectInjectionAttack().run(target, AttackConfig(num_variants=3))
```

Docker 一键起靶场 + 看板：`docker compose up --build`（见 docker-compose.yml）。

## 自定义策略

策略引擎支持 YAML 覆写默认策略（默认失败关闭）：

```yaml
# policy.yaml
run_command:
  action: deny
  allow:
    - "^(ls|cat|pwd|whoami|echo)\\b.*"
  deny:
    - "rm\\s+-rf"
web_search:
  action: allow
```

```python
from agent_shield.defenses import PolicyEngine
engine = PolicyEngine.from_yaml("policy.yaml")
```

## 测试

```bash
pytest -q     # 单元 + 端到端（攻防闭环、MITM 代理、MCP 连接器，全部离线可跑）
```

## 常见问题

**Q: 为什么默认用 Mock 模型？**
A: 保证确定性 —— 攻防结果可复现，CI 不会闪断。真实模型用于量化真实成功率。

**Q: 判定会不会误报？**
A: 判定只看轨迹里的客观事实：是否真的调用了带标记参数的 run_command / read_file。
    标记命令是无害的 `touch`；判定只统计"实际执行成功"的调用，被拦截的不算。

**Q: 越权模块里 read_file 为什么被默认拦截？**
A: 默认策略对 read_file 失败关闭（只允许 /tmp 内路径），`/etc/passwd` 等敏感路径
    直接拒绝 —— 这正是防护要演示的效果，可用 YAML 覆写策略。

**Q: 我能加自己的工具/靶场吗？**
A: 可以。`ToolRegistry.add(Tool(...))` 添加工具；`build_local_target(tools=...)`
    传入自定义工具集；实现 `AgentTarget` 接入外部智能体。
