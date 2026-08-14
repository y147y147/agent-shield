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
agent-shield attack                           # 攻击脆弱靶场（Mock 模型）
agent-shield attack --defense                 # 防护后重跑
agent-shield attack -n 5 --json report.json   # 5 个变体 + 输出 JSON 报告
```

`attack` 命令在发现漏洞（存在 success 用例）时以退出码 1 结束 —— 可接入 CI
做"智能体上线前安全检查"。

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
pytest -q     # 单元 + 端到端（攻防闭环，离线可跑）
```

## 常见问题

**Q: 为什么默认用 Mock 模型？**
A: 保证确定性 —— 攻防结果可复现，CI 不会闪断。真实模型用于量化真实成功率。

**Q: 判定会不会误报？**
A: 判定只看轨迹里的客观事实：是否真的调用了带标记参数的 run_command。
    标记命令是无害的 `touch`。

**Q: 我能加自己的工具/靶场吗？**
A: 可以。`ToolRegistry.add(Tool(...))` 添加工具；`build_local_target(tools=...)`
    传入自定义工具集；实现 `AgentTarget` 接入外部智能体。
