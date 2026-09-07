# ReAct 场景 Fixtures（C2.1）

本目录提供 **ScriptedReActLLM** 用的命名场景，用于离线验收「失败 → 改参 / 换模块」等自适应路径，无需真实 API。

## 场景列表

| 名称 | 说明 |
|------|------|
| `retry_change_params` | 同一模块 `num_variants` 从 1 提高到 5，产生 `bypass_index=1` |
| `switch_module` | `direct_injection` → `indirect_injection` 换向量 |
| `duplicate_then_retry` | 同参重复被拒绝后改参重试 |

## 使用

```python
from tests.fixtures.react_scenarios import get_scenario
from agent_shield.orchestrator.react_loop import ScriptedReActLLM

scenario = get_scenario("retry_change_params")
planner = ScriptedReActLLM(scenario.script)
```

自动化测试见 `tests/test_audit_real_llm.py`（`test_react_scenario_offline`）。

## 真实 LLM 集成测试

设置环境变量后运行：

```bash
export AUDIT_LLM_MODEL=deepseek-chat
export AUDIT_LLM_API_KEY=sk-...
export AUDIT_LLM_BASE_URL=https://api.deepseek.com/v1   # 可选

pytest tests/test_audit_real_llm.py -m integration -v
```

未设置 `AUDIT_LLM_MODEL` 时 integration 用例自动 skip。
