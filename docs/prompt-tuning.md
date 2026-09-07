# 审计指挥官 Prompt 调优清单（C2.3）

> 适用：`orchestrator/prompts.py` 中的 Plan / ReAct 系统提示词。  
> 调优后请运行 `pytest tests/test_audit_real_llm.py tests/test_react_loop.py -q` 做回归。

---

## 1. ReAct 模式

### 1.1 失败后的 Reflection（必须）

- **规则**：Observation 显示 `blocked` / `failed` / 成功率过低时，下一轮 assistant 内容须包含 **Reflection**（说明为何失败、下一步改什么）。
- **Action**：优先改 `num_variants` 或 `params`（编码、路径变体），再考虑换相邻模块（如 `direct_injection` → `indirect_injection`）。
- **反模式**：失败后立即用**完全相同参数**再打同一模块（系统会拒绝并返回 error）。

### 1.2 禁止空转

- **规则**：禁止连续 **3 轮** 仅调用 `list_coverage` 而不执行任何攻击模块。
- **例外**：会话第一轮可先 `list_coverage` 了解缺口。

### 1.3 bypass 上限

- 同一模块默认最多 **5 次** bypass；达上限后须换模块或 `finish_audit`。
- Prompt 中应明确写出上限，避免模型死磕单向量。

### 1.4 结束条件

- 覆盖目标达成、无法继续提升、或接近 `max_turns` 时调用 `finish_audit`。
- **数字指标以系统本地聚合为准**；`narrative` 仅作叙述，勿编造成功率。

---

## 2. Plan 模式

### 2.1 JSON 严格性

- 只输出 **AuditPlan JSON**，不要 markdown 代码块包裹（解析器会尝试剥离，但不应依赖）。
- `module` 必须是注册表中的合法名称；非法名称由运行时拒绝执行。

### 2.2 步数与覆盖

- 默认 **3–5** 步；`full=True` 时尽量覆盖全部非 mock_only 模块。
- 优先顺序：直接注入 → 间接注入 → 越权/工具误用 → 供应链/记忆/资源类。

### 2.3 mock_only

- `rogue_agent` 等模块标注 `[mock_only]`；黑盒 HTTP 目标下不会出现在 tool 列表中。

---

## 3. 真实 LLM 联调建议

1. 先用 **react + mock 指挥官离线脚本** 确认编排层无回归。
2. 再设 `AUDIT_LLM_*` 跑 integration：
   ```bash
   pytest tests/test_audit_real_llm.py -m integration -v
   ```
3. 对比 **plan vs react**：react 应在失败后出现改参或换模块（过程链可见 `bypass=1`）。
4. Web 端选 OpenAI 兼容 + API Key；Mock 下 plan/react 结果相近属预期。

---

## 4. 常见退化信号

| 现象 | 可能原因 | 调整方向 |
|------|----------|----------|
| 只调 `list_coverage` 不攻击 | Prompt 过强调「先规划」 | 加强「必须执行至少 3 个不同模块」 |
| 同参重复 5+ 次 | 未强调防重复规则 | 引用 Observation 中的 error 文案 |
| 过早 `finish_audit` | max_turns 或覆盖标准模糊 | 写明最小覆盖模块数 |
| Plan JSON 解析失败 | 模型输出闲聊 | 加强「禁止非 JSON」与示例 schema |

---

## 5. 相关文档

- [autonomous-audit-agent.md](autonomous-audit-agent.md) — Phase A/B 执行文档  
- [audit-agent-phase-c-plus.md](audit-agent-phase-c-plus.md) — Phase C+ 路线图  
- [tests/fixtures/react_scenarios/README.md](../tests/fixtures/react_scenarios/README.md) — 离线场景脚本
