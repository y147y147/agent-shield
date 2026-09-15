# 贡献指南（Contributing to AgentShield）

感谢你有兴趣为 AgentShield 做贡献！本项目同时接受**代码**、**载荷/数据集**、**文档**与**测试**贡献。

## 1. 环境准备

```bash
git clone https://github.com/y147y147/agent-shield.git
cd agent-shield

python -m venv .venv
# Windows: .venv\Scripts\activate     macOS / Linux: source .venv/bin/activate
pip install -e ".[dev]"
```

要求：Python ≥ 3.11（CI 覆盖 3.11 / 3.12）、无需任何 API Key（默认 Mock 模型离线运行）。

## 2. 开发命令

```bash
pytest -q          # 全量测试（离线、确定性）
ruff check .       # 静态检查（CI 同款）
agent-shield demo  # 攻防对比演示
agent-shield web   # Web 工作台（http://127.0.0.1:8086）
```

也提供了 `Makefile`：`make install / make test / make lint / make demo / make attack`。

## 3. 目录速览

```
agent_shield/
├── attacks/       攻击模块（每个文件一个攻击向量，@register 注册）
├── defenses/      防护模块（GuardRail 接口：策略引擎 / 注入检测 / 沙箱 / 预算 / 完整性）
├── runtime/       智能体运行时（工具调用循环 + 防护注入点）
├── core/          报告渲染、基准矩阵、统计（Wilson 置信区间）
├── reporters/     结果导出（SARIF 2.1.0 等）
├── targets/       目标适配层（local / http 黑盒 / mcp）
├── proxy/         MITM 审计代理
├── orchestrator/  自主审计指挥官（plan / react / 会话 / PoC 报告）
├── webapp.py      Web 攻防工作台     dashboard.py  审计看板
tests/             测试（按模块划分，见下）
docs/              文档（架构 / 攻击矩阵 / 使用指南 / v1.0 演进计划）
```

详细架构见 [docs/architecture.md](docs/architecture.md)，攻击矩阵见 [docs/attack-taxonomy.md](docs/attack-taxonomy.md)。

## 4. 新增一个攻击模块（约 30–60 行）

```python
from agent_shield.attacks.base import AttackConfig, AttackModule
from agent_shield.attacks.registry import register
from agent_shield.models import AgentTrace, AttackCase, AttackResult, AttackVerdict, Severity


@register
class MyAttack(AttackModule):
    name = "my_attack"
    description = "一句话说明这个攻击向量"
    owasp_asi = "ASI-01"          # 必须对齐 OWASP Agentic Top 10（2026）
    atlas_id = "AML.T00XX"        # 可选：MITRE ATLAS 近似映射

    async def run(self, target, config: AttackConfig) -> AttackResult:
        ...

    def judge(self, trace: AgentTrace) -> AttackCase:
        ...
```

要求：

1. **必须**提供 `name` / `description` / `owasp_asi`；
2. 判定依据必须是轨迹里的**客观事实**（例如"标记命令被真实执行"），不要用模型自评；
3. 载荷请使用**无害标记命令**（`touch`、`echo`），不要写破坏性/外联型载荷；
4. 配套测试：至少覆盖「脆弱靶场应成功」与「加固靶场应被拦截」两条路径；
5. 如果是新的 ASI 类别，请同步更新 `tests/test_asi_mapping.py` 与 `docs/attack-taxonomy.md`。

## 5. 新增一个防护模块

实现 `GuardRail`（`agent_shield/defenses/base.py`）并挂到 `build_local_target(guardrails=...)`：

- `check_tool_call(call)` → 工具调用前决策（deny 即拦截）；
- `sanitize_tool_output(call, output)` → 工具输出喂给模型前清洗；
- `sanitize_user_input(text)` → 用户输入清洗；
- 需要按运行计数的防护请实现 `reset()`（每次 run 开始会被调用）。

**默认必须 fail-closed**：无法判定、解析失败、异常情况一律拒绝。策略规则请显式声明
`action: allow` 才放行（未覆盖工具默认拒绝，见 `policy_engine.py` 顶部文档）。

## 6. 测试要求

- 新功能 / 新模块**必须带测试**；改判定逻辑必须补回归用例；
- 涉及 Windows/macOS 兼容的测试请勿使用 POSIX-only 命令（`touch` / `sleep` / `rm -rf`），
  需要外部行为时用 `sys.executable` 跑 Python 脚本（参考 `tests/test_sandbox.py`）；
- 测试必须**离线可跑、结果确定**（不要依赖真实模型；真模型用例请打 `@pytest.mark.integration` 标记）；
- 测试不得污染真实用户目录：需要落盘时用 `tmp_path` 或显式传 `--session-db` 等参数。

```bash
pytest -q -m "not integration"
```

## 7. 提交与 PR

- 提交信息用 Conventional Commits：`feat:` / `fix:` / `docs:` / `test:` / `chore:` / `refactor:`（中英文均可）；
- 一个 PR 只做一件事，附上"为什么"与验证方式（命令 + 输出摘要）；
- PR 模板里的检查表请逐条确认（测试、lint、文档、CHANGELOG、无密钥）。

## 8. 安全与合规红线

- 不要提交真实 API Key、内网地址、客户数据或生产日志；
- 不要提交可直接武器化的攻击载荷（本项目只保留无害标记命令风格）；
- 所有能力仅用于**授权测试**；贡献即表示你同意 [SECURITY.md](SECURITY.md) 中的伦理约定。

## 9. 报告问题

- Bug / 功能建议：GitHub Issues（模板会引导你提供环境与复现步骤）；
- 安全漏洞：请走私密渠道，见 [SECURITY.md](SECURITY.md)。

---

## English summary

Contributions are welcome: code, payloads/datasets, docs and tests. Use Python ≥ 3.11,
`pip install -e ".[dev]"`, then `pytest -q` and `ruff check .` before opening a PR.

New attack modules must declare `name` / `description` / `owasp_asi`, judge on objective
trace evidence, use harmless marker commands, and ship tests for both the vulnerable and
the defended path. New guardrails must be fail-closed by default. Tests must stay offline,
deterministic and cross-platform (no POSIX-only commands), and must not write into the real
user home directory. Commit messages follow Conventional Commits.
