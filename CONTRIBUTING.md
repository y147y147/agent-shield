# 贡献指南

感谢你对 AgentShield 的兴趣。这是一个**安全攻防研究**项目，所有改动必须遵守
"可量化决策门"，避免只满足演示、不解决实际问题。

## 施工前必读

- [README.md](../README.md) 把握项目定位；
- [docs/architecture.md](../docs/architecture.md) 了解分层与攻防闭环；
- 本项目含真实攻击载荷（`agent_shield/payloads/`）——**仅用于授权目标与离线靶场**，
  提交新载荷需附上与 OWASP ASI / MITRE ATLAS 的对齐说明。

## 环境

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate   macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
```

## 常用命令

```bash
ruff check .                                   # Lint（钉住规则的 CI 同款）
pytest -q                                      # 全量单测（离线）
python scripts/preflight.py                    # 上架前一键自检（见下）
agent-shield gate                              # 红队决策门（不过即非零退出）
agent-shield fp-benchmark --max-fpr 0.05       # FPR 门禁
```

### 上架前的一键预检

`scripts/preflight.py` 镜像 CI（ruff → audit-benchmark → FPR 门禁 → 红队门 →
全量单测 → demo），并追加**硬编码长密钥扫描**。**推送前请先跑通它**，任一失败=会挂 CI。

> 无 git 环境的机器上，仍请手动确认：`git ls-files | grep -E '\.venv/|\.db$'` 为空，
> 且仓库根目录不存在 `.db` / `.env` 运行时产物（均已被 `.gitignore` 排除，但防止历史强加）。

## 新增一个攻击模块

1. `agent_shield/attacks/<name>.py` 继承 `AttackModule`，用 `@register` 注册；
2. 攻击载荷优先放 `agent_shield/payloads/data/<name>.yaml`，不硬编码在代码里；
3. 判定依据**实际执行的工具调用 / 输出证据**（`trace.has_executed_tool_call` 等），
   不靠规则空判；
4. 补 `tests/test_<name>.py`，并跑决策门：**裸机可打穿（ASR>0）→ 加固归零（ASR=0）**。

## 提交规范

- 保持每个提交聚焦一个可验证的小改动，提交信息说明"为什么"而非"改了什么"。
- 新功能/修复需附测试；改动防线前先复跑 `python scripts/preflight.py`。
- 是否新增攻击向量变化较大时，在 PR 描述里填 `CHANGELOG.md` 对应条目。

## 行为准则

以建设性的方式讨论安全问题；不产出、不传播用于未授权目标的操作指南。