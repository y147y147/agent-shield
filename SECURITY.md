# 安全策略（Security Policy）

## 支持版本

| 版本 | 是否接受安全修复 |
| --- | --- |
| 0.4.x | ✅ |
| < 0.4 | ❌（请先升级） |

## 报告漏洞

**请勿用公开 Issue 报告安全问题。** 请使用 GitHub 的私密渠道：

> 仓库页面 → **Security** → **Report a vulnerability**（Private vulnerability reporting）

报告中请尽量包含：

1. 受影响的版本 / 提交号，以及运行环境（OS、Python 版本）；
2. 复现步骤：目标类型（local / http / mcp）、攻击模块或策略配置、完整命令；
3. 影响说明：绕过了哪一层防护（策略引擎 / 注入检测 / 沙箱 / 代理），造成的后果；
4. 可复现的最小样例（PoC）：载荷、轨迹片段或 SARIF/JSON 报告；
5. 你建议的修复方向（可选）。

## 响应时间线（尽力而为）

| 阶段 | 目标时间 |
| --- | --- |
| 确认收到 | 72 小时内 |
| 初步定级与复现 | 7 天内 |
| 修复或缓解方案 | 90 天内（协同披露窗口） |
| 公开致谢 | 修复发布后（如你同意） |

## 在范围内的漏洞

- 防护绕过：`PolicyEngine` 语义校验绕过、注入检测器绕过（含编码混淆）、沙箱黑名单绕过；
- 隔离失效：`SandboxExecutor` 逃逸、资源限制绕过、工作目录外写入；
- 审计与代理：MITM 代理的检测绕过、审计事件丢失/伪造；
- 供应链：`ToolIntegrityGuard` 指纹绕过；
- 工具本身的安全缺陷（如路径穿越、命令注入、凭据泄露）。

## 不在范围内

- 被测试目标模型自身的行为（模型权重与对齐由厂商负责，本项目只做应用层缓解）；
- 对演示靶场（`examples/`、Mock 模型）的 DoS/压测；
- 缺少安全加固说明的"预期限制"：例如 v0.4 的沙箱**不是**强隔离（见 `agent_shield/defenses/sandbox.py` 文档字符串），已知并已记录在 `docs/optimization-plan-v1.0.md`；
- 社会工程学、物理访问、第三方依赖自身的 0-day（请直接报告给上游）。

## 授权与伦理

本项目（含攻击载荷与红队能力）**仅用于获得授权的安全测试、研究与教学**。
提交漏洞报告即表示你已在自己拥有或获授权的环境中完成验证，且不会公开武器化细节。
载荷中的标记命令（如 `touch`）均为无害命令，请保持这一约定。

---

# Security Policy (English summary)

We support the latest released minor version. **Do not report security issues in public
issues** — use GitHub's private *Report a vulnerability* flow (repository → Security tab).

Please include: affected version/commit, environment, reproduction steps (target type,
module or policy config, exact command), which defense layer was bypassed and the impact,
a minimal PoC (payload, trace excerpt, or SARIF/JSON report).

Timeline (best effort): acknowledgement within 72 hours, triage within 7 days, fix or
mitigation within 90 days as a coordinated disclosure window.

In scope: bypasses of the policy engine, injection detector, sandbox, tool-integrity
check, MITM proxy, audit integrity, and any flaw in the tooling itself.
Out of scope: the tested model's own behaviour, DoS against demo targets, and documented
limitations such as "the v0.4 sandbox is not a strong isolation boundary".

Use of this project is limited to **authorized testing and security education**.
