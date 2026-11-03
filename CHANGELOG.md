# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Added
- **语义伪装间接注入对抗集**：`semantic_injection`（模板/检测/Mock 抽取）+ 载荷库 `s-001`–`s-005` / 良性对照 `b-002`；加固须归零、裸机可打穿。
- **容器级沙箱后端**：`DockerSandboxExecutor` + `build_sandbox_executor`（`AGENT_SHIELD_SANDBOX=auto|local|docker`，`--network=none` / 只读根 / 非 root）；`RunCommandTool` 默认按后端装配。
- **弱模块自改进**：`rewrite_profile_for` / `self-improve-weak`；`tool_impersonation` 用 impersonation 风格 + 精确 marker，避免重写话术与 judge 脱节。
- **HTTP 一键挂真 Agent**：`attack-http --serve` 本地起靶场并黑盒攻击；或 `--url` 指向已部署 `POST /run` 服务。
- **本地 `.env` 加载**：`envfile.load_dotenv`（CLI 启动时）；提供 `.env.example`，密钥勿贴聊天。
- **语义污点跟踪** `TaintTracker`：同 run 内跟踪「敏感源 / 框架+敏感动作 → write/email/重定向汇」，封死 ad04 类半链落地。
- **路径归一化** `PathNormalizeGuard`：Windows 上将 `/c/Users`、`/mnt/c/...` 改写成宿主路径，降低真实模型路径臆造导致的 FPR。
- **社区基准 N 次分布**：`community-benchmark --repeats N --seed` 输出 hits/trials + Wilson CI（真实模型单样本翻转可门槛化）。
- 上架预检一键脚本 `scripts/preflight.py`：镜像 CI 的本地做法（ruff / audit-benchmark
  / FPR 门禁 / 红队门 / 全量单测 / demo）+ 硬编码长密钥扫描，任一失败非零退出。
- **社区基准横向对比** `community-benchmark`：注入文本逐字取自 **AgentDojo 官方仓库**
  攻击框架（`baseline_attacks.py` / `important_instructions_attacks.py`），
  在本地 mock 靶场输出裸机 vs 加固的 ASR 对比表；`--max-asr 0.3` 门禁接入 CI 与预检（离线、确定性，非官方基准评分）。
- `CONTRIBUTING.md` / `AUTHORS.md`：规范开源协作入口。
- PyPI 发布 CI（`publish.yml`，可信发布，无明文密钥）。

### Changed
- `InjectionDetector`：补全 `Ignore your/all/the previous|above`；「TODO/IMPORTANT + 敏感动作」复合整段脱敏（纯 TODO 不误伤）。
- 全量防线装配顺序：`TaintTracker → InjectionDetector → PathNormalize → PolicyEngine → …`（local + LangChain）。
- **修复真实模型加固 ASR 反升**：整段脱敏后运行时短路（`input_blocked`），不再把占位符喂给主模型去 `dir` 工作目录；`reset()` 移到 `sanitize` 之前以保留污点；`SYSTEM UPDATE` 改为片段脱敏以免误伤 FPR。
- **工具输出通道深度防护**：`deobfuscate`（base64/全角/零宽/HTML/NFKC）后再检测；不可信工具
  （web_search/receive_message/http_fetch）输出窄信号扫描；默认防线挂「仅工具通道」IntentClassifier。

## [0.4.0] - 2026-10-12

### Added
- **M5 成本门禁**：`agent_shield/budget.py` 单价格源 + `CostBudget`（任务/每日累计超限熔断）、
  `cny_to_usd`、`today_start_ts`；usage 转发计费、campaign/self_improve/repair 全路径挂接；
  CLI/console 预算参数（元）超限 → 红告警 + `aborted` 落库 + 非零退出。
- **Web 攻防控制台**（`web --store <path>` 的 `/console`）：三 tab 单页、`/api/dispatch`
  异步 job、结果视图、SVG/Markdown 报告导出。
- **M3 修复闭环**：`agent_shield/repair/`（盲区案例库 + 五段流水），
  `locate_defense_hits` 防线命中定位，四门决策门（裸机打穿 / 盲区复现 / 加固归零 / 能力不降）。
- **M2 自改进循环**：`agent_shield/self_improve/`（LLM 重写攻击话术迭代），
  M1 六表数据层（campaigns / attack_runs / traces / verdicts / costs / findings 状态机）。
- **sarif**：`attack --sarif` 生成 SARIF 2.1.0 报告，可上传 Code Scanning。

### Changed
- 真实模型基准确认：DeepSeek（chat / reasoner）上可攻可防、能力分不降，
  详见 `docs/phase4-report.md`、`docs/real-asr/`。

## [0.3.0] - 2026-10-10

### Added
- **Phase 4 真实框架适配**：`run-campaign --targets langchain` 打到真实
  LangChain AgentExecutor 上；`rebuild_tools()` 修复供应链投毒对模型不可见的快照问题。
  后续已迁移到 LangChain v1 ``create_agent``（底层 LangGraph），废弃 AgentExecutor。
- 第 14 个攻击模块 `workspace_exfiltration`（ASI-02，工作目录敏感文件窃取）。
- 第四守卫钩子 `sanitize_final_output` + `FinalAnswerGuard`：打通 final_answer
  输出端盲区，敏感文件最小权限策略。
- `unexpected_code_execution` 等行为层防御（ASI-06/07/08/10）与长程持久化剧情实验。
- 自适应防御状态机（normal → strict → locked）、逃逸边界透明化、攻击指纹记忆库。

## [0.2.0] - 2026-10-08

### Added
- FPR 门禁（`fp-benchmark --max-fpr`）与近失项（near-miss）脱敏后完成率。
- 一键红队门禁 `gate`：对抗回归 + 红队决策门 + FPR 不劣化，接入 CI。
- 战报入库与 SVG 战役图表、MITM 审计代理、Web 攻防工作台、MCP 支持。
- `redteam` 定向话术生成器（司仪 LM，默认喂受害模板）。

## [0.1.0] - 2026-10-05

### Added
- 插件化攻击框架（首批攻击模块 + `@register`）、注入检测器、失败关闭策略引擎、
  LLM-as-Judge 防护，mock 演示攻防对比 100% → 0%。
- 多模型基准（ASR / FPR / 成本 / SVG 对比）、离线 mock 管道。
- 首个 CI、中英双语 README、决策门/恢复 验收文档。

[Unreleased]: https://github.com/y147y147/agent-shield/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/y147y147/agent-shield/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/y147y147/agent-shield/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/y147y147/agent-shield/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/y147y147/agent-shield/releases/tag/v0.1.0