# 更新日志（Changelog）

本文件记录项目的显著变更，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Changed — **行为破坏性变更（Breaking）**

- **策略引擎默认改为 fail-closed**：未覆盖的工具默认**拒绝**（此前默认放行），单条规则未写
  `action` 时同样默认拒绝。`receive_message` 已在默认策略中显式 `allow`，保证只读通道可用。
  - 影响：自定义策略若依赖"未列出即放行"，需显式写 `action: allow`，或设置
    `default_action: allow`；新增了 `"*"` 通配兜底规则。
  - 详见 `agent_shield/defenses/policy_engine.py` 顶部文档与 `tests/test_policy_fail_closed.py`。

### Added

- **SARIF 2.1.0 报告器**（`agent_shield/reporters/sarif.py`）：攻击结果可直接进 GitHub
  Code Scanning 与任何 SARIF 消费平台；新增 CLI 选项 `agent-shield attack --sarif out.sarif`。
- **`--no-fail-on-finding`**：CI 中先收集报告而不让流水线失败（默认仍为发现漏洞时退出码 1）。
- **自扫描工作流**（`.github/workflows/security-scan.yml`）：对内置靶场跑攻击 → 上传 SARIF。
- **统计模块**（`agent_shield/core/stats.py`）：Wilson score 置信区间与比例估计。
- **多轮基准评测**：`run_benchmark(runs=N)` / `run_benchmark_matrix(runs=N)` /
  `agent-shield benchmark --runs 5`，报告与 Markdown 输出成功率的同时给出 95% 置信区间。
- **可观测性**（`agent_shield/observability/`，零依赖）：
  - 结构化日志：JSON 单行输出 + `--log-level` / `--log-format json`（默认静默，库不配置 root logger）；
  - Prometheus 指标：工具调用（含拦截）、策略决策、注入命中、沙箱执行结果、防护决策耗时；
  - `GET /metrics`：MITM 代理与 Web 攻防工作台均暴露，可直接接 Prometheus/Grafana。
- **误报率（FPR）基准**（`agent_shield/core/fp_benchmark.py` + `datasets/benign_tasks.yaml`）：
  36 条良性业务任务（strict 集）+ 3 条 near-miss 用例，输出 FPR 与置信区间；
  新增 CLI `agent-shield fp-benchmark --max-fpr 0.05` 作为 CI 门禁（防"防护误伤正常业务"）。
- **沙箱逃逸用例套件 v0**（`tests/test_sandbox_escape.py` + `docs/sandbox-escape-matrix.md`）：
  19 类已拦截命令、8 类 v0 明确挡不住的手法（含策略层纵深补救），并固定跨平台差异。
- **已验证的依赖版本快照** `requirements-lock.txt`，CI 新增 `locked-deps` job 按锁定版本装包并跑测试。
- 仓库治理文件：`SECURITY.md`、`CONTRIBUTING.md`、`CHANGELOG.md`、`CODE_OF_CONDUCT.md`、
  Issue/PR 模板、`.github/dependabot.yml`。
- 测试：`tests/test_policy_fail_closed.py`、`tests/test_sarif.py`、`tests/test_stats.py`、
  `tests/test_benchmark_runs.py`、`tests/test_observability.py`、`tests/test_sandbox_escape.py`、
  `tests/test_fp_benchmark.py`。

### Fixed

- **Windows 控制台中文输出崩溃（CI 上暴露）**：GitHub 的 Windows runner 上 `stdout` 默认编码为
  **cp1252**，Rich 渲染中文/表格时抛 `UnicodeEncodeError`，使 `audit-benchmark` 步骤以退出码 1
  失败（Linux/macOS 不受影响；本地可用 `PYTHONIOENCODING=cp1252` 复现）。修复：
  - CLI 启动时把 `stdout`/`stderr` 强制切到 UTF-8 并以 `errors="replace"` 兜底
    （`agent_shield/cli.py::_configure_stdio`，所有 CLI 命令共用）；
  - 两个 workflow 统一设置 `PYTHONUTF8=1`，覆盖测试与校验脚本的输出；
  - 新增回归测试 `tests/test_cli_stdio.py`（含"以 cp1252 启动子进程跑 CLI"的端到端复现）。
- **CI lint 全红（工具链漂移）**：CI 按 `ruff>=0.5` 装到了 **0.16.7**，其默认规则集比本机 0.14 更宽
  （新增 `I` / `UP` / `DTZ` / `RUF` / `S` / `PLW` / `TRY` 等）→ 33 个报错、6 个矩阵任务全部卡在 Lint。
  处理方式：
  - `pyproject.toml` 用 `[tool.ruff.lint] select` **显式固定规则集**（`E4/E7/E9/F/I/UP/DTZ`），
    并把 `ruff` 钉到 `>=0.16,<0.17`，避免以后再被默认规则集扩张打到；
  - 修复全部报错：datetime 一律显式带时区（`datetime.now(UTC)` / `tzinfo=UTC`）、导入排序、
    `typing.Sequence/Iterable` → `collections.abc`、`__all__` 排序、`datetime.UTC`、
    `subprocess.run(..., check=False)` 显式传参、进度回调异常不再静默 `pass`（改为 debug 日志）、
    去掉 `int(round(...))` 冗余转换；
  - 行为变更（次要）：规划器输出不是 JSON 对象时由 `ValueError` 改为 `TypeError`（ruff TRY004 建议，
    调用方均未依赖该异常类型）；
  - 暂缓 `UP042`（`str, Enum` → `StrEnum`）：会改变 `str(Enum)` 的运行时返回值，单独评估后再改。
- **Code Scanning 上传失败**：SARIF 的 `physicalLocation.artifactLocation.uri` 原先使用
  `agent://<target>` 自定义 scheme，GitHub 报
  `an invalid URI was provided as a SARIF location: parse "agent://...": invalid IP-literal`。
  现改为**仓库相对路径**（默认 `agent_shield/targets/local.py`，可用 `target_artifact=` 覆盖），
  人类可读的目标名仍保留在 `logicalLocations` 与 result 属性中；CI 的 SARIF 校验步骤新增
  "uri 必须是相对路径且不含 scheme"断言，防止回归。
- **Windows 误报修复**：策略引擎解析命令时 `shlex(posix=True)` 会把反斜杠当作转义符，
  导致 `ls C:\dir\file` 这类**合法**命令被误判为"越界路径"而拒绝；现于 Windows 上先统一
  路径分隔符再解析。该误报由良性对照集（`fp-benchmark`）发现，并已加跨平台回归用例。
- CI 扩到 **Linux / macOS / Windows × Python 3.11 / 3.12**；修复依赖 POSIX-only 命令
  （`touch` / `sleep`）的沙箱测试，改为用 `sys.executable` 执行 Python 脚本。
- `audit` CLI 测试改为显式传 `--session-db`，不再写入真实用户目录（测试自包含化）。
- `agent_shield.__version__` 与 `pyproject.toml` 版本对齐（0.4.0）。

## [0.4.0] - 2026-09-07

### Added

- 攻击模块补齐至 **12 个**，覆盖 OWASP Agentic Top 10（2026）ASI-01 ~ ASI-10：
  `unexpected_code_execution`(ASI-05)、`inter_agent_communication`(ASI-07)、
  `human_trust_exploitation`(ASI-09)、`rogue_agent`(ASI-10)、`mcp_poisoning`(ASI-04 MCP 通道)。
- 防护：`SandboxExecutor`（危险命令黑名单 + 资源限制 + 超时 + 固定工作目录）；
  `--defense` 自动隐含开启沙箱；策略引擎语义校验强化（realpath 根目录、shell 元字符、命令白名单）。
- 平台：Web 攻防工作台（过程链流式、多模型对比、策略/沙箱测试、审计记录、自动审计、会话历史）；
  自主审计指挥官（plan / react、HITL、会话持久化、PoC 报告、质量回归 `audit-benchmark`、`audit-schedule`）；
  HTTP 黑盒靶场（`serve` / `http-agent`）；代理审计捕猎（proxy hunt）。
- 文档：双语文档（`README.md` 中文 / `README.en.md` 英文）与 `docs/usage-guide.md` 等。

### Changed

- ASI 映射与测试对齐 OWASP 官方清单；`mcp_poisoning` 纳入注册表与覆盖断言。

### Fixed

- 修复 `ruff` 静态检查问题（未使用导入/变量、前向引用注解）。

## [0.3.0] - 2026-08-14

### Added

- 攻击模块：`tool_poisoning`（供应链投毒 AML.T0104）、`data_exfiltration`（AML.C0054）、
  `memory_poisoning`（记忆污染）、`resource_abuse`（调用循环 DoS）。
- 防护：`ToolIntegrityGuard`（工具指纹校验）、`CallBudgetGuard`（单次运行调用预算）。
- 平台：`benchmark` 全向量矩阵、审计看板（FastAPI + 原生 JS）、HTTP 靶场与 `HttpAgentTarget`、
  `AgentRuntime` 审计集成、Dockerfile + docker-compose。

## [0.2.0] - 2026-08-14

### Added

- 攻击模块：`direct_injection`（用户输入通道目标劫持）、`privilege_escalation`（越权读 + 外发）；
- 防护：`GuardRail` 异步钩子与用户输入清洗、`LLMJudgeDetector`（LLM-as-Judge 慢路径 + 缓存）、
  策略引擎读文件失败关闭、外发默认拒绝；
- 组件：MITM 审计代理（audit / sanitize / block 三种模式 + SQLite 审计）、MCP 连接器（JSON-RPC）；
- CLI：`proxy`、`mcp` 命令与 `attack --judge-model`。

## [0.1.0] - 2026-08-14

### Added

- 核心骨架：数据模型、工具调用运行时、目标适配层、攻击/防护插件体系；
- 首个攻击向量：间接 Prompt 注入（ASI-01 / AML.T0011.002）；
- 防护层：注入检测器 + 失败关闭策略引擎；
- CLI：`attack` / `demo` / `modules`，支持 JSON 与 Markdown 报告；
- 离线确定性 `MockLLM`（CI 用）与 OpenAI 兼容真实模型连接器。
