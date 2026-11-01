# Phase 3 交付报告：打磨（入库 / 图表 / 调度 / 门禁）

> 对应 `docs/plan-v2.md` 第 4 节 Phase 3 行：*中间结果入库、图表、`audit-schedule` 接 runner；全程数字进文档、CI 门串起 Phase1+2*。
> 本文档记录本阶段**已实现**的能力、验收数字与本阶段落地的决策门，全部离线可回归。

## 1. 阶段目标与决策门（回顾）

| 出阶段条件（plan） | 落地情况 |
|---|---|
| 中间结果入库 | ✅ `run-campaign --db` 持久化累积 |
| 图表 | ✅ `run-campaign --chart-dir` 纯 SVG 战报图 |
| `audit-schedule` 接 runner | ✅ `--runner campaign` cron 定时驱动战役 |
| 全程数字进文档 | ✅ 本文档 |
| CI 门串起 Phase1+2 | ✅ `gate` 一键门禁接入 ci.yml |

## 2. 交付清单

| # | 模块 / 入口 | 说明 |
|---|---|---|
| 1 | `agent_shield/campaign_store.py` — `CampaignStore` | sqlite 战役战报库：`record_run / list_runs / latest`；表 `campaign_runs`（cfg/summary/markdown 快照）+ `campaign_rows`（逐 目标×模块 聚合行） |
| 2 | `agent_shield/core/campaign_chart.py` — `render_campaign_chart_svg` | 纯 SVG 横向柱状图（0% 绿 / >0% 琥珀~红），无第三方图表库，离线可回归 |
| 3 | `cli.py run-campaign` | 新增 `--db`（入库，默认 `~/.agent-shield/campaign_runs.db`）与 `--chart-dir`（输出 `campaign-report.svg`） |
| 4 | `cli.py audit-schedule` | 新增 `--runner campaign` + `--c-*` 战役参数；cron 定时跑 `run_campaign` 并自动入库；`--cron` 默认 `* * * * *` 以支持 `--once` |
| 5 | `agent_shield/gate.py` — `run_gates` + `cli.py gate` | 一键红队门禁，一串 Phase1 对抗回归 + Phase2 红队决策门 + FPR 不劣化 |
| 6 | `.github/workflows/ci.yml` | Test 步骤前新增 `agent-shield gate` 门禁步骤 |
| 7 | `tests/test_phase3.py` | 3 条：store 读写回读 / 图表渲染 / 门禁全过 |

## 3. 验收数字（本次实测）

### 3.1 一键门禁 `agent-shield gate`（seed=20261010）

| 门 | 状态 | 明细 |
|---|---|---|
| adversarial_regression（Phase1） | PASS | direct_injection:0%；indirect_injection:0%（加固后 ASR=0） |
| redteam_gate（Phase2） | PASS | weak_asr=100% strong_asr=0%（决策门达成） |
| fpr | PASS | strict_fpr=0.0%（≤5%）· clean=36/36 |

退出码 0，任一不过即非零退出。

### 3.2 回归与静态检查

- 全量测试：**441 passed, 3 skipped**（较 Phase 2 的 438 新增 3 条，无回归）
- 静态检查：`ruff check agent_shield tests` **全绿**

### 3.3 CLI 端到端冒烟（均实测通过）

- `run-campaign -m indirect_injection ... --db p3runs.db --chart-dir p3charts` → 入库 run_id=1 + 输出 `campaign-report.svg`
- `audit-schedule --runner campaign --c-* ... --once` → 定时战役完成 defense=True cells=1 run_id=1

## 4. 落地的决策门（如何自证）

1. **门禁命令**：`agent-shield gate` 全离线 mock、固定 seed，可复现；三道门各自有明确布尔断言，**任一 FAIL 即退出码 1** —— CI 直接引用，杜绝"改了防线但没验证"。
2. **入库可回读**：`CampaignStore.latest(run_id)` 能回读逐行聚合与 Markdown 快照，`list_runs` 累积多局，供趋势/文档。
3. **图表可回归**：SVG 由战报结构确定性生成，无随机、无三方依赖，任何英雄改动后重跑即可对比。

## 5. 文件改动清单

- 新增：`agent_shield/campaign_store.py`、`agent_shield/core/campaign_chart.py`、`agent_shield/gate.py`、`tests/test_phase3.py`、`docs/phase3-report.md`（本文档）
- 修改：`agent_shield/cli.py`（run-campaign --db/--chart-dir、audit-schedule --runner campaign、gate 命令）、`.github/workflows/ci.yml`、`README.md`

## 6. 明确不做（防蔓延复核）

- <=15 行内未引入任何新外部依赖（复用既有 sqlite/typer/rich）。
- 门禁只跑**离线 mock 代表役种**（注入类），不做全模块真实模型门（那是验收增强，非必经路径，留作后续）。
- 未给任何模型"更宽权限"；自适应/门禁只收严。

---

*生成时间：2026-10-10 · 基于本次全量实测数字，非估算。*