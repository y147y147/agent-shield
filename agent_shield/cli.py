"""AgentShield 命令行入口。

用法示例::

    agent-shield demo                          # 攻防对比演示（离线，零成本）
    agent-shield attack                        # 对脆弱靶场发起间接注入攻击
    agent-shield attack --defense              # 启用防护后再攻击（对比效果）
    agent-shield attack -m direct_injection    # 直接注入攻击
    agent-shield attack -m privilege_escalation  # 越权攻击
    agent-shield attack --llm openai-compat --model deepseek-chat   # 打真实模型
    agent-shield proxy --port 8090 --mock-upstream   # MITM 审计代理
    agent-shield dashboard --db proxy_audit.db       # Web 审计看板
    agent-shield audit --mode plan --llm mock   # 自主审计（Plan-and-Execute，离线）
    agent-shield audit --target http --url http://127.0.0.1:8000 --mode react --llm mock
    agent-shield web --port 8086                     # Web 攻防工作台（攻击/防护对比/多模型/策略/沙箱/审计）
    agent-shield benchmark                           # 全攻击向量 × 加固前后成功率矩阵
    agent-shield audit-benchmark --quick           # 自主审计指挥官质量回归（离线）
    agent-shield audit-schedule --cron "0 2 * * *" --once  # 定时审计（示例）
    agent-shield http-agent --port 8000              # 暴露 HTTP 黑盒靶场
    agent-shield mcp --url http://127.0.0.1:8080/mcp   # 审计 MCP server 工具
    agent-shield modules                       # 列出可用攻击模块
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agent_shield.attacks import AttackConfig, get_attack_module, list_attack_modules
from agent_shield.core.report import result_to_json, result_to_markdown
from agent_shield.runtime.llm import OpenAICompatLLM
from agent_shield.targets import DEFAULT_TASK, build_local_target

app = typer.Typer(help="AgentShield — LLM 智能体安全攻防框架", add_completion=False)
console = Console()


def _render_result(result) -> None:
    table = Table(title=f"攻击结果: [bold]{result.module}[/bold]", show_lines=True)
    table.add_column("#", justify="right")
    table.add_column("用例", style="cyan")
    table.add_column("判定", justify="center")
    table.add_column("严重度", justify="center")
    table.add_column("证据", overflow="fold", max_width=70)

    style_of = {"success": "bold red", "blocked": "bold yellow", "failed": "green"}
    sev_of = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue", "info": "white"}

    for i, case in enumerate(result.cases, start=1):
        table.add_row(
            str(i),
            case.name,
            f"[{style_of[case.verdict.value]}]{case.verdict.value}[/]",
            f"[{sev_of[case.severity.value]}]{case.severity.value}[/]",
            "；".join(case.evidence) or "—",
        )
    console.print(table)

    summary = result.summary()
    console.print(
        Panel.fit(
            f"[bold]{summary['successes']}[/bold] / {summary['total']} 个用例攻击成功，"
            f"成功率 [bold red]{summary['success_rate']:.0%}[/bold red]；"
            f"被拦截 [bold yellow]{summary['blocked']}[/bold yellow]，未生效 {summary['failed']}；"
            f"耗时 {summary['duration_ms']} ms",
            title=f"{result.module} 摘要（{result.atlas_id or '—'} / {result.owasp_asi or '—'}）",
            border_style="bright_blue",
        )
    )


def _render_comparison(before, after) -> None:
    table = Table(title="攻防对比：加固前 vs 加固后", show_lines=True)
    table.add_column("指标", style="bold")
    table.add_column("加固前（脆弱）", justify="center")
    table.add_column("加固后（防护）", justify="center")
    table.add_row("用例数", str(before.total), str(after.total))
    table.add_row("攻击成功", f"[bold red]{before.successes}[/]", f"[green]{after.successes}[/]")
    table.add_row("成功率", f"[bold red]{before.success_rate:.0%}[/]", f"[green]{after.success_rate:.0%}[/]")
    table.add_row("被防护拦截", str(before.blocked), f"[yellow]{after.blocked}[/]")
    table.add_row("耗时 (ms)", str(before.duration_ms), str(after.duration_ms))
    console.print(table)
    if after.success_rate == 0:
        console.print("[green]✓ 防护生效：注入指令已被检测/拦截，攻击全部失败。[/]")
    else:
        console.print(f"[yellow]! 防护未完全生效：仍有 {after.successes} 个用例绕过防护，建议加固策略。[/]")


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
@app.command("attack")
def attack(
    module: str = typer.Option("indirect_injection", "--module", "-m", help="攻击模块名"),
    defense: bool = typer.Option(False, "--defense/--no-defense", help="启用防护层（注入检测 + 策略引擎）"),
    variants: int = typer.Option(3, "--variants", "-n", min=1, help="载荷变体数量"),
    task: str = typer.Option(DEFAULT_TASK, "--task", "-t", help="目标任务"),
    llm: str = typer.Option("mock", "--llm", help="目标模型: mock（离线确定性） | openai-compat（真实模型）"),
    model: str | None = typer.Option(None, "--model", help="openai-compat 时必填，如 deepseek-chat"),
    api_key: str | None = typer.Option(None, "--api-key", help="API Key（默认读 OPENAI_API_KEY）"),
    base_url: str | None = typer.Option(None, "--base-url", help="API Base URL（默认读 OPENAI_BASE_URL）"),
    judge_model: str | None = typer.Option(None, "--judge-model", help="启用 LLM-as-Judge 慢路径检测（需模型名，如 deepseek-chat）"),
    sandbox: bool = typer.Option(False, "--sandbox/--no-sandbox", help="run_command 在沙箱中执行（资源限制 + 超时）"),
    json_out: Path | None = typer.Option(None, "--json", help="同时输出 JSON 报告到此路径"),
    md_out: Path | None = typer.Option(None, "--markdown", help="同时输出 Markdown 报告到此路径"),
    sarif_out: Path | None = typer.Option(
        None, "--sarif", help="同时输出 SARIF 2.1.0 报告（GitHub Code Scanning / CI 集成）"
    ),
    fail_on_finding: bool = typer.Option(
        True,
        "--fail-on-finding/--no-fail-on-finding",
        help="发现漏洞时以退出码 1 结束（CI 门禁）；--no-fail-on-finding 则始终返回 0",
    ),
) -> None:
    """对目标智能体执行一次攻击测试。"""
    judge_llm = None
    if judge_model:
        judge_llm = OpenAICompatLLM(model=judge_model, api_key=api_key, base_url=base_url)
    target = build_local_target(
        llm=llm, defense=defense, model=model, api_key=api_key, base_url=base_url,
        judge_llm=judge_llm, sandbox=sandbox,
    )
    console.print(f"[dim]目标: {target.name} — {target.description}[/]")

    attack_module = get_attack_module(module)
    result = asyncio.run(attack_module.run(target, AttackConfig(task=task, num_variants=variants)))

    _render_result(result)

    if json_out:
        json_out.write_text(json.dumps(result_to_json(result), ensure_ascii=False, indent=2), encoding="utf-8")
        console.print(f"[dim]JSON 报告已写入: {json_out}[/]")
    if md_out:
        md_out.write_text(result_to_markdown(result), encoding="utf-8")
        console.print(f"[dim]Markdown 报告已写入: {md_out}[/]")
    if sarif_out:
        from agent_shield.reporters import result_to_sarif, write_sarif

        write_sarif(sarif_out, result_to_sarif(result, target_name=target.name))
        console.print(f"[dim]SARIF 报告已写入: {sarif_out}[/]")

    # 攻击成功 = 发现漏洞：非零退出码，方便 CI 集成（可用 --no-fail-on-finding 关闭）
    if result.successes and fail_on_finding:
        raise typer.Exit(code=1)


@app.command("demo")
def demo(
    variants: int = typer.Option(3, "--variants", "-n", min=1),
    task: str = typer.Option(DEFAULT_TASK, "--task", "-t"),
) -> None:
    """一键演示：先攻击脆弱靶场，再启用防护重跑，输出对比。"""
    console.print(Panel.fit(
        "Demo: 间接 Prompt 注入 → 智能体执行攻击者命令 → 启用防护 → 攻击被拦截",
        title="AgentShield 攻防演示",
        border_style="bright_blue",
    ))

    attack_module = get_attack_module("indirect_injection")

    console.print("\n[bold cyan]第 1 步：攻击未防护的脆弱靶场[/]")
    vulnerable = build_local_target(llm="mock", defense=False)
    before = asyncio.run(attack_module.run(vulnerable, AttackConfig(task=task, num_variants=variants)))
    _render_result(before)

    console.print("\n[bold cyan]第 2 步：启用防护（注入检测器 + 失败关闭策略引擎）后重跑[/]")
    defended = build_local_target(llm="mock", defense=True)
    after = asyncio.run(attack_module.run(defended, AttackConfig(task=task, num_variants=variants)))
    _render_result(after)

    console.print("\n[bold cyan]第 3 步：对比[/]")
    _render_comparison(before, after)


@app.command("audit")
def audit(
    mode: str = typer.Option("plan", "--mode", help="审计模式: plan | react"),
    target: str = typer.Option("local", "--target", help="目标类型: local | http | mcp"),
    url: str | None = typer.Option(None, "--url", help="http 目标地址，如 http://127.0.0.1:8000"),
    mcp_url: str | None = typer.Option(None, "--mcp-url", help="mcp 目标 MCP server 地址，如 http://127.0.0.1:8080/mcp"),
    defense_url: str | None = typer.Option(None, "--defense-url", help="http 加固端点（攻防对比用，可选）"),
    timeout: float = typer.Option(60.0, "--timeout", min=1.0, help="http 请求超时（秒）"),
    llm: str = typer.Option("mock", "--llm", help="local 靶场模型: mock | openai-compat"),
    model: str | None = typer.Option(None, "--model", help="openai-compat 时的模型名（指挥官与靶场共用）"),
    api_key: str | None = typer.Option(None, "--api-key", help="API Key（默认读 OPENAI_API_KEY）"),
    base_url: str | None = typer.Option(None, "--base-url", help="OpenAI 兼容 API Base URL"),
    steps: int = typer.Option(5, "--steps", "-n", min=1, help="plan 模式：计划步数上限"),
    max_turns: int = typer.Option(12, "--max-turns", min=1, help="react 模式：最大轮次"),
    task: str = typer.Option(DEFAULT_TASK, "--task", "-t", help="默认用户任务"),
    compare_defense: bool = typer.Option(True, "--compare-defense/--no-compare-defense", help="攻防对比"),
    full: bool = typer.Option(False, "--full/--no-full", help="plan 模式：尽量覆盖全部模块"),
    include_mock_only: bool = typer.Option(True, "--include-mock-only/--no-include-mock-only"),
    fail_fast: bool = typer.Option(False, "--fail-fast/--no-fail-fast", help="plan 模式：遇错即停"),
    save: bool = typer.Option(True, "--save/--no-save", help="将会话报告写入 SQLite"),
    session_db: Path | None = typer.Option(None, "--session-db", help="会话库路径（默认 ~/.agent-shield/audit_sessions.db）"),
    proxy_db: Path | None = typer.Option(None, "--proxy-db", help="MITM Proxy audit_events SQLite（启用 analyze_proxy_events）"),
    export_traces: Path | None = typer.Option(None, "--export-traces", help="导出成功用例完整 AgentTrace JSON"),
    json_out: Path | None = typer.Option(None, "--json", help="输出会话 JSON 报告"),
    md_out: Path | None = typer.Option(None, "--markdown", help="输出会话 Markdown 报告"),
) -> None:
    """自主安全审计：plan（一次规划）或 react（逐步决策），输出会话级攻防报告。"""
    from agent_shield.models import AuditSessionReport
    from agent_shield.orchestrator.hitl import DANGEROUS_ATTACK_MODULES
    from agent_shield.orchestrator.plan_execute import FixedPlanLLM, audit_plan_and_execute
    from agent_shield.orchestrator.react_loop import DefaultReActLLM, audit_agent_loop
    from agent_shield.orchestrator.report import (
        export_session_traces,
        session_report_to_json,
        session_report_to_markdown,
    )
    from agent_shield.orchestrator.session_store import AuditSessionStore
    from agent_shield.orchestrator.target_factory import AuditTargetSpec, build_audit_target_factory, resolve_audit_options
    from agent_shield.paths import default_session_db_path
    from agent_shield.proxy.audit import AuditStore
    from agent_shield.runtime.llm import OpenAICompatLLM

    if mode not in {"plan", "react"}:
        console.print(f"[red]未知模式 `{mode}`，请使用 plan 或 react。[/]")
        raise typer.Exit(code=2)

    if target not in {"local", "http", "mcp"}:
        console.print(f"[red]未知 --target: {target}，请使用 local、http 或 mcp。[/]")
        raise typer.Exit(code=2)

    if target == "http" and not url:
        console.print("[red]http 目标需指定 --url（如 http://127.0.0.1:8000）[/]")
        raise typer.Exit(code=2)

    if target == "mcp" and not mcp_url:
        console.print("[red]mcp 目标需指定 --mcp-url（如 http://127.0.0.1:8080/mcp）[/]")
        raise typer.Exit(code=2)

    hitl_confirmed = frozenset(DANGEROUS_ATTACK_MODULES)

    proxy_store = AuditStore(proxy_db) if proxy_db else None

    if llm == "mock":
        use_proxy = bool(proxy_store and proxy_store.count() > 0 and mode == "react")
        if mode == "plan":
            planner = FixedPlanLLM()
            console.print("[dim]指挥官: FixedPlanLLM（离线）[/]")
        else:
            planner = DefaultReActLLM(use_proxy_analysis=use_proxy)
            label = "DefaultReActLLM+proxy" if use_proxy else "DefaultReActLLM"
            console.print(f"[dim]指挥官: {label}（离线）[/]")
    elif llm == "openai-compat":
        if not model:
            console.print("[red]openai-compat 需指定 --model[/]")
            raise typer.Exit(code=2)
        planner = OpenAICompatLLM(model=model, api_key=api_key, base_url=base_url)
        console.print(f"[dim]指挥官: OpenAICompatLLM ({model})[/]")
    else:
        console.print(f"[red]未知 --llm: {llm}[/]")
        raise typer.Exit(code=2)

    if proxy_store and proxy_store.count() > 0:
        console.print(f"[dim]Proxy 狩猎: {proxy_store.count()} 条 audit_events[/]")

    target_spec = AuditTargetSpec(
        kind=target,  # type: ignore[arg-type]
        llm=llm,
        model=model,
        api_key=api_key,
        api_base_url=base_url,
        target_url=url,
        defense_target_url=defense_url,
        timeout=timeout,
        mcp_url=mcp_url,
    )
    compare_defense, include_mock_only, option_notes = resolve_audit_options(
        target_spec,
        compare_defense=compare_defense,
        include_mock_only=include_mock_only,
    )
    for note in option_notes:
        console.print(f"[yellow]{note}[/]")

    target_factory = build_audit_target_factory(target_spec)

    title = "Plan-and-Execute" if mode == "plan" else "ReAct"
    if target == "http":
        target_label = f"http:{url}"
    elif target == "mcp":
        target_label = f"mcp:{mcp_url}"
    else:
        target_label = f"local:{llm}"
    console.print(
        Panel.fit(
            f"mode={mode} · target={target_label} · compare_defense={compare_defense}",
            title=f"自主安全审计（{title}）",
            border_style="bright_blue",
        )
    )

    async def _run() -> AuditSessionReport:
        if mode == "plan":
            return await audit_plan_and_execute(
                planner=planner,
                target_factory=target_factory,
                task=task,
                max_steps=steps,
                compare_defense=compare_defense,
                include_mock_only=include_mock_only,
                fail_fast=fail_fast,
                full=full,
                export_traces=export_traces is not None,
                hitl_confirmed_modules=hitl_confirmed,
            )
        return await audit_agent_loop(
            planner=planner,
            target_factory=target_factory,
            task=task,
            max_turns=max_turns,
            compare_defense=compare_defense,
            include_mock_only=include_mock_only,
            proxy_store=proxy_store,
            export_traces=export_traces is not None,
            hitl_confirmed_modules=hitl_confirmed,
        )

    report = asyncio.run(_run())

    table = Table(title=f"会话报告 · risk={report.risk_level}", show_lines=True)
    table.add_column("模块", style="cyan")
    table.add_column("防护", justify="center")
    table.add_column("成功/总数", justify="center")
    table.add_column("成功率", justify="center")
    table.add_column("错误", overflow="fold", max_width=40)
    for s in report.steps:
        total = s.result_summary.get("total", "—")
        successes = s.result_summary.get("successes", "—")
        rate = s.result_summary.get("success_rate")
        rate_s = f"{float(rate):.0%}" if isinstance(rate, (int, float)) else "—"
        table.add_row(
            s.module,
            "on" if s.defense_on else "off",
            f"{successes}/{total}",
            rate_s,
            s.error or "—",
        )
    console.print(table)
    console.print(
        Panel.fit(
            f"计划 {len(report.modules_planned)} 步 · 覆盖 {report.vectors_covered} 向量 · "
            f"脆弱成功 {report.successes_vulnerable} · 防护成功 {report.successes_defended} · "
            f"防护拦截 {report.blocked_defended} · risk=[bold]{report.risk_level}[/]",
            title=report.objective[:60],
            border_style="green",
        )
    )
    if report.planner_usage:
        pu = report.planner_usage
        console.print(
            f"[dim]指挥官用量: calls={pu.get('calls', 0)} tokens={pu.get('total_tokens', 0)} "
            f"est=${pu.get('estimated_cost_usd', 0):.4f}[/]"
        )

    if json_out:
        json_out.write_text(
            json.dumps(session_report_to_json(report), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        console.print(f"[dim]JSON 报告已写入: {json_out}[/]")
    if md_out:
        md_out.write_text(session_report_to_markdown(report), encoding="utf-8")
        console.print(f"[dim]Markdown 报告已写入: {md_out}[/]")

    if export_traces:
        n = export_session_traces(report, export_traces)
        console.print(f"[dim]AgentTrace 已导出: {export_traces}（{n} 条）[/]")

    if save:
        db_path = session_db or default_session_db_path()
        session_store = AuditSessionStore(db_path)
        try:
            sid = session_store.save_session(report, target_spec=target_spec, task=task)
            console.print(f"[dim]会话已保存: id={sid} db={db_path}[/]")
        finally:
            session_store.close()


@app.command("modules")
def modules() -> None:
    """列出已注册的攻击模块。"""
    table = Table(title="可用攻击模块")
    table.add_column("模块名", style="cyan")
    table.add_column("说明")
    for name, desc in list_attack_modules():
        table.add_row(name, desc)
    console.print(table)


@app.command("proxy")
def proxy(
    port: int = typer.Option(8090, "--port", "-p", help="监听端口"),
    upstream: str | None = typer.Option(None, "--upstream", help="上游 LLM API Base URL（默认读 OPENAI_BASE_URL）"),
    api_key: str | None = typer.Option(None, "--api-key", help="上游 API Key（默认读 OPENAI_API_KEY）"),
    mode: str = typer.Option("sanitize", "--mode", help="audit(只记录) | sanitize(记录+清洗，默认) | block(记录+拦截)"),
    db: Path = typer.Option(Path("proxy_audit.db"), "--db", help="SQLite 审计库路径"),
    mock_upstream: bool = typer.Option(False, "--mock-upstream", help="使用内置 Mock 上游（离线演示）"),
) -> None:
    """启动 MITM 审计代理：插在 Agent 与 LLM API 之间，不改 Agent 代码。"""
    import uvicorn

    from agent_shield.defenses import InjectionDetector
    from agent_shield.proxy.audit import AuditStore
    from agent_shield.proxy.server import build_proxy_app

    store = AuditStore(db)
    proxy_app = build_proxy_app(
        upstream_base_url=upstream,
        api_key=api_key,
        detector=InjectionDetector(sanitize=True),
        store=store,
        mode=mode,
        mock_upstream=mock_upstream,
    )
    console.print(
        f"[bold green]AgentShield proxy[/]  http://127.0.0.1:{port}/v1  "
        f"(mode={mode}, db={db}, mock_upstream={mock_upstream})\n"
        f"[dim]把智能体的 LLM Base URL 指向上面地址即可开始审计。[/]"
    )
    uvicorn.run(proxy_app, host="127.0.0.1", port=port)


@app.command("mcp")
def mcp(
    url: str = typer.Option(..., "--url", help="MCP server HTTP 地址，如 http://127.0.0.1:8080/mcp"),
    list_only: bool = typer.Option(True, "--list/--no-list", help="只列出工具（默认）"),
) -> None:
    """连接 MCP server 并列出其暴露的工具（MCP 安全审计入口）。"""

    async def _fetch() -> list[dict]:
        from agent_shield.connectors.mcp import MCPClient

        client = MCPClient(url)
        await client.initialize()
        return await client.list_tools()

    tools = asyncio.run(_fetch())
    table = Table(title=f"MCP tools @ {url}")
    table.add_column("工具名", style="cyan")
    table.add_column("描述")
    for tool in tools:
        table.add_row(tool["name"], (tool.get("description") or "")[:90])
    console.print(table)
    console.print(f"[dim]共 {len(tools)} 个工具。恶意 MCP server 可用工具描述/输出注入指令 —— 接入前请审计（见 docs/attack-taxonomy.md）。[/]")


@app.command("benchmark")
def benchmark(
    llm: str = typer.Option("mock", "--llm", help="目标模型: mock | openai-compat"),
    variants: int = typer.Option(3, "--variants", "-n", min=1),
    runs: int = typer.Option(1, "--runs", min=1, help="每个模块重复轮次（多轮聚合，输出 Wilson 置信区间）"),
    json_out: Path | None = typer.Option(None, "--json", help="输出 JSON 矩阵"),
    md_out: Path | None = typer.Option(None, "--markdown", help="输出 Markdown 矩阵"),
) -> None:
    """基准评测：全部攻击模块 × 加固前后成功率矩阵（含置信区间）。"""
    from agent_shield.core.benchmark import format_matrix_rate, matrix_to_markdown, run_benchmark_matrix

    matrix = asyncio.run(run_benchmark_matrix(llm=llm, num_variants=variants, runs=runs))

    cases_per_module = variants * runs
    table = Table(
        title=f"基准评测：{len(matrix)} 个攻击向量（llm={llm}，{runs} 轮 × {variants} 变体 = {cases_per_module} 用例/模块）",
        show_lines=True,
    )
    table.add_column("攻击模块", style="cyan")
    table.add_column("OWASP", justify="center")
    table.add_column("ATLAS", justify="center")
    table.add_column("加固前成功率（95% CI）", justify="center")
    table.add_column("加固后成功率（95% CI）", justify="center")
    for row in matrix:
        before_text = format_matrix_rate(row, "vulnerable")
        after_text = format_matrix_rate(row, "defended")
        before = f"[bold red]{before_text}[/]" if row["vulnerable_success_rate"] else f"[green]{before_text}[/]"
        after = f"[green]{after_text}[/]" if row["defended_success_rate"] == 0 else f"[bold red]{after_text}[/]"
        table.add_row(row["module"], row["owasp_asi"] or "—", row["atlas_id"] or "—", before, after)
    console.print(table)
    if runs > 1:
        console.print(
            f"[dim]置信区间为 Wilson score interval（{int(round(matrix[0]['confidence'] * 100)) if matrix else 95}%）。"
            f"单轮 100%/0% 不等于「必然/绝不可能」，多轮运行可给出误差范围。[/]"
        )

    if json_out:
        json_out.write_text(json.dumps(matrix, ensure_ascii=False, indent=2), encoding="utf-8")
    if md_out:
        md_out.write_text(matrix_to_markdown(matrix), encoding="utf-8")


@app.command("fp-benchmark")
def fp_benchmark_cmd(
    llm: str = typer.Option("mock", "--llm", help="目标模型: mock | openai-compat"),
    dataset: Path | None = typer.Option(None, "--dataset", help="良性对照集 YAML（默认 datasets/benign_tasks.yaml）"),
    max_fpr: float = typer.Option(0.05, "--max-fpr", min=0.0, max=1.0, help="FPR 门禁上限，超过则以退出码 1 结束"),
    confidence: float = typer.Option(0.95, "--confidence", min=0.5, max=0.999, help="置信水平"),
    json_out: Path | None = typer.Option(None, "--json", help="输出 JSON 报告"),
    md_out: Path | None = typer.Option(None, "--markdown", help="输出 Markdown 报告"),
) -> None:
    """误报率（FPR）基准：在启用防护的靶场上跑良性对照集，度量是否误伤正常业务。"""
    from agent_shield.core.fp_benchmark import run_fp_benchmark

    report = asyncio.run(run_fp_benchmark(llm=llm, dataset_path=dataset, confidence=confidence))

    table = Table(
        title=(
            f"良性对照集 FPR：{report.total} 条 strict + {report.near_miss_total} 条 near-miss"
            f"（llm={llm}）"
        ),
        show_lines=True,
    )
    table.add_column("指标")
    table.add_column("值", justify="right")
    table.add_row(
        "FPR（strict 集，入门禁）",
        f"{report.fpr:.1%}（95% CI {report.ci_low:.1%}–{report.ci_high:.1%}）",
    )
    table.add_row("被误伤的良性任务", f"{report.flagged}/{report.total}")
    table.add_row("覆盖度（触发了工具的用例）", f"{report.exercised}/{report.total}")
    table.add_row("工具调用", f"{report.tool_calls} 次（实际执行 {report.executed_calls} 次）")
    table.add_row(
        "near-miss 误报（仅参考）",
        f"{report.near_miss_fpr:.0%}（{report.near_miss_flagged}/{report.near_miss_total}）",
    )
    console.print(table)

    for finding in report.findings:
        console.print(f"[yellow]· {finding.task_id}[/]（{finding.tolerance}）: {'；'.join(finding.reasons)}")
    for miss in report.expectation_misses:
        console.print(f"[dim]· 覆盖度提示: {miss}[/]")

    if json_out:
        json_out.write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        console.print(f"[dim]JSON 报告已写入: {json_out}[/]")
    if md_out:
        md_out.write_text(report.to_markdown(), encoding="utf-8")
        console.print(f"[dim]Markdown 报告已写入: {md_out}[/]")

    if report.fpr > max_fpr:
        console.print(f"[bold red]FPR {report.fpr:.1%} 超过门禁 {max_fpr:.1%}[/]")
        raise typer.Exit(code=1)
    console.print(f"[green]FPR {report.fpr:.1%} ≤ 门禁 {max_fpr:.1%}，未误伤良性任务。[/]")


@app.command("audit-benchmark")
def audit_benchmark_cmd(
    quick: bool = typer.Option(False, "--quick", help="快速模式：3 步 plan / 12 轮 react"),
    json_out: Path | None = typer.Option(None, "--json", help="输出 JSON 结果"),
    md_out: Path | None = typer.Option(None, "--markdown", help="输出 Markdown 结果"),
    fail_on_regression: bool = typer.Option(
        True,
        "--fail-on-regression/--no-fail-on-regression",
        help="任一场景未达阈值时非零退出",
    ),
) -> None:
    """自主审计指挥官质量回归：3 mock 目标配置 × plan/react，检测 Prompt 退化。"""
    from agent_shield.core.audit_benchmark import results_to_markdown, run_audit_benchmark

    results = asyncio.run(run_audit_benchmark(quick=quick))
    failed = [r for r in results if not r.passed]

    table = Table(
        title=f"自主审计 Benchmark（{'quick' if quick else 'full'} · {len(results)} 场景）",
        show_lines=True,
    )
    table.add_column("目标配置", style="cyan")
    table.add_column("模式")
    table.add_column("modules", justify="right")
    table.add_column("risk")
    table.add_column("bypass", justify="center")
    table.add_column("turns", justify="right")
    table.add_column("finish", justify="center")
    table.add_column("结果", justify="center")
    for r in results:
        m = r.metrics
        status = "[green]PASS[/]" if r.passed else "[bold red]FAIL[/]"
        table.add_row(
            r.target_config,
            r.mode,
            str(m.modules_covered),
            m.risk_level,
            "是" if m.bypass_used else "否",
            str(m.turns),
            "是" if m.finish_called else "否",
            status,
        )
    console.print(table)

    if failed:
        console.print("[bold red]未达阈值：[/]")
        for r in failed:
            console.print(f"  · {r.target_config}/{r.mode}: {'; '.join(r.failures)}")

    if json_out:
        json_out.write_text(
            json.dumps([r.to_dict() for r in results], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    if md_out:
        md_out.write_text(results_to_markdown(results), encoding="utf-8")

    if fail_on_regression and failed:
        raise typer.Exit(code=1)


@app.command("audit-schedule")
def audit_schedule_cmd(
    cron: str = typer.Option(..., "--cron", help="5 段 cron：minute hour day month weekday"),
    mode: str = typer.Option("plan", "--mode", help="plan | react"),
    target: str = typer.Option("local", "--target", help="local | http | mcp"),
    mcp_url: str | None = typer.Option(None, "--mcp-url"),
    url: str | None = typer.Option(None, "--url"),
    llm: str = typer.Option("mock", "--llm"),
    steps: int = typer.Option(3, "--steps", "-n", min=1),
    max_turns: int = typer.Option(8, "--max-turns", min=1),
    once: bool = typer.Option(False, "--once", help="仅检查当前是否匹配 cron 并执行一次（不守护）"),
    poll_seconds: int = typer.Option(60, "--poll", min=10, help="守护模式下检查间隔（秒）"),
    session_db: Path | None = typer.Option(None, "--session-db"),
) -> None:
    """定时自主审计：按 cron 表达式周期性运行 audit（默认守护循环）。"""
    from agent_shield.core.audit_schedule import cron_matches, run_cron_loop
    from agent_shield.orchestrator.hitl import DANGEROUS_ATTACK_MODULES
    from agent_shield.orchestrator.plan_execute import FixedPlanLLM, audit_plan_and_execute
    from agent_shield.orchestrator.react_loop import DefaultReActLLM, audit_agent_loop
    from agent_shield.orchestrator.session_store import AuditSessionStore
    from agent_shield.orchestrator.target_factory import AuditTargetSpec, build_audit_target_factory, resolve_audit_options
    from agent_shield.paths import default_session_db_path
    from agent_shield.targets import DEFAULT_TASK

    if mode not in {"plan", "react"}:
        raise typer.BadParameter("mode 须为 plan 或 react")
    if target not in {"local", "http", "mcp"}:
        raise typer.BadParameter("target 须为 local、http 或 mcp")

    spec = AuditTargetSpec(
        kind=target,  # type: ignore[arg-type]
        llm=llm,
        target_url=url,
        mcp_url=mcp_url,
    )
    compare_defense, include_mock_only, notes = resolve_audit_options(
        spec, compare_defense=False, include_mock_only=True,
    )
    target_factory = build_audit_target_factory(spec)
    planner = FixedPlanLLM() if mode == "plan" else DefaultReActLLM()
    hitl_confirmed = frozenset(DANGEROUS_ATTACK_MODULES)
    db_path = session_db or default_session_db_path()
    session_store = AuditSessionStore(db_path)

    async def _run_once() -> None:
        if mode == "plan":
            report = await audit_plan_and_execute(
                planner=planner,
                target_factory=target_factory,
                task=DEFAULT_TASK,
                max_steps=steps,
                compare_defense=compare_defense,
                include_mock_only=include_mock_only,
                hitl_confirmed_modules=hitl_confirmed,
            )
        else:
            report = await audit_agent_loop(
                planner=planner,
                target_factory=target_factory,
                task=DEFAULT_TASK,
                max_turns=max_turns,
                compare_defense=compare_defense,
                include_mock_only=include_mock_only,
                hitl_confirmed_modules=hitl_confirmed,
            )
        sid = session_store.save_session(report, target_spec=spec, task=DEFAULT_TASK)
        console.print(
            f"[green]定时审计完成[/] risk={report.risk_level} vectors={report.vectors_covered} session={sid}"
        )

    if once:
        if not cron_matches(cron):
            console.print("[yellow]当前时刻不匹配 cron，跳过执行[/]")
            session_store.close()
            return
        asyncio.run(_run_once())
        session_store.close()
        return

    console.print(f"[dim]audit-schedule 守护中 cron={cron} poll={poll_seconds}s db={db_path}[/]")
    for note in notes:
        console.print(f"[yellow]{note}[/]")

    async def _daemon() -> None:
        await run_cron_loop(cron, _run_once, poll_seconds=poll_seconds)

    try:
        asyncio.run(_daemon())
    finally:
        session_store.close()


@app.command("web")
def web(
    port: int = typer.Option(8086, "--port", "-p", help="监听端口"),
    db: Path = typer.Option(Path("proxy_audit.db"), "--db", help="审计 SQLite 库路径（攻击事件实时入库）"),
) -> None:
    """Web 攻防工作台：攻击/防护对比/多模型测试/策略/沙箱/审计，全可视化。"""
    import uvicorn

    from agent_shield.proxy.audit import AuditStore
    from agent_shield.webapp import build_web_app

    web_app = build_web_app(AuditStore(db))
    console.print(
        f"[bold green]AgentShield 攻防工作台[/]  http://127.0.0.1:{port}  (db={db})\n"
        f"[dim]Mock 离线直接可用；填 model/base-url/api-key 即切换真实 API 大模型测试。[/]"
    )
    uvicorn.run(web_app, host="127.0.0.1", port=port)


@app.command("dashboard")
def dashboard(
    db: Path = typer.Option(Path("proxy_audit.db"), "--db", help="SQLite 审计库路径"),
    port: int = typer.Option(8085, "--port", "-p", help="监听端口"),
) -> None:
    """Web 看板：审计事件可视化（配合 proxy / 运行时审计使用）。"""
    import uvicorn

    from agent_shield.dashboard import build_dashboard_app
    from agent_shield.proxy.audit import AuditStore

    proxy_app = build_dashboard_app(AuditStore(db))
    console.print(f"[bold green]AgentShield dashboard[/]  http://127.0.0.1:{port}  (db={db})")
    uvicorn.run(proxy_app, host="127.0.0.1", port=port)


@app.command("http-agent")
def http_agent(
    port: int = typer.Option(8000, "--port", "-p", help="监听端口"),
    defense: bool = typer.Option(False, "--defense/--no-defense", help="服务端启用防护"),
    sandbox: bool = typer.Option(False, "--sandbox/--no-sandbox", help="run_command 在沙箱中执行"),
    llm: str = typer.Option("mock", "--llm", help="目标模型: mock | openai-compat"),
    model: str | None = typer.Option(None, "--model"),
    api_key: str | None = typer.Option(None, "--api-key"),
    base_url: str | None = typer.Option(None, "--base-url"),
) -> None:
    """把 Demo 靶场以 HTTP 服务暴露（黑盒智能体，供 HttpAgentTarget 测试）。"""
    import uvicorn

    from agent_shield.serve import build_http_agent_app

    server_app = build_http_agent_app(
        llm=llm, defense=defense, sandbox=sandbox, model=model, api_key=api_key, base_url=base_url
    )
    console.print(f"[bold green]AgentShield demo agent[/]  http://127.0.0.1:{port}/run  (defense={defense}, sandbox={sandbox})")
    uvicorn.run(server_app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    app()
