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
    agent-shield benchmark                           # 全攻击向量 × 加固前后成功率矩阵
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
    json_out: Path | None = typer.Option(None, "--json", help="同时输出 JSON 报告到此路径"),
    md_out: Path | None = typer.Option(None, "--markdown", help="同时输出 Markdown 报告到此路径"),
) -> None:
    """对目标智能体执行一次攻击测试。"""
    judge_llm = None
    if judge_model:
        judge_llm = OpenAICompatLLM(model=judge_model, api_key=api_key, base_url=base_url)
    target = build_local_target(
        llm=llm, defense=defense, model=model, api_key=api_key, base_url=base_url, judge_llm=judge_llm
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

    # 攻击成功 = 发现漏洞：非零退出码，方便 CI 集成
    if result.successes:
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
    json_out: Path | None = typer.Option(None, "--json", help="输出 JSON 矩阵"),
    md_out: Path | None = typer.Option(None, "--markdown", help="输出 Markdown 矩阵"),
) -> None:
    """基准评测：全部攻击模块 × 加固前后成功率矩阵。"""
    from agent_shield.core.benchmark import matrix_to_markdown, run_benchmark_matrix

    matrix = asyncio.run(run_benchmark_matrix(llm=llm, num_variants=variants))

    table = Table(title=f"基准评测：{len(matrix)} 个攻击向量（llm={llm}）", show_lines=True)
    table.add_column("攻击模块", style="cyan")
    table.add_column("OWASP", justify="center")
    table.add_column("ATLAS", justify="center")
    table.add_column("加固前成功率", justify="center")
    table.add_column("加固后成功率", justify="center")
    for row in matrix:
        before = f"[bold red]{row['vulnerable_success_rate']:.0%}[/]" if row["vulnerable_success_rate"] else "[green]0%[/]"
        after = f"[green]{row['defended_success_rate']:.0%}[/]" if row["defended_success_rate"] == 0 else f"[bold red]{row['defended_success_rate']:.0%}[/]"
        table.add_row(row["module"], row["owasp_asi"] or "—", row["atlas_id"] or "—", before, after)
    console.print(table)

    if json_out:
        json_out.write_text(json.dumps(matrix, ensure_ascii=False, indent=2), encoding="utf-8")
    if md_out:
        md_out.write_text(matrix_to_markdown(matrix), encoding="utf-8")


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
    llm: str = typer.Option("mock", "--llm", help="目标模型: mock | openai-compat"),
    model: str | None = typer.Option(None, "--model"),
    api_key: str | None = typer.Option(None, "--api-key"),
    base_url: str | None = typer.Option(None, "--base-url"),
) -> None:
    """把 Demo 靶场以 HTTP 服务暴露（黑盒智能体，供 HttpAgentTarget 测试）。"""
    import uvicorn

    from agent_shield.serve import build_http_agent_app

    server_app = build_http_agent_app(llm=llm, defense=defense, model=model, api_key=api_key, base_url=base_url)
    console.print(f"[bold green]AgentShield demo agent[/]  http://127.0.0.1:{port}/run  (defense={defense})")
    uvicorn.run(server_app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    app()
