"""AgentShield 命令行入口。

用法示例::

    agent-shield demo                          # 攻防对比演示（离线，零成本）
    agent-shield attack                        # 对脆弱靶场发起间接注入攻击
    agent-shield attack --defense              # 启用防护后再攻击（对比效果）
    agent-shield attack --llm openai-compat --model deepseek-chat   # 打真实模型
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
    json_out: Path | None = typer.Option(None, "--json", help="同时输出 JSON 报告到此路径"),
    md_out: Path | None = typer.Option(None, "--markdown", help="同时输出 Markdown 报告到此路径"),
) -> None:
    """对目标智能体执行一次攻击测试。"""
    target = build_local_target(llm=llm, defense=defense, model=model, api_key=api_key, base_url=base_url)
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


if __name__ == "__main__":
    app()
