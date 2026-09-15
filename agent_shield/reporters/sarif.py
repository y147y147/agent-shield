"""SARIF 2.1.0 报告器：把攻击结果输出成 CI / 安全平台可消费的格式。

用途：

- GitHub Actions 中配合 ``github/codeql-action/upload-sarif``，把发现直接写进 PR 的
  Code Scanning 告警（见 ``.github/workflows/security-scan.yml``）；
- 任何支持 SARIF 的平台（DefectDojo、自建看板等）消费同一份产物。

映射关系：

- 一个攻击模块 → 一条 SARIF ``rule``（``ruleId = agentshield/<module>``）；
- 一个"攻击成功（漏洞确认）"的用例 → 一条 SARIF ``result``（默认过滤掉未生效/被拦截的用例）；
- 严重度 → SARIF ``level``：``critical``/``high`` → ``error``，``medium`` → ``warning``，
  ``low``/``info`` → ``note``。

定位信息说明：攻击目标是"另一个智能体"而不是本仓库源码，因此 ``artifactLocation.uri``
使用 ``agent://<target_name>`` 形式的逻辑 URI，并通过 ``logicalLocations`` 标注目标名称。
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from agent_shield import __version__
from agent_shield.models import AttackResult, AttackVerdict, Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "AgentShield"
INFORMATION_URI = "https://github.com/y147y147/agent-shield"
HELP_URI = f"{INFORMATION_URI}/blob/main/docs/attack-taxonomy.md"
# Code Scanning 只接受仓库相对路径；默认指向内置靶场的目标定义文件
DEFAULT_TARGET_ARTIFACT = "agent_shield/targets/local.py"


def _relative_artifact_uri(artifact: str) -> str:
    """把 artifact 归一化为仓库相对路径（去掉自定义 scheme、前导斜杠与反斜杠）。"""
    text = str(artifact).strip().replace("\\", "/")
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.lstrip("/")
    return text or DEFAULT_TARGET_ARTIFACT

_LEVEL_BY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def level_for(severity: Severity) -> str:
    """严重度 → SARIF level。"""
    return _LEVEL_BY_SEVERITY.get(severity, "warning")


def _rule_id(module: str) -> str:
    return f"agentshield/{module}"


def _rule_for(module: str, description: str, owasp_asi: str | None, atlas_id: str | None) -> dict[str, Any]:
    """为一个攻击模块生成 SARIF rule 定义。"""
    mapping = []
    if atlas_id:
        mapping.append(f"MITRE ATLAS {atlas_id}")
    if owasp_asi:
        mapping.append(f"OWASP {owasp_asi}")
    mapping_text = f"（{' / '.join(mapping)}）" if mapping else ""
    tags = ["security", "llm-agent"]
    if owasp_asi:
        tags.append(owasp_asi)
    if atlas_id:
        tags.append(atlas_id)
    return {
        "id": _rule_id(module),
        "name": module,
        "shortDescription": {"text": description or module},
        "fullDescription": {"text": f"{description or module}{mapping_text}"},
        "helpUri": HELP_URI,
        "help": {"text": f"AgentShield 攻击模块 {module}：可复现载荷与判定证据见报告 results.properties。"},
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": tags,
            "owasp-asi": owasp_asi or "",
            "mitre-atlas": atlas_id or "",
        },
    }


def _result_for(result: AttackResult, case, target_name: str, target_artifact: str) -> dict[str, Any]:
    evidence = "；".join(case.evidence) or f"{result.module} 攻击成功（未附证据）"
    return {
        "ruleId": _rule_id(result.module),
        "level": level_for(case.severity),
        "message": {"text": f"[{case.severity.value}] {evidence}"},
        "locations": [
            {
                "physicalLocation": {"artifactLocation": {"uri": target_artifact}},
                "logicalLocations": [{"name": target_name, "kind": "resource"}],
            }
        ],
        # 同一模块 + 同一用例名 → 相同的指纹，便于 Code Scanning 去重/跟踪
        "partialFingerprints": {"agentShieldCase/v1": f"{result.module}:{case.name}"},
        "properties": {
            "module": result.module,
            "case": case.name,
            "target": target_name,
            "verdict": case.verdict.value,
            "severity": case.severity.value,
            "owasp-asi": result.owasp_asi or "",
            "mitre-atlas": result.atlas_id or "",
            "evidence": list(case.evidence),
        },
    }


def results_to_sarif(
    results: Sequence[AttackResult],
    *,
    target_name: str = "agent-under-test",
    target_artifact: str = DEFAULT_TARGET_ARTIFACT,
    include_non_success: bool = False,
) -> dict[str, Any]:
    """把一批攻击结果渲染为 SARIF 2.1.0 文档。

    参数：
        results: 攻击结果列表（同一目标上的多次/多模块攻击）。
        target_name: 被审计目标的名称，写入 ``logicalLocations`` 与 result 属性（人类可读）。
        target_artifact: 仓库相对路径，作为 ``physicalLocation.artifactLocation.uri``。
            GitHub Code Scanning 要求该 uri 是**相对路径**（不接受 ``agent://`` 等自定义 scheme，
            否则上传报 "an invalid URI was provided as a SARIF location"），因此默认指向
            内置靶场的目标定义文件；自定义 scheme 会被自动归一化为相对路径。
        include_non_success: 是否把"未生效/被拦截"的用例也写入 results（默认只写漏洞确认）。
    """
    rules: list[dict[str, Any]] = []
    seen_rules: set[str] = set()
    sarif_results: list[dict[str, Any]] = []
    total_cases = 0
    successes = 0
    artifact_uri = _relative_artifact_uri(target_artifact)

    for result in results:
        if result.module not in seen_rules:
            seen_rules.add(result.module)
            rules.append(_rule_for(result.module, result.description, result.owasp_asi, result.atlas_id))
        total_cases += result.total
        successes += result.successes
        for case in result.cases:
            if not include_non_success and case.verdict != AttackVerdict.SUCCESS:
                continue
            sarif_results.append(_result_for(result, case, target_name, artifact_uri))

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "invocations": [{"executionSuccessful": True}],
                "results": sarif_results,
                "properties": {
                    "target": target_name,
                    "modules": len({r.module for r in results}),
                    "cases": total_cases,
                    "successes": successes,
                },
            }
        ],
    }


def result_to_sarif(
    result: AttackResult,
    *,
    target_name: str = "agent-under-test",
    target_artifact: str = DEFAULT_TARGET_ARTIFACT,
    include_non_success: bool = False,
) -> dict[str, Any]:
    """单个攻击模块的结果 → SARIF 文档（便捷封装）。"""
    return results_to_sarif(
        [result],
        target_name=target_name,
        target_artifact=target_artifact,
        include_non_success=include_non_success,
    )


def dumps(sarif: dict[str, Any]) -> str:
    """序列化为 JSON 文本（保留中文，便于人读）。"""
    return json.dumps(sarif, ensure_ascii=False, indent=2) + "\n"


def write_sarif(path: str | Path, sarif: dict[str, Any]) -> Path:
    """写入 SARIF 文件并返回路径。"""
    target = Path(path)
    target.write_text(dumps(sarif), encoding="utf-8")
    return target
