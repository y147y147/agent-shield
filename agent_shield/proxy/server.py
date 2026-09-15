"""MITM 审计代理服务。

插在"智能体 <-> LLM API"之间，不改一行智能体代码即可：

- audit：记录所有请求，检测工具输出中的注入信号；
- sanitize：在记录的同时清洗注入内容后再转发给上游模型（默认）；
- block：检测到注入时直接拒绝请求（403）。

用法（见 CLI `agent-shield proxy`）：

    1. 启动代理：  agent-shield proxy --port 8090 --mock-upstream
    2. 把智能体的 LLM API 指向 http://127.0.0.1:8090/v1
    3. 智能体照常运行，代理完成审计/清洗/拦截
"""

from __future__ import annotations

import os
from copy import deepcopy

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from agent_shield.defenses import InjectionDetector
from agent_shield.observability import render_metrics
from agent_shield.proxy.audit import AuditStore


def _mock_upstream_response(model: str, messages: list[dict], detections: list) -> dict:
    """离线演示用 Mock 上游：回显收到的消息数与注入是否仍存在。"""
    injection_present = any(
        "INSTRUCTION:" in (m.get("content") or "") for m in messages if m.get("role") == "tool"
    )
    return {
        "id": "chatcmpl-mock",
        "object": "chat.completion",
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": (
                        f"[mock-upstream] messages={len(messages)} detections={len(detections)} "
                        f"injection_still_present={injection_present}"
                    ),
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def build_proxy_app(
    upstream_base_url: str | None = None,
    api_key: str | None = None,
    detector: InjectionDetector | None = None,
    store: AuditStore | None = None,
    mode: str = "sanitize",
    mock_upstream: bool = False,
) -> FastAPI:
    """构建审计代理 FastAPI 应用。

    mode: "audit"（只记录） | "sanitize"（记录+清洗） | "block"（记录+拦截）
    """
    upstream = (upstream_base_url or os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
    key = api_key or os.environ.get("OPENAI_API_KEY", "EMPTY")
    detector = detector or InjectionDetector(sanitize=True)
    store = store or AuditStore()
    if mode not in ("audit", "sanitize", "block"):
        raise ValueError(f"未知 mode: {mode}（可选 audit / sanitize / block）")

    app = FastAPI(title="AgentShield Audit Proxy")

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> JSONResponse:
        body = await request.json()
        model = body.get("model", "?")
        messages = deepcopy(body.get("messages") or [])
        detections: list[dict] = []

        # 工具输出是注入的主要载体：检测 + 按模式处置
        for msg in messages:
            if msg.get("role") == "tool" and isinstance(msg.get("content"), str):
                found = detector.detect(msg["content"])
                if found:
                    detections.extend(d.model_dump() for d in found)
                    if mode == "sanitize":
                        msg["content"] = detector.sanitize_text(msg["content"])

        if mode == "block" and detections:
            store.record_event("in", model, "block", detections, "injection detected, request blocked")
            return JSONResponse(
                status_code=403,
                content={"error": {"message": "blocked by AgentShield: injection detected", "type": "agent_shield_block"}},
            )

        if mock_upstream:
            response = _mock_upstream_response(model, messages, detections)
            action = "mock"
        else:
            forward = {k: v for k, v in body.items() if k != "messages"}
            forward["messages"] = messages
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    f"{upstream}/chat/completions",
                    json=forward,
                    headers={"Authorization": f"Bearer {key}"},
                )
                resp.raise_for_status()
                response = resp.json()
            action = "forward"

        store.record_event("in", model, action, detections, f"messages={len(messages)}")
        return JSONResponse(content=response)

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok", "mode": mode, "mock_upstream": mock_upstream}

    @app.get("/audit/latest")
    async def audit_latest(n: int = 20) -> dict:
        return {"events": store.latest(n)}

    @app.get("/metrics")
    async def metrics() -> PlainTextResponse:
        """Prometheus 文本格式指标（检测命中、策略决策、沙箱执行、防护耗时）。"""
        return PlainTextResponse(render_metrics(), media_type="text/plain; version=0.0.4; charset=utf-8")

    return app
