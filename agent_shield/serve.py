"""把本地靶场以 HTTP 服务形式暴露（黑盒智能体演示服务）。

用法::

    agent-shield http-agent --port 8000 --defense
    # 然后可用 HttpAgentTarget 或任何 HTTP 客户端攻击测试
"""

from __future__ import annotations

from fastapi import FastAPI

from agent_shield.targets import LocalAgentTarget, build_local_target


def build_http_agent_app(llm: str = "mock", defense: bool = False, **llm_kwargs) -> FastAPI:
    """构建一个暴露靶场的 HTTP 服务：POST /run {"task": ...} → {"trace": ...}。"""
    target: LocalAgentTarget = build_local_target(llm=llm, defense=defense, **llm_kwargs)
    app = FastAPI(title=f"AgentShield demo agent ({target.name})")

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok", "target": target.name, "description": target.description}

    @app.post("/run")
    async def run(body: dict) -> dict:
        trace = await target.run(body["task"])
        return {"trace": trace.model_dump(mode="json")}

    return app
