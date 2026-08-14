"""HTTP Target：把暴露 HTTP 接口的智能体当黑盒目标。

契约（与 agent_shield.serve 的演示服务一致）：:

    POST {base_url}/run
    {"task": "..."}
    → 200 {"trace": {AgentTrace JSON}}

说明：黑盒目标无法注入第三方工具内容（inject_tool_payload 为 no-op），
适合对"已部署的智能体服务"做外部视角的安全测试。
"""

from __future__ import annotations

import httpx

from agent_shield.models import AgentTrace
from agent_shield.targets.base import AgentTarget


class HttpAgentTarget(AgentTarget):
    """黑盒 HTTP 智能体目标。"""

    def __init__(
        self,
        base_url: str,
        timeout: float = 60.0,
        name: str = "http-agent",
        description: str = "black-box HTTP agent",
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.transport = transport  # 测试时注入 ASGITransport
        self.name = name
        self.description = description

    async def run(self, task: str) -> AgentTrace:
        async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport) as client:
            resp = await client.post(f"{self.base_url}/run", json={"task": task})
            resp.raise_for_status()
        return AgentTrace.model_validate(resp.json()["trace"])
