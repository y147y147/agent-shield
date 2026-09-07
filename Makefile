.PHONY: install test lint demo attack audit-benchmark

install:
	pip install -e ".[dev]"

test:
	pytest -q

lint:
	ruff check .

demo:
	agent-shield demo

attack:
	agent-shield attack

# D3：自主审计指挥官质量回归（离线、无外网）
audit-benchmark:
	agent-shield audit-benchmark --quick
