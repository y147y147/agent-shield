.PHONY: install install-locked test lint demo attack benchmark fp escape audit-benchmark

install:
	pip install -e ".[dev]"

# 按已验证的版本快照安装（可复现）
install-locked:
	pip install -r requirements-lock.txt && pip install -e . --no-deps

test:
	pytest -q

lint:
	ruff check .

demo:
	agent-shield demo

attack:
	agent-shield attack

# 攻防矩阵（--runs N 输出 Wilson 置信区间）
benchmark:
	agent-shield benchmark --runs 5

# 误报率门禁：良性对照集（FPR 超过 5% 即失败）
fp:
	agent-shield fp-benchmark --max-fpr 0.05

# 沙箱逃逸用例套件（明确 v0 能挡/挡不住的边界）
escape:
	pytest -q tests/test_sandbox_escape.py

# D3：自主审计指挥官质量回归（离线、无外网）
audit-benchmark:
	agent-shield audit-benchmark --quick
