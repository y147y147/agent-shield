.PHONY: install test lint demo attack

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
