FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY agent_shield ./agent_shield

RUN pip install --no-cache-dir .

EXPOSE 8000 8085

CMD ["agent-shield", "http-agent", "--port", "8000"]
