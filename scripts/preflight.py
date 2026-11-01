"""AgentShield 上架前一键预检。

镜像 CI (.github/workflows/ci.yml) 的本地做法：把离线可跑的质检步骤与
"密钥硬编码扫描"串成一条命令，任一步骤失败即以非零退出——适合推到
GitHub 前在本地自检一遍。

用法：
    # 在仓库根目录下
    python scripts/preflight.py

步骤：
    1. ruff check .                        （lint，钉住规则的 CI 同款配置）
    2. agent-shield audit-benchmark --quick  （离线审计基准）
    3. agent-shield fp-benchmark --max-fpr 0.05 （良性业务 FPR 门禁）
    4. agent-shield gate                    （红队决策门，不过即非零退出）
    5. pytest -q                            （全量单测）
    6. agent-shield demo                    （离线攻防演示冒烟）
    7. secret-scan                          （扫描硬编码的"真·长密钥"，非 demo 占位）
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# 镜像 CI 的颜色/中文输出兜底
ENV = {"PYTHONUTF8": "1", **dict(__import__("os").environ)}

# 只匹配"真·长密钥"（sk- 后跟 >=24 位随机串）。demo 占位如 sk-demo-*、
# sk-xxx、sk-test、sk-cli 都短得多，天然被排除。
LONG_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{24,}\b")
# 绕开被 .gitignore 忽略的目录与伪造的测试负载
SKIP_DIRS = {".venv", ".git", "node_modules", "__pycache__", ".pytest_cache",
             ".ruff_cache", ".mypy_cache", ".basetmp", "dist", "build"}
SKIP_PATTERNS = ("sk-demo", "sk-xxx", "sk-...",)  # 二次兜底


def find_cli() -> str:
    """定位 agent-shield 控制台脚本（与当前解释器同 venv）。"""
    exe = shutil.which("agent-shield")
    if exe:
        return exe
    sysdir = Path(sys.executable).parent / "agent-shield.exe"
    if sysdir.exists():
        return str(sysdir)
    raise SystemExit("未找到 agent-shield 命令，请先 `pip install -e .[dev]`")


def sh(desc: str, cmd: list[str]) -> bool:
    print(f"\n=== {desc} ===")
    try:
        subprocess.run(cmd, cwd=ROOT, env=ENV, check=True)
        print(f"  OK  {desc}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  FAIL  {desc} (exit={e.returncode})")
        return False


def secret_scan() -> bool:
    print("\n=== secret-scan（硬编码长密钥检测） ===")
    hits: list[tuple[Path, int, str]] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {
            ".py", ".yaml", ".yml", ".toml", ".md", ".json", ".env", ".ini", ".cfg",
        }:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if any(tok in text for tok in SKIP_PATTERNS):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if LONG_KEY_RE.search(line):
                hits.append((path, i, line.strip()[:80]))
    if hits:
        for path, i, line in hits:
            print(f"  HIT  {path.relative_to(ROOT)}:{i}: {line}")
        print(f"  FAIL  secret-scan：发现 {len(hits)} 处疑似硬编码密钥")
        return False
    print("  OK  secret-scan（未发现硬编码长密钥）")
    return True


def main() -> int:
    cli = find_cli()
    py = [sys.executable, "-m"]
    steps = [
        ("ruff check", [*py, "ruff", "check", "."]),
        ("audit-benchmark --quick", [cli, "audit-benchmark", "--quick"]),
        ("fp-benchmark --max-fpr 0.05", [cli, "fp-benchmark", "--max-fpr", "0.05"]),
        ("community-benchmark --max-asr 0.3", [cli, "community-benchmark", "--max-asr", "0.3"]),
        ("gate（红队决策门）", [cli, "gate"]),
        ("pytest -q（全量单测）", [*py, "pytest", "-q"]),
        ("demo（离线冒烟）", [cli, "demo"]),
    ]
    results = {desc: sh(desc, cmd) for desc, cmd in steps}
    results["secret-scan"] = secret_scan()

    print("\n" + "=" * 50)
    all_ok = all(results.values())
    for desc, ok in results.items():
        print(f"  {'PASS' if ok else 'FAIL'}  {desc}")
    print("=" * 50)
    print("全面通过 ✅ 可以直接上传 GitHub" if all_ok else "存在失败 ❌ 请修正后重跑")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())