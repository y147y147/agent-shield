# 变更说明 / Summary

<!-- 这个 PR 做了什么？为什么需要？ -->

## 类型 / Type

- [ ] feat：新功能
- [ ] fix：缺陷修复
- [ ] docs：文档
- [ ] test：测试
- [ ] refactor / chore：重构或杂务
- [ ] breaking：破坏性变更（请在下方说明迁移方式）

## 关联 Issue

<!-- 例如 Closes #12 -->

## 验证方式 / Verification

<!-- 贴出你实际跑过的命令与结果摘要 -->

```bash
pytest -q
ruff check .
agent-shield demo
```

## 检查表 / Checklist

- [ ] 新增/修改的行为**带测试**，且测试离线可跑、结果确定
- [ ] `pytest -q` 与 `ruff check .` 本地通过
- [ ] 测试不依赖 POSIX-only 命令，也不写入真实用户目录（跨平台 CI：Linux/macOS/Windows）
- [ ] 文档已同步（README / docs / docstring；涉及 CLI 选项时给出示例）
- [ ] `CHANGELOG.md` 已更新（Unreleased 段）
- [ ] 涉及攻击能力时：仅使用无害标记命令，且符合 [SECURITY.md](../blob/main/SECURITY.md) 的授权约定
- [ ] 未提交任何真实密钥、内网地址或客户数据

## 破坏性变更说明 / Breaking changes

<!-- 影响面、迁移步骤、是否需要 default_action/显式 allow 等 -->
