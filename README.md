# ai4security-security4ai

AI 时代安全实践笔记，两条主线：

- **AI for Security（ai4security）**：用 AI 和自动化缩短「漏洞披露 → 被利用」与「补丁上线」之间的窗口。
- **Security for AI（security4ai）**：AI 网关、MCP、Agent 本身就是攻击面，如何建模与加固。

> 本仓库以学习笔记、案例分析和可复用模式为主。引用的示例代码以其原仓库许可证为准；本仓库不包含可用的利用代码。

## 目录

| 路径 | 内容 | 状态 |
|---|---|---|
| `ai4security/01-security-radar/` | [aws-samples/sample-security-radar](https://github.com/aws-samples/sample-security-radar) 源码深读：架构、代码判定、定位与缓解 | 进行中 |
| `ai4security/02-php2shell-case/` | PHP2Shell（CVE-2026-109618/109619）从情报到补丁的推演 | 计划中 |
| `security4ai/01-litellm-case/` | LiteLLM 漏洞链分析与 AI 网关加固 | 计划中 |
| `security4ai/02-mcp-agent-threats/` | MCP / Agent 工具调用威胁模型 | 计划中 |
| `patterns/` | 可复用设计模式 | 计划中 |
| `checklists/` | 上线前安全检查清单 | 计划中 |

## 功能 / 内容列表

- 仓库骨架与两条主线的目录规划

## 参考

- 博客：[从安全头条到代码补丁：用 AWS Continuum 与 AWS WAF 构建安全事件雷达](https://aws.amazon.com/cn/blogs/china/security-aws-continuum-aws-waf-build-security-event)
- 示例：[aws-samples/sample-security-radar](https://github.com/aws-samples/sample-security-radar)

## License

MIT-0，见 [LICENSE](LICENSE)。
