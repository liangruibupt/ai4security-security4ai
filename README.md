# ai4security-security4ai

AI 时代安全实践笔记，两条主线：

- **AI for Security（ai4security）**：用 AI 和自动化缩短「漏洞披露 → 被利用」与「补丁上线」之间的窗口。
- **Security for AI（security4ai）**：AI 网关、MCP、Agent 本身就是攻击面，如何建模与加固。

> 本仓库以学习笔记、案例分析和可复用模式为主。引用的示例代码以其原仓库许可证为准；本仓库不包含可用的利用代码。

## 目录

| 路径 | 内容 | 状态 |
|---|---|---|
| `ai4security/01-security-radar/` | [aws-samples/sample-security-radar](https://github.com/aws-samples/sample-security-radar) 源码深读：[架构与工程护栏](ai4security/01-security-radar/01-architecture-and-guardrails.md)、[代码判定与大模型约束](ai4security/01-security-radar/02-decisions-in-code.md)、[定位、Continuum 与边缘缓解](ai4security/01-security-radar/03-respond-and-mitigate.md)，以及读源码时发现的问题 | ✅ |
| `ai4security/02-php2shell-case/` | PHP2Shell（CVE-2026-109618/109619）从情报到定位、补丁、WAF 规则的推演，附自查命令 | ✅ |
| `security4ai/01-litellm-case/` | LiteLLM 2026 漏洞时间线、攻击链、根因分类与 AI 网关加固清单 | ✅ |
| `security4ai/02-mcp-agent-threats/` | MCP / Agent 信任边界与 12 类威胁，对照 OWASP LLM Top 10 2025 与 Agentic 威胁清单 | ✅ |
| `patterns/` | 从深读中提炼的可复用设计模式 | ✅ |
| `checklists/` | 上线前安全检查清单：AI 网关、Agent 与 MCP、漏洞响应准备 | ✅ |
| `scripts/` | `check_source_links.py` 校验文档里的源码行链接；`sample_citations.py` 抽样对照引用与源码 | ✅ |

## 功能 / 内容列表

- Security Radar 源码深读三篇，全部源码行引用（约 490 处）可用脚本校验
- PHP2Shell 案例推演（ai4security）
- LiteLLM 漏洞链案例与 AI 网关加固清单（security4ai）
- MCP / Agent 威胁模型（security4ai）
- 可复用设计模式与上线前检查清单
- 源码引用校验脚本

## 参考

- 博客：[从安全头条到代码补丁：用 AWS Continuum 与 AWS WAF 构建安全事件雷达](https://aws.amazon.com/cn/blogs/china/security-aws-continuum-aws-waf-build-security-event)
- 示例：[aws-samples/sample-security-radar](https://github.com/aws-samples/sample-security-radar)

## License

MIT-0，见 [LICENSE](LICENSE)。
