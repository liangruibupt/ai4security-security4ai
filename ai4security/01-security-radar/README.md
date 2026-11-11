# Security Radar 源码深读

对象：[aws-samples/sample-security-radar](https://github.com/aws-samples/sample-security-radar)，提交 `7d5362e`（2026-11-01）。配套博客：[从安全头条到代码补丁：用 AWS Continuum 与 AWS WAF 构建安全事件雷达](https://aws.amazon.com/cn/blogs/china/security-aws-continuum-aws-waf-build-security-event)。

它是 AWS Continuum 前面的「探测器 + 触发器」：每 10 分钟采集公开情报，用代码判定真实性和紧急度，把相关事件定位到你代码里的 `文件:行`，交给 AWS Security Agent 和 AWS Continuum 证实并以 PR / MR 交付补丁；补丁上线前用 AWS WAF 和 Route 53 Resolver DNS Firewall 在边缘先观察、后拦截。

## 阅读顺序

| 篇 | 内容 |
|---|---|
| [01 整体架构与工程护栏](01-architecture-and-guardrails.md) | 三个 CDK 栈与 Region 划分、Step Functions 工位、信源健康、DynamoDB 单表、部署顺序、IAM 最小权限测试、变异注册表、成本护栏 |
| [02 代码判定与大模型约束](02-decisions-in-code.md) | 去重聚类、独立来源计数、真实性 V0–V4、严重度 P0–P2、链上回执、IOC 提取、逐句引用校验、疑似重复提示 |
| [03 定位、Continuum 与边缘缓解](03-respond-and-mitigate.md) | 资格门、定位到行、Security Agent 规则包、OCSF finding、Continuum 环境与 PR 交付、Inspector ScanSbom、WAF / DNS Firewall 计划与核查 |
| [PHP2Shell 案例](../02-php2shell-case/README.md) | 用示例里的 demo-shop 目标走一遍：分级、定位、补丁、WAF 规则 |

文中每条结论都带源码行链接。`scripts/check_source_links.py` 可校验全部链接指向的文件和行存在：

```bash
python3 scripts/check_source_links.py <sample-security-radar 本地 clone，检出 7d5362e>
```

## 读源码时发现的问题

以下问题在对应文档里有详细说明和代码位置，尚未向上游报告。

| 问题 | 影响 | 位置 |
|---|---|---|
| `destroy-stage.sh` 第 10 行的 `#` 注释把 `python -` 的参数和 `<<'PY'` heredoc 一起注释掉，heredoc 内容被当作 shell 执行 | 在 `set -e` 下脚本中途退出，走不到 `cdk destroy` | [01](01-architecture-and-guardrails.md) |
| cdk-nag 的 DDB3 抑制理由说不需要时间点恢复，但栈实际已开启 | 抑制多余，误导读者 | [01](01-architecture-and-guardrails.md) |
| 任一条目（哪怕 T3 推文）链接的成功交易都能把 Web3 事件升到 V2 | 金额 ≥ 100 万美元时直接成为 P0 | [02](02-decisions-in-code.md) |
| 数字校验是子串匹配 | 原文有 `2010` 时句中的 `10` 也能通过 | [02](02-decisions-in-code.md) |
| Bedrock 返回未列出的停止原因且有文本时，被当作 `ok` | 异常结束的输出可能被当作正常 | [02](02-decisions-in-code.md) |
| `coverage.py` 注释写扫描去抖 6 小时，`Limits` 实际是 24 小时 | 注释与代码不一致 | [03](03-respond-and-mitigate.md) |
| mock 数据的 PHP2Shell 补丁：Dockerfile hunk 与目标文件不一致、注释声称修复了证据里未修复的 CVE、`composer.json` 里的 `"php": "^8.3"` 未改 | 演示数据不自洽 | [PHP2Shell 案例](../02-php2shell-case/README.md) |

B 篇还列出了常量未使用、`limits.py` 注释与代码不符等较小问题。

## 测试

在本地只读运行了相关测试，没有部署任何 AWS 资源：架构相关 6 个测试文件 312 个通过，判定相关 9 个测试文件 185 个通过。
