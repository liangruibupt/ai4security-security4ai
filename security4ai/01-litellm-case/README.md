# 案例：LiteLLM 2026 年漏洞链

LiteLLM 是 BerriAI 维护的开源 AI 网关（AI gateway）和 Python SDK。它把 100 多家大模型提供商的接口统一成 OpenAI 兼容格式。以代理（proxy）模式部署时，它集中保存所有上游提供商的 API Key、虚拟 Key、预算和日志（[CSA 研究笔记](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/06/CSA_research_note_litellm-ai-gateway-critical-vuln-chain_20260616-csa-styled.pdf)）。

2026 年 3 月到 9 月，LiteLLM 先后出现一次 PyPI 供应链投毒、一个未认证 SQL 注入、一个 MCP 测试端点命令注入，以及多个权限提升和 SSRF 漏洞。其中至少两个被 CISA（美国网络安全与基础设施安全局）列入已知被利用漏洞目录（KEV, Known Exploited Vulnerabilities）。

本文只讨论成因、影响和防护，不提供可用的利用载荷。

## 1. 时间线

CVSS 列优先给出 GitHub 安全公告（GHSA）的 CVSS 4.0 分数，括号内为 NVD 的 CVSS 3.1 分数。"已被利用"只记录有公开证据的情况。

| 日期（UTC） | CVE / 事件 | 类别 | CVSS | 受影响版本 | 修复版本 | 已被利用？ |
|---|---|---|---|---|---|---|
| 2026-02-19 | Obsidian Security 向 BerriAI 报告 CVE-2026-47101/47102/40217（[Obsidian](https://www.obsidiansecurity.com/blog/litellm-privilege-escalation-rce)） | 越权 / 提权 / 沙箱逃逸 | 见下方各行 | 见下方各行 | 见下方各行 | 报告时未公开 |
| 2026-03-24 | PyPI 供应链投毒，恶意包 `litellm==1.82.7`、`1.82.8`（[LiteLLM 官方公告](https://docs.litellm.ai/blog/security-update-march-2026)） | 供应链 / 凭据窃取 | 9.4（CVE-2026-33634，见注 1） | 仅 1.82.7、1.82.8 | 已下架；1.83.0 由新 CI/CD 流水线发布 | 是。恶意包本身就是攻击 |
| 2026-04-06 | CVE-2026-35030（[GHSA-jjhc-v7c2-5hh6](https://github.com/BerriAI/litellm/security/advisories/GHSA-jjhc-v7c2-5hh6)） | 认证绕过（OIDC 缓存键碰撞） | 9.4（9.1） | < 1.83.0，且仅在 `enable_jwt_auth: true` 时 | 1.83.0 | 未见公开报告 |
| 2026-04-06 | CVE-2026-35029（[GHSA-53mr-6c8q-9789](https://github.com/BerriAI/litellm/security/advisories/GHSA-53mr-6c8q-9789)） | `/config/update` 缺少角色校验，可至 RCE | 8.7（8.8） | < 1.83.0 | 1.83.0 | 未见公开报告 |
| 2026-04-10 | CVE-2026-40217（[X41 D-Sec 公告](https://www.x41-dsec.de/lab/advisories/x41-2026-001-litellm/)） | 自定义代码 guardrail 沙箱逃逸，RCE | —（8.8） | 截至 2026-04-08 的版本 | 1.83.10-stable 引入 RestrictedPython 沙箱（[Obsidian](https://www.obsidiansecurity.com/blog/litellm-privilege-escalation-rce)） | 未见公开报告 |
| 2026-04-19 | 1.83.7-stable 发布，修复 42208 与 42271（[THN](https://thehackernews.com/2026/04/litellm-cve-2026-42208-sql-injection.html)） | — | — | — | — | — |
| 2026-04 公开 | CVE-2026-42208（[GHSA-r75f-5x8p-qvmc](https://github.com/advisories/GHSA-r75f-5x8p-qvmc)） | 未认证 SQL 注入 | 9.3（9.8） | 1.81.16 ≤ v < 1.83.7 | 1.83.7 | 是。2026-04-26 16:17 首次观测到攻击；2026-05-08 入 KEV |
| 2026-05-21 | CVE-2026-47101（NVD 发布） | 越权：`allowed_routes` 未校验 | 8.7（8.8） | < 1.83.14 | 1.83.14-stable | 未见公开报告 |
| 2026-05-21 | CVE-2026-47102（NVD 发布） | 提权：`/user/update` 缺字段级授权 | 8.7（8.8） | < 1.83.10 | 1.83.10-stable | 未见公开报告 |
| 2026-05-26 | CVE-2026-48710（Starlette "BadHost"，[GHSA-86qp-5c8j-p5mr](https://github.com/Kludex/starlette/security/advisories/GHSA-86qp-5c8j-p5mr)） | Host 头校验绕过（依赖库） | —（6.5） | Starlette < 1.0.1 | Starlette 1.0.1 | 2026-09-02 入 KEV |
| 2026-06-08 | CVE-2026-42271（[GHSA-v4p8-mg3p-g94g](https://github.com/BerriAI/litellm/security/advisories/GHSA-v4p8-mg3p-g94g)） | MCP 测试端点命令注入 | 8.7（8.8） | 1.74.2 ≤ v < 1.83.7 | 1.83.7 | 是。2026-06-08 入 KEV，联邦机构修复期限 2026-06-22（[THN](https://thehackernews.com/2026/06/litellm-flaw-cve-2026-42271-exploited.html)） |
| 2026-09-02 | CVE-2026-84377（[Red Hat](https://access.redhat.com/security/cve/cve-2026-84377)） | SSRF，泄露提供商凭据 | —（6.5） | < 1.88.6；以及 1.89–1.96 各分支的早期补丁版本 | 1.88.6、1.89.7、1.90.7、1.91.5、1.92.2、1.93.2、1.94.3、1.95.1、1.96.2（[Docker Scout](https://scout.docker.com/v/CVE-2026-84377?n=litellm&s=github&t=pypi&vr=%3C1.88.6)） | 未见公开报告 |

注：

1. NVD 把 [CVE-2026-33634](https://nvd.nist.gov/vuln/detail/CVE-2026-33634) 描述为 Trivy（Aqua Security 的开源扫描器）的发布凭据被盗事件，引用列表里包含 LiteLLM 的公告，CISA 于 2026-03-26 将其列入 KEV。CSA 笔记把这个编号直接对应到 LiteLLM 投毒事件。LiteLLM 投毒是否有单独的 CVE 编号，**未证实**。
2. 恶意包在 PyPI 上的存活时间说法不一。LiteLLM 官方称 10:39 起约 40 分钟（[官方公告](https://docs.litellm.ai/blog/security-update-march-2026)）；Wiz 称约 08:30 发布、11:25 被隔离（[Wiz](https://www.wiz.io/blog/threes-a-crowd-teampcp-trojanizes-litellm-in-continuation-of-campaign)）。官方建议把 10:39 至 16:00 之间做过 `pip install` 的环境都视为可能受影响。
3. "36 小时内被利用"是标题说法。Sysdig 记录的首次攻击发生在 GitHub Advisory Database 收录公告后约 26 小时 7 分钟（[THN 引用 Sysdig](https://thehackernews.com/2026/04/litellm-cve-2026-42208-sql-injection.html)）。
4. CVE-2026-42208 的修复版本：厂商公告写 1.83.7；CSA 建议直接升到 1.83.10-stable，并同时把 Starlette 升到 1.0.1（[CSA](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/06/CSA_research_note_litellm-ai-gateway-critical-vuln-chain_20260616-csa-styled.pdf)）。考虑到 CVE-2026-84377，今天（2026-11-11）的最低目标版本应是所在分支的 SSRF 修复版本。
5. 任务线索里写 CVE-2026-84377 "泄露提供商凭据"。这一点与 NVD 描述一致，但它需要已认证用户，CVSS 3.1 只有 6.5（中危）。

## 2. 为什么 AI 网关是高价值目标

普通 Web 应用的 SQL 注入通常泄露一个业务库。AI 网关的数据库里存的是**所有上游凭据**。Sysdig 观察到，攻击者直接查询保存提供商密钥的 `litellm_credentials` 和保存运行时环境的 `litellm_config`，没有去碰用户表和团队表（[THN 引用 Sysdig](https://thehackernews.com/2026/04/litellm-cve-2026-42208-sql-injection.html)）。Sysdig 的判断是，这类数据库被拖走，影响更接近一次云账号失陷。

Obsidian 列出了网关被完全控制后的可达范围（[Obsidian](https://www.obsidiansecurity.com/blog/litellm-privilege-escalation-rce)）：

- 主机级密钥：`LITELLM_MASTER_KEY`、用于解密库内凭据的 `LITELLM_SALT_KEY`、`DATABASE_URL`。
- 所有提供商的 Key：OpenAI、Anthropic、Gemini、Bedrock、Azure 等。配置文件和环境变量里的是明文；数据库里的是密文，但拿到 salt key 即可解密。
- MCP 与智能体凭据：网关兼做 MCP 网关时，还包括 OAuth token、SaaS API Key、工具凭据。
- 对话内容：经网关的提示词、回复和日志。
- **中间人位置**：网关夹在智能体和模型之间，攻击者可以改写模型回复，伪造工具调用，让下游智能体在开发者机器上执行命令。Obsidian 用 LiteLLM 的回调（callback）机制演示了这一点。回调从配置加载，不在管理界面显示。

所以，网关的安全等级应当等于它所托管的全部提供商账号的安全要求之和（[CSA](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/06/CSA_research_note_litellm-ai-gateway-critical-vuln-chain_20260616-csa-styled.pdf)）。

## 3. 攻击链

下面按入口分成四条链。它们的终点相同：拿到网关进程权限或其数据库，进而拿到所有上游凭据。

### 3.1 供应链：Trivy → PyPI 发布凭据 → 恶意包

1. 2026-03-19，TeamPCP 组织用盗来的凭据发布了恶意 Trivy 版本，并改写了 `trivy-action` 的大部分版本标签（[NVD CVE-2026-33634](https://nvd.nist.gov/vuln/detail/CVE-2026-33634)）。
2. LiteLLM 的 CI/CD 用 Trivy 做安全扫描。被投毒的 Trivy 在流水线里运行，把 PyPI 发布 token 外传（[CSA](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/06/CSA_research_note_litellm-ai-gateway-critical-vuln-chain_20260616-csa-styled.pdf)）。
3. 攻击者绕过官方 CI 直接上传 1.82.7 和 1.82.8。GitHub 仓库里没有恶意代码（[LiteLLM 官方公告](https://docs.litellm.ai/blog/security-update-march-2026)）。
4. 1.82.7 在启动代理或导入 `litellm.proxy.proxy_server` 时执行载荷。1.82.8 额外放了一个 `litellm_init.pth`，利用 Python 的 `.pth` 机制，**任何** Python 进程启动都会执行，不需要导入 LiteLLM（[Wiz](https://www.wiz.io/blog/threes-a-crowd-teampcp-trojanizes-litellm-in-continuation-of-campaign)）。
5. 载荷收集环境变量、SSH 密钥、云凭据、Kubernetes 配置、CI/CD 密钥，加密后外传，并尝试在 Kubernetes 内横向移动和持久化（[Wiz](https://www.wiz.io/blog/threes-a-crowd-teampcp-trojanizes-litellm-in-continuation-of-campaign)、[Trend Micro](https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html)）。

官方 Docker 镜像不受影响，因为它在 `requirements.txt` 里锁定了依赖版本（[LiteLLM 官方公告](https://docs.litellm.ai/blog/security-update-march-2026)）。未锁版本的 `pip install litellm`，或经智能体框架、MCP 服务器间接引入的未锁依赖，才会拉到恶意版本。

### 3.2 未认证 SQL 注入：CVE-2026-42208

- 校验代理 API Key 时，有一条查询把调用方提供的 Key 拼进了 SQL 文本，没有用参数绑定（[GHSA-r75f-5x8p-qvmc](https://github.com/advisories/GHSA-r75f-5x8p-qvmc)）。
- 这条查询在错误处理路径上，位于认证决策之前。任何能访问代理端口的客户端都能通过构造的 `Authorization` 头触发它，比如请求 `POST /chat/completions`。
- 结果：读取并可能修改代理数据库，包括虚拟 Key、提供商凭据和配置。
- 无法立即升级时，厂商给出的临时缓解是在 `general_settings` 下设置 `disable_error_logs: true`，切断不可信输入到达该查询的路径（[THN](https://thehackernews.com/2026/04/litellm-cve-2026-42208-sql-injection.html)）。

### 3.3 MCP 测试端点命令注入：CVE-2026-42271 + CVE-2026-48710

- `POST /mcp-rest/test/connection` 和 `POST /mcp-rest/test/tools/list` 用于保存前预览一个 MCP 服务器。它们接受完整的服务器配置，包括 stdio 传输用到的 `command`、`args`、`env` 字段（[THN](https://thehackernews.com/2026/06/litellm-flaw-cve-2026-42271-exploited.html)）。
- 端点会真正尝试连接，于是以代理进程的权限在主机上启动请求里给出的命令。
- 端点只要求一个有效的代理 API Key。保存端点要求 `PROXY_ADMIN`，测试端点却没有，权限不一致。1.83.7 把测试端点也改成需要 `PROXY_ADMIN`。
- Horizon3.ai 把它和 Starlette 的 Host 头绕过（CVE-2026-48710）串起来，绕过认证，得到未认证 RCE，并评估链式 CVSS 为 10.0（[THN](https://thehackernews.com/2026/06/litellm-flaw-cve-2026-42271-exploited.html)）。Starlette 的问题在于：路由用原始路径，而 `request.url` 由 Host 头重建，两者可以不一致，依赖 `request.url` 做访问控制的中间件就会被绕过（[NVD CVE-2026-48710](https://nvd.nist.gov/vuln/detail/CVE-2026-48710)）。

Obsidian 还指出一个设计层面的取舍：即便在当前版本，`proxy_admin` 注册 stdio MCP 服务器本身就意味着能在网关主机上执行命令。命令白名单只是把这条执行路径挪到了更严格的授权之后（[Obsidian](https://www.obsidiansecurity.com/blog/litellm-privilege-escalation-rce)）。因此，**拿到 `proxy_admin` 就等于拿到主机**。

### 3.4 低权限用户 → 管理员 → RCE：CVE-2026-47101 / 47102 / 40217

Obsidian 把这三个漏洞组合成 CVSS 9.9 的链（[Obsidian](https://www.obsidiansecurity.com/blog/litellm-privilege-escalation-rce)）：

1. **CVE-2026-47101**：`/key/generate`、`/key/update` 等接口把调用方提交的 `allowed_routes` 原样写库。这个字段本意是收窄 Key 的权限，但路由检查把它当作兜底授权。默认的 `internal_user` 可以给自己签发一个能访问管理路由的 Key。
2. **CVE-2026-47102**：`/user/update` 只检查"是否在改自己"，不限制可改字段。用户可以把自己的 `user_role` 改成 `proxy_admin`。`org_admin` 无需前一个漏洞就能直接做到。
3. **CVE-2026-40217**：自定义代码 guardrail 用 `exec()` 运行用户代码，但没有清空 `__builtins__`，Python 会自动注入完整的内置模块。测试端点的正则黑名单可被运行时字节码改写绕过（X41 D-Sec 发现）；生产端点则根本没有黑名单。

Obsidian 总结的根因是：每一层都假设前一层已经检查过。路由层信任字段，处理函数信任路由层，实际没有人做最终校验。

### 3.5 SSRF 泄露凭据：CVE-2026-84377

已认证用户可以在请求里带上 `api_base`、`base_url`、`model_list`、`fallbacks`、`litellm_credential_name` 等路由或凭据参数，把出站的提供商调用改到自己控制的地址。代理会带着运营方配置的提供商 Key 去请求这个地址（[NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-84377)）。原有校验没有覆盖所有敏感参数，也没有检查嵌套字段、路径参数和方括号形式的表单数据。这个漏洞同时允许请求代理能访问到的内网服务（[Red Hat](https://access.redhat.com/security/cve/cve-2026-84377)）。

## 4. 根因分类

| 根因类别 | 对应漏洞 | 说明 |
|---|---|---|
| 未参数化查询 | CVE-2026-42208 | 认证前路径拼接 SQL。经典 Web 漏洞，出现在新的 AI 组件里。 |
| 授权只做在路由层，处理函数不复核 | 35029、42271、47101、47102 | 敏感操作（改配置、启动子进程、改角色、签发 Key）缺少处理函数级、字段级授权。 |
| 同类端点权限不一致 | 42271 | "测试"端点与"保存"端点做同样危险的事，但权限更低。 |
| 不安全的动态执行 | 40217、42271、stdio MCP | `exec()`、子进程启动。黑名单式沙箱可被绕过。 |
| 弱缓存键 / 弱密码学 | 35030、GHSA-69x8-hrgq-fjj8 | 用 token 前 20 字符做缓存键；口令用无盐 SHA-256 存储，且登录接口接受哈希本身（[LiteLLM 安全加固公告](https://docs.litellm.ai/blog/security-hardening-april-2026)）。 |
| 出站目标可被请求控制 | 84377 | 请求参数决定上游地址，凭据随请求外发。 |
| 依赖库缺陷 | 48710（Starlette） | 框架层 URL 重建与路由不一致，访问控制被绕过。 |
| 构建与发布链信任过宽 | 33634 / 1.82.7–1.82.8 | 安全扫描器在持有发布凭据的 CI 环境里运行，被投毒后直接拿走 PyPI token。 |
| 凭据集中存放 | 全部 | 网关把所有提供商 Key 放在同一个库和同一个进程里，任一入口失守，影响面就是全部。 |

## 5. AI 网关加固清单

适用于 LiteLLM，也适用于其他自建 AI 网关、模型路由器和 MCP 网关。

### 5.1 网络暴露

- [ ] 代理端口不直接暴露到公网。只允许内部已认证客户端访问，或放在自带认证的 API 网关之后（[CSA](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/06/CSA_research_note_litellm-ai-gateway-critical-vuln-chain_20260616-csa-styled.pdf)）。
- [ ] 网关主机和它的 PostgreSQL 单独分段，与普通办公网隔离。
- [ ] 管理界面和管理 API 走独立的监听地址或独立域名，仅限运维网段访问。

### 5.2 认证与授权

- [ ] 不用的认证方式就关掉。例如未使用 JWT/OIDC 时不开 `enable_jwt_auth`。
- [ ] 定期审计 `proxy_admin`、`org_admin` 账号，把 `proxy_admin` 当作主机 root 级权限管理（[Obsidian](https://www.obsidiansecurity.com/blog/litellm-privilege-escalation-rce)）。
- [ ] 审计已签发虚拟 Key 的 `allowed_routes`，清理含通配符或管理路由的 Key。
- [ ] 主密钥（master key）只用于引导，日常调用使用有范围和预算的虚拟 Key。

### 5.3 密钥存储

- [ ] 提供商 Key 用最小权限：只开推理权限，不给账号管理权限（[CSA](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/06/CSA_research_note_litellm-ai-gateway-critical-vuln-chain_20260616-csa-styled.pdf)）。
- [ ] 能用密钥管理服务（HashiCorp Vault、AWS Secrets Manager 等）在运行时注入的，就不要落在网关数据库里。
- [ ] `LITELLM_SALT_KEY` 与数据库凭据分开存放。拿到其一不应能直接解密全部凭据。
- [ ] 在提供商侧设置用量上限和异常告警，作为泄露后的兜底。
- [ ] 一旦怀疑失陷：轮换所有提供商 Key、数据库口令、MCP token、云凭据和 CI/CD token。没有发现入侵迹象不等于没有被拖库（[CSA](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/06/CSA_research_note_litellm-ai-gateway-critical-vuln-chain_20260616-csa-styled.pdf)）。

### 5.4 管理路由与可执行扩展

- [ ] 在反向代理层只放行业务需要的路由（如 `/chat/completions`、`/embeddings`），默认拒绝 `/key/*`、`/user/*`、`/config/*`、`/guardrails/*` 等管理路由，除非来源是运维网段。
- [ ] 审计所有自定义代码 guardrail 和 `litellm_settings.callbacks`。回调不在管理界面显示，失陷后常被用来驻留（[Obsidian](https://www.obsidiansecurity.com/blog/litellm-privilege-escalation-rce)）。
- [ ] 校验部署代码的完整性（镜像摘要、文件哈希），而不只是检查配置。

### 5.5 MCP 端点

- [ ] 未升级前，在反向代理或 WAF 上拦截 `POST /mcp-rest/test/connection` 和 `POST /mcp-rest/test/tools/list`（[THN](https://thehackernews.com/2026/06/litellm-flaw-cve-2026-42271-exploited.html)）。
- [ ] 尽量不在网关上启用 stdio 传输的 MCP 服务器。确需使用时放进单独的容器或沙箱，限制文件系统和网络（[MCP 安全最佳实践](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)）。
- [ ] 记录所有子进程启动事件，作为检测信号。

### 5.6 出站白名单（防 SSRF）

- [ ] 网关的出站流量只允许到已知提供商的域名，用出口代理或安全组强制执行。
- [ ] 禁止网关访问云元数据地址 `169.254.169.254`、链路本地和私有网段。在 AWS 上启用 IMDSv2 并把跳数限制设为 1（[AWS 文档](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)）。
- [ ] 禁止客户端在请求里指定 `api_base`、`base_url`、`litellm_credential_name` 等参数，或在边缘层剥离这些字段（对应 CVE-2026-84377）。

### 5.7 依赖与构建

- [ ] 锁定版本并校验哈希：`pip install --require-hashes -r requirements.txt`（[pip 文档](https://pip.pypa.io/en/stable/topics/secure-installs/)），或使用 `uv.lock` / `poetry.lock`。LiteLLM 官方镜像正是因为锁了依赖而躲过投毒。
- [ ] 不在生产镜像构建里写未锁版本的 `pip install litellm`。同时检查间接依赖：智能体框架和 MCP 服务器也可能引入 LiteLLM。
- [ ] 为每个镜像生成 SBOM（软件物料清单，如 CycloneDX 或 SPDX 格式），漏洞公告一出即可反查。
- [ ] CI 中的第三方工具（包括安全扫描器）按不可信对待：按提交哈希固定 GitHub Action，扫描任务不接触发布凭据，发布使用 PyPI 可信发布（[Trusted Publishers](https://docs.pypi.org/trusted-publishers/)，基于 OIDC）而不是长期 token。
- [ ] 排查是否装过 1.82.7/1.82.8：检查锁文件、镜像层，以及 `site-packages` 下是否有 `litellm_init.pth`。

### 5.8 WAF 规则（升级前的临时补偿）

- [ ] 按路径拦截：MCP 测试端点、管理路由。
- [ ] 按请求体字段拦截：业务请求中出现 `api_base`、`base_url`、`model_list`、`fallbacks`、`litellm_credential_name` 时拒绝或剥离。
- [ ] 拒绝 Host 头与预期域名不一致的请求（对应 Starlette CVE-2026-48710）。
- [ ] `Authorization` 头做长度和字符集校验，只接受预期的 Key 格式。这只能降低风险，不能替代升级。

### 5.9 监控

- [ ] 打开 PostgreSQL 查询日志，关注认证查询中的异常 bearer token 值（[CSA](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/06/CSA_research_note_litellm-ai-gateway-critical-vuln-chain_20260616-csa-styled.pdf)）。
- [ ] 告警：网关进程派生 shell 或非预期子进程；网关出站到非白名单地址；异常 Host 头；对 `litellm_credentials`、`litellm_config` 的读取量突增。
- [ ] 告警：新增 `proxy_admin`、角色变更、新增 guardrail 或回调、新签发带管理路由的 Key。
- [ ] 订阅 GitHub 安全公告、OSV 和 CISA KEV，按"公告到被利用约 1 天"的节奏准备响应。

## 6. AI for Security 怎么帮忙

CVE-2026-42208 从公告收录到首次被利用只隔了约 26 小时，攻击者没有等公开 PoC，凭公告和开源的数据库表结构就动手了（[THN 引用 Sysdig](https://thehackernews.com/2026/04/litellm-cve-2026-42208-sql-injection.html)）。人工流程（看到新闻 → 找负责人 → 找部署 → 排期升级）通常以天或周计，赶不上这个节奏。

下面是一条 Security-Radar 式流水线，按"先在边缘止血、再修代码"的顺序走：

| 阶段 | 做什么 | 对 LiteLLM 事件的具体作用 |
|---|---|---|
| 1. 收集 | 持续拉取 GHSA、OSV、NVD、CISA KEV、厂商博客。用 LLM 把公告归一化为结构化字段：包名、受影响区间、修复版本、前置条件、临时缓解。 | 42208 公告里的"受影响 1.81.16 至 1.83.7 之前"和"`disable_error_logs: true` 可缓解"在收录后几分钟内变成机器可用的数据。 |
| 2. 定位 | 在所有仓库里搜索 `requirements*.txt`、`pyproject.toml`、`poetry.lock`、`uv.lock`、`Pipfile.lock`、Dockerfile 中的 `pip install`、Helm values 和 K8s 清单里的镜像标签，精确到 `文件:行号`；再结合 SBOM 找间接依赖。 | 直接列出"`infra/gateway/requirements.txt:14` 锁定 `litellm==1.82.6`""`charts/ai-gw/values.yaml:9` 用的是 `main-v1.81.x` 标签"。对投毒事件，可同时找出锁到 1.82.7/1.82.8 的位置和未锁版本的位置。 |
| 3. 验证 | 判断是否真的可达：该部署是否暴露在不可信网络；是否开启 `enable_jwt_auth`（35030 的前提）；是否启用 MCP 网关（42271）；Starlette 版本是否 ≤ 1.0.0（48710）。只读检查，不发攻击流量。 | 过滤掉不满足前提的告警。例如没开 JWT 的部署对 35030 降级处理，把人力集中到公网可达且版本落在 42208 区间的实例。 |
| 4. 边缘缓解（先做） | 自动生成并提交 WAF / 反向代理规则变更，以及配置开关变更，走人工审批后下发。 | 在补丁上线前几小时内拦截 `/mcp-rest/test/*`、剥离 `api_base` 类字段、下发 `disable_error_logs: true`。这些动作可逆，风险低，可以先于升级完成。 |
| 5. 修复 PR | 生成升级 PR：改版本号、重新生成带哈希的锁文件、附上公告链接、受影响位置、验证结论和回滚方式。CI 跑通后交给负责人合并。 | 把"知道要升级"到"PR 已就绪"的时间压到小时级。 |
| 6. 善后 | 生成凭据轮换工单（提供商 Key、数据库口令、MCP token），附检测查询（PostgreSQL 日志、子进程事件、出站流量）。 | 对 42208 这类可能已拖库的漏洞，升级之后还要轮换，否则泄露的 Key 仍然有效。 |

需要人工把关的地方：

- WAF 规则和配置变更下发前需要人工审批。误拦业务路由会造成中断。
- 自动 PR 只改版本和锁文件，不自动合并。
- 流水线本身要按本仓库 `security4ai` 部分的要求设计：公告内容和仓库内容都是不可信数据，LLM 只做抽取和定位，不根据公告文本执行命令。

---

Content was rephrased for compliance with licensing restrictions
