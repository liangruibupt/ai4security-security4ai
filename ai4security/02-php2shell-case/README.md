# PHP2Shell 案例：雷达怎么从一条漏洞新闻走到一份补丁

本文用一个真实事件，把 [aws-samples/sample-security-radar](https://github.com/aws-samples/sample-security-radar)（提交 `7d5362e`）的整条链路串起来。事件是 PHP2Shell：CVE-2026-109618 和 CVE-2026-109619，两个 PHP 解释器内存安全漏洞，可导致未认证远程代码执行（Remote Code Execution，RCE）。

文中用到三类材料：

- 源仓库代码。路径相对于仓库根目录，链接前缀为 `https://github.com/aws-samples/sample-security-radar/blob/7d5362e/`。
- 演示目标 `integrations/continuum/targets/demo-shop`。这是一个故意钉在受影响版本上的小商城，不要部署。
- `ui/mock-data/data/` 下的示例数据。仓库 README 说明它只用于本地开发（[README.md:107](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/README.md#L107)）。其中分析卡的句子是占位文本，不是模型输出。

本文不包含任何可用的利用代码。

## 1. 外部事实

以下内容转述自三篇公开分析，日期都是 UTC。

- **漏洞本身**：两个漏洞的 CVSS v4.0 评分都是 9.2。按 Datadog 的描述，CVE-2026-109618 是内存分配失败后，PHP 把未初始化的数据留给清理流程处理；CVE-2026-109619 是工作进程把上一个请求的过期状态带进了下一个请求，属于释放后使用（use-after-free）。恶意请求在应用代码运行之前就被 PHP 处理，所以应用层认证挡不住（[Datadog Security Labs](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)）。
- **影响范围**：所有处理 Web 请求的 PHP 运行方式都在范围内，包括 Apache 模块、PHP-FPM、php-cgi、FrankenPHP 和 LiteSpeed。盘点时要包括自带 PHP 解释器的容器。命令行的 `php` 可能和实际服务网页的运行时版本不同（[Datadog](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)）。
- **时间线**：细节在 2026-10-20 泄露，比计划的协调披露早两天，PHP 因此把发布提前到 10-21（[Pentest-Tools.com](https://pentest-tools.com/research/php2shell-rce)）。10-21 14:00 发布修复版本（[Sansec](https://sansec.io/research/php2shell)）。
- **补丁前已被利用**：Amazon 在 10-17 就在蜜罐上看到了利用尝试，比公开披露早四天（[Datadog](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)，[Pentest-Tools.com](https://pentest-tools.com/research/php2shell-rce)）。Cloudflare 报告 10-21 07:43 出现攻击，早于当天的补丁发布（[Sansec](https://sansec.io/research/php2shell)）。
- **修复版本**：8.2.35、8.3.36、8.4.27、8.5.12。8.1 及更早版本没有官方发布版，PHP 安全团队只为 7.4、8.0、8.1 提供了源码补丁。发行版的回移植包可能保留原来的版本号，要查包的更新日志，不能只看版本字符串（[Sansec](https://sansec.io/research/php2shell)，[Pentest-Tools.com](https://pentest-tools.com/research/php2shell-rce)）。
- **临时缓解只是部分有效**：社区流传的 `session.upload_progress.enabled=0` 和 `memory_limit=-1` 只能降低暴露，三篇文章都说只有升级才是完整修复（[Datadog](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)，[Sansec](https://sansec.io/research/php2shell)，[Pentest-Tools.com](https://pentest-tools.com/research/php2shell-rce)）。

来源之间有两处不一致，引用时要注意：

- Sansec 对"哪个 CVE 是哪类缺陷"的归类，和 Datadog 的描述不同。
- Sansec 引述一位研究者的测试：公开的 PoC 对默认安装的 PHP 不起作用，大多数需要目标应用本身有本地文件包含漏洞。Datadog 则在自己的实验环境里复现了命令执行。

所以"是否容易利用"有争议，"必须升级"没有争议。

雷达的证据里还出现了第三个 CVE：CVE-2026-115560。事件里 10-23 的几条 X 帖子说，它和 PHP2Shell 是两回事，不在 10-21 的紧急更新里，PHP 给了一行缓解配置（`ui/mock-data/data/events/ev_bb65db3b8694e5f4.json` 的 `items`）。这一点在第 4.5 节会用到。

## 2. 演示目标 demo-shop

`demo-shop` 有四个文件。PHP 8.3.30 钉在三处。

`Dockerfile`（[第 1 行](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/integrations/continuum/targets/demo-shop/Dockerfile#L1)）：

```dockerfile
FROM public.ecr.aws/docker/library/php:8.3.30-apache
COPY src/ /var/www/html/
RUN docker-php-ext-install pdo_mysql
```

`composer.json`（[第 8 行](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/integrations/continuum/targets/demo-shop/composer.json#L8)）：

```json
{
  "name": "demo/shop",
  "require": {
    "php": "^8.3"
  },
  "config": {
    "platform": {
      "php": "8.3.30"
    }
  }
}
```

`.gitlab-ci.yml`（[第 2 行](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/integrations/continuum/targets/demo-shop/.gitlab-ci.yml#L2)）：

```yaml
test:
  image: php:8.3.30-cli
  script: [php -v]
```

`src/index.php` 只是一个对输入做了 `htmlspecialchars` 的搜索页（[src/index.php:1-4](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/integrations/continuum/targets/demo-shop/src/index.php#L1)）。它本身没有漏洞，这正是 PHP2Shell 的特点：漏洞在解释器里，干净的应用代码也受影响。舰队仓库的 README 写明，demo-shop 故意出错的地方是三处 8.3.30 加上容器以 root 运行（[integrations/continuum/fleet-README.md:14](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/integrations/continuum/fleet-README.md#L14)）。

在演示配置里，demo-shop 走 GitHub 渠道（[src/radar/targets.py:25](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/targets.py#L25)）。

## 3. 事件定级：来源、V 级、P 级

示例事件是 `ev_bb65db3b8694e5f4`，标题取自最早的 T1 来源："PHP core RCE vulnerability patches (CVE-2026-109618 and CVE-2026-109619)"。它聚合了 20 条证据、8 个独立来源。

| 来源 | 等级 | 条数 | 说明 |
|---|---|---|---|
| Fortinet PSIRT | T1 | 1 | 10-21 07:00，最早一条，事件的首报来源 |
| CISA Advisories | T1 | 1 | 10-21 12:00，给出四个修复版本，当时 CISA 未观察到利用 |
| X 安全账号 | T1 / T2 | 7 | 1 条 T1，其余 T2；包括 CVE-2026-115560 的几条 |
| The Hacker News | T2 | 6 | 10-22 06:34 一条报道 Amazon 看到 10-17 的利用尝试，信号 `exploited: yes` |
| BleepingComputer | T2 | 2 | 修复公告、Amazon 的利用时间 |
| SecurityWeek | T2 | 2 | 利用早于补丁、厂商响应 |
| Odaily | T3 | 1 | 中文转述 |

定级逻辑都在 `src/radar/pipeline.py`。

**V 级（可信度）是 V3。** 漏洞事件只要有一个 T1 来源，且首见不满 14 天，就是 V3 "confirmed"（[pipeline.py:281-285](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/pipeline.py#L281)，`FINALIZE_QUIET_DAYS_VULN = 14` 见 [limits.py:15](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/limits.py#L15)）。示例数据里的 `level_reason` 是 `confirmed: T1 source (fortinet_psirt)`。

**利用状态是 `reported`，不是 `confirmed`。** `confirmed` 需要 CISA 已知被利用漏洞目录（Known Exploited Vulnerabilities，KEV）收录，或者 T1 来源明确说已被利用。这里说"已被利用"的是 T2 的 The Hacker News，KEV 也没收录，所以是 `reported`（[pipeline.py:296-299](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/pipeline.py#L296)）：

```python
if any(i.signals["kev"] or (i.tier == "T1" and i.signals["exploited"] == "yes") for i in items):
    return "confirmed"
if any(i.signals["exploited"] == "yes" for i in items):
    return "reported"
```

**P 级（严重度）是 P0。** 漏洞事件 `reported` 且 V 级不低于 V2，就是 P0（[pipeline.py:318-321](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/pipeline.py#L318)）。P0 还要求事件在 72 小时内首见或升级过，否则降为 P1（[pipeline.py:303-307](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/pipeline.py#L303)，[limits.py:21](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/limits.py#L21)）。示例事件的时间线显示，The Hacker News 那条利用报道并入后，严重度从 P2 升到 P0，利用状态从 `none` 变为 `reported`。

示例数据里的 EPSS（Exploit Prediction Scoring System，漏洞利用预测评分）：CVE-2026-109618 为 0.1162（百分位 0.960），CVE-2026-109619 为 0.0599（百分位 0.933）。两者都没有进 KEV。

## 4. 响应站：定位、评审、验证、补丁

### 4.1 资格门

P0 直接通过严重度门槛。标题里的 `PHP` 命中产品登记表（[src/radar/products.py:37](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/products.py#L37)）。`versions()` 从 CISA 的"update to PHP 8.5.12, 8.4.27, 8.3.36, or 8.2.35"和 The Hacker News 的"fixes are in PHP …"里抽出四个修复版本（[products.py:89-107](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/products.py#L89)）。

对测试夹具运行 `respond.eligibility()` 的结果是：

```
eligible: True · product: php · fixed: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 · affected: []
reason: P0 · 产品 PHP 命中登记表 · 修复版本 8.5.12/8.4.27/8.3.36/8.2.35 从证据逐字抽取
```

测试 `test_fixed_versions_are_extracted_verbatim_from_php2shell_evidence` 锁定了这个结果（[tests/test_respond.py:55](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/tests/test_respond.py#L55)）。

### 4.2 定位到文件:行

`products.inventory()` 在 demo-shop 里找到三处钉版本的位置。`verdict()` 在 8.3 分支内比较：8.3.30 低于 8.3.36，判 `affected`（[products.py:126-158](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/products.py#L126)）。

| 位置 | 类型 | 找到的版本 | 本分支修复版本 |
|---|---|---|---|
| `demo-shop/.gitlab-ci.yml:2` | CI 镜像 | 8.3.30 | 8.3.36 |
| `demo-shop/Dockerfile:1` | 运行时镜像 | 8.3.30 | 8.3.36 |
| `demo-shop/composer.json:8` | composer platform | 8.3.30 | 8.3.36 |

测试 `test_inventory_locates_every_php_pin_in_demo_shop_by_line` 断言的就是这三处（[tests/test_respond.py:69-72](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/tests/test_respond.py#L69)）。

有三个细节：

- `composer.json` 第 4 行的 `"php": "^8.3"` 不会被匹配。composer 定位器要求完整的 `x.y.z`（[products.py:41](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/products.py#L41)），而范围约束不是一个可以比较的版本。
- 示例数据 `events/ev_bb65db3b8694e5f4.json` 和 `continuum.json` 把 composer 的位置写成第 7 行，代码和测试算出来的是第 8 行。示例数据是手写的，以测试为准。
- 同一个 P0 事件下，`wp-storefront` 的 `wordpress:6.8.1-php8.3-apache` 只钉到分支 `8.3`。雷达判 `unknown`，但目标用到了 PHP，仍会发起付费评审（`test_php2shell_reviews_every_php_target_including_wordpress_image`，[tests/test_respond.py:305-308](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/tests/test_respond.py#L305)）。示例数据里的雷达自身仓库没有 PHP，判 `skipped`，原因是"清单中无 PHP，不评审（省费用）"。

### 4.3 AWS Security Agent

雷达生成的规则名是 `radar-cve-2026-109618-cve-2026-109619-cve-2026-115560`（[src/radar/respond.py:129-132](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/respond.py#L129)）。评估文本由 `requirement()` 生成（[respond.py:135-165](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/respond.py#L135)）：

```
Find every PHP runtime/dependency the code base builds or runs on (container base images, CI images,
runtime config, lock files). Fail if any PHP version is below the fixed release of its branch
(>= 8.5.12, >= 8.4.27, >= 8.3.36, >= 8.2.35) or its branch is not listed.
Affected: CVE-2026-109618, CVE-2026-109619, CVE-2026-115560.
```

示例数据记录的评审结果（`response.actions` 和 `response.findings`）：

- 评审耗时 27.1 分钟，结论 COMPLETED，共 3 个 finding。
- 命中雷达规则的 1 个："PHP runtime pinned to known-affected 8.3.30, below the fixed 8.3.36"，位置 `Dockerfile:1`，HIGH。
- 另外 2 个是评审顺带发现的："Container runs as root"（HIGH）和"Insecure default configuration"（MEDIUM）。
- 自动修复生成了一份 diff，改动 3 个文件，全部升到 8.3.36。

### 4.4 AWS Continuum

示例数据里，Continuum 一侧的进度是：

- 分析卡已作为知识文档写入 `context/`（[respond.py:192-206](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/respond.py#L192)）。
- 针对 `demo-shop/Dockerfile:1` 提交了一条 OCSF 2002 finding，状态 `SUBMITTED`。文档结构见本系列 [03-respond-and-mitigate.md 第 5.3 节](../01-security-radar/03-respond-and-mitigate.md)。
- 环境扫描状态 `BUILDING`。
- `issues` 为空。

也就是说，**在这份示例数据里，Continuum 还没有给出可利用性结论，也还没有生成补丁**。示例里唯一的补丁来自 Security Agent 的自动修复（`response.patches[0].source = "security_agent"`）。Continuum 验证完成后，结论（`CONFIRMED` / `DISCARDED`）、可利用性证据和补丁会经 `_read_env()` 取回（[src/radar/continuum_aws.py:315-368](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/continuum_aws.py#L315)）。因为 demo-shop 在 GitHub 渠道，补丁会由 Continuum 直接开成 PR。

示例的 `continuum.json` 里有一个成本账本：10-23 当天 Continuum 花费 726.29 美元，10-24 为 595.47 美元。这说明了为什么代码里有那么多扫描护栏（[respond.py:398-410](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/respond.py#L398)）。

### 4.5 补丁 diff

`ui/mock-data/data/continuum/patches/demo-shop-php2shell.diff` 一共改了四个文件。下面分段引用。

CI 镜像（[diff 第 1-9 行](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/ui/mock-data/data/continuum/patches/demo-shop-php2shell.diff#L1)）：

```diff
diff --git a/.gitlab-ci.yml b/.gitlab-ci.yml
index dd2775f..67cd7c3 100644
--- a/.gitlab-ci.yml
+++ b/.gitlab-ci.yml
@@ -1,3 +1,3 @@
 test:
-  image: php:8.3.30-cli
+  image: php:8.3.36-cli
   script: [php -v]
```

运行时镜像（[第 10-18 行](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/ui/mock-data/data/continuum/patches/demo-shop-php2shell.diff#L10)）：

```diff
diff --git a/Dockerfile b/Dockerfile
index bf9a853..ea263e7 100644
--- a/Dockerfile
+++ b/Dockerfile
@@ -1,3 +1,3 @@
-FROM php:8.3.30-apache
+FROM php:8.3.36-apache
 COPY src/ /var/www/html/
 RUN docker-php-ext-install pdo_mysql
```

composer platform（[第 19-32 行](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/ui/mock-data/data/continuum/patches/demo-shop-php2shell.diff#L19)）：

```diff
diff --git a/composer.json b/composer.json
index f43b749..b97c986 100644
--- a/composer.json
+++ b/composer.json
@@ -5,7 +5,7 @@
   },
   "config": {
     "platform": {
-      "php": "8.3.30"
+      "php": "8.3.36"
     }
   }
 }
\ No newline at end of file
```

注释（[第 33-42 行](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/ui/mock-data/data/continuum/patches/demo-shop-php2shell.diff#L33)）：

```diff
diff --git a/src/index.php b/src/index.php
index 573a43f..0dc4e97 100644
--- a/src/index.php
+++ b/src/index.php
@@ -1,4 +1,4 @@
 <?php
-// demo storefront (intentionally on an affected PHP 8.3 release)
+// demo storefront (PHP 8.3.36 - patched for CVE-2026-109618, CVE-2026-109619, CVE-2026-115560)
 $q = $_GET['q'] ?? '';
 echo '<h1>Search: ' . htmlspecialchars($q) . '</h1>';
```

审查这份补丁时，有三点值得注意。这也是代码里坚持"合并由人做"的原因：

1. **Dockerfile 那一段对不上当前的目标文件。** 补丁期望的上下文是 `FROM php:8.3.30-apache`，而 `integrations/continuum/targets/demo-shop/Dockerfile` 现在是 `FROM public.ecr.aws/docker/library/php:8.3.30-apache`。补丁里的写法和早期验证脚本内嵌的演示仓库一致（[integrations/continuum/poc.py:32](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/integrations/continuum/poc.py#L32)）。`scripts/deliver_prs.py` 的 `target_of()` 要求补丁里的每一行上下文都在目标里存在（[scripts/deliver_prs.py:112-126](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/scripts/deliver_prs.py#L112)），所以这份补丁对当前目标会被判为"目标未知"而跳过，不会被错误应用。
2. **注释夸大了修复范围。** 新注释写"patched for … CVE-2026-115560"。但事件自己的证据说 CVE-2026-115560 不在 10-21 的更新里（见第 1 节）。原因在上游：事件合并时把 115560 并进了 PHP2Shell 事件，规则名和规则的"Affected"列表都带上了它，AI 生成补丁时照抄了。代码里 `prune_plan()` 的注释也提到过一次错误合并（PHP2Shell 和 Node2Shell）留下的规则（[respond.py:367-372](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/respond.py#L367)）。
3. **`"php": "^8.3"` 没改。** 补丁改了 platform，但 `require` 里的约束仍然允许 8.3.30。这不影响镜像，但其他环境用 composer 校验时不会拦下旧版本。

Security Agent 那条"容器以 root 运行"的 finding，这份补丁也没有处理。

### 4.6 交付和人工步骤

Continuum 开出 PR 之后，`apply()` 把链接写进事件页的动作列表（[respond.py:659-664](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/respond.py#L659)）。人审查并合并 PR。之后再盘点时，Dockerfile 里不再有 8.3.30，雷达把对应的 finding 移到 `resolved_findings`。因为 Continuum 没有更新 finding 的接口，这一步由雷达自己记录（[respond.py:385-396](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/respond.py#L385)）。

## 5. 缓解站：补丁合并前的这段时间

### 5.1 WAF：cve 档，PHP 规则组

演示用的 AWS 托管规则更新日志快照（`tests/fixtures/snapshots/2026-10-29/waf-changelog.html`）里，有三行点名了 PHP2Shell。用 `mitigate.parse_waf_changelog()` 解析的结果如下：

| 日期 | 规则组 | 静态版本 | 规则 | CVE |
|---|---|---|---|---|
| 2026-10-21 | AWSManagedRulesPHPRuleSet | Version_2.3 | PHP2Shell_BODY | 109619、109618 |
| 2026-10-22 | AWSManagedRulesPHPRuleSet | Version_2.4 | PHP2Shell_BODY_Extended | 109618 |
| 2026-10-22 | AWSManagedRulesPHPRuleSet | Version_2.5 | PHP2Shell_BODY_Extended | 109618、109619 |

`waf_catalog()` 取点名该 CVE 的最新版本，所以最低版本是 `Version_2.5`；规则取所有行的并集（[src/radar/mitigate.py:140-154](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/mitigate.py#L140)）。两个 CVE 落在同一个规则组，`waf_plans()` 把它们合并成一个方案（[mitigate.py:202-212](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/mitigate.py#L202)）。PHP 也有 `product` 档的规则组，但 `cve` 档更具体，优先（[mitigate.py:193-196](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/mitigate.py#L193)）。CVE-2026-115560 在快照里没有对应行，所以没有专门规则。

测试 `test_b1_php2shell_maps_to_php_rule_set_at_least_2_4_with_both_rules` 锁定了这些结论（[tests/test_mitigate.py:48-62](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/tests/test_mitigate.py#L48)）。

示例数据 `mitigate.json` 和事件的 `mitigation` 块里，demo-shop 的方案状态是 `staged`：规则在 Count，等人确认后切到 Block。渲染出来的 web ACL 规则是：

```json
{"Name": "radar-AWSManagedRulesPHPRuleSet", "Priority": 0,
 "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "AWSManagedRulesPHPRuleSet",
   "RuleActionOverrides": [{"Name": "PHP2Shell_BODY_Extended", "ActionToUse": {"Count": {}}},
                           {"Name": "PHP2Shell_BODY", "ActionToUse": {"Count": {}}}]}},
 "OverrideAction": {"None": {}},
 "VisibilityConfig": {"SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true,
                      "MetricName": "radarAWSManagedRulesPHPRuleSet"}}
```

这里没有写 `Version`，用的是默认版本（[mitigate.py:236-251](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/mitigate.py#L236)）。如果账号里的默认版本低于 `Version_2.5`，只读审计会报告 `too_old`（[mitigate.py:270-273](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/mitigate.py#L270)）。规则标签的大小写和规则名不同，例如 `PHP2Shell_BODY` 对应 `awswaf:managed:aws:php-app:PHP2Shell_Body`，所以匹配不区分大小写（[mitigate.py:226-233](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/mitigate.py#L226)）。

人看过 Count 期间的命中样本后，用下面的命令提升为 Block。命令只记录决定，缓解站下一轮应用（[scripts/promote.py:3-6](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/scripts/promote.py#L3)）：

```bash
STAGE= uv run python scripts/promote.py waf security-radar-waf-demo AWSManagedRulesPHPRuleSet --by <你的名字>
```

WAF 规则只是降低风险。Datadog 提醒，规则看不到检测引擎截断的字节、解析器丢弃的字段，也看不到分块传输时处理方式不同的请求体，所以要确认你的 WAF 实际检查到了什么（[Datadog](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)）。每个缓解方案都带着同一句提示："缓解 ≠ 修复"（[mitigate.py:28](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/mitigate.py#L28)）。

### 5.2 Inspector：看不到运行时

示例数据里，demo-shop 的 Inspector 状态是 `no_packages`，0 个组件。demo-shop 没有 `composer.lock`，PHP 版本只出现在镜像标签、CI 镜像和 composer platform 里。Inspector ScanSbom 不判断 `pkg:generic/php` 这类运行时包（[src/radar/inspector.py:3-5](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/inspector.py#L3)）。所以对 PHP2Shell 来说，Inspector 帮不上忙，定位完全依靠雷达自己的产品登记表。页面上显示的是"没有可判断的包"，而不是"干净"（[src/radar/mitigate_station.py:72-74](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/mitigate_station.py#L72)）。

### 5.3 DNS Firewall

示例数据把 `php2shell-loader.top` 列为这个事件的域名 IOC，动作是 ALERT。代码只接受证据里以去毒化写法出现的域名，例如 `php2shell-loader[.]top`（[src/radar/patterns.py:93-118](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/patterns.py#L93)）。示例事件里的证据摘录并不包含这个域名，所以它应当看作演示用的示例值，无法从示例证据核对。默认动作是 ALERT，只有人工提升后才会 BLOCK（[mitigate.py:330-341](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/mitigate.py#L330)）。

### 5.4 Security Hub

开启导出后，（PHP2Shell × demo-shop）会生成一条 ASFF finding：严重度 CRITICAL（由 P0 映射），资源是三处文件:行，建议是"升级到 8.3.36"，并附上 WAF 和 DNS 的当前状态（[src/radar/securityhub.py:23-51](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/securityhub.py#L23)）。示例数据里没有这部分。

## 6. 自己的 PHP 资产怎么查

雷达的思路可以直接用在你自己的环境：先找出每一处钉 PHP 版本的地方，再按分支和修复版本比较。修复版本是 8.2.35、8.3.36、8.4.27、8.5.12。

### 6.1 正在服务网页的运行时

命令行的版本不一定是服务网页的版本，两个都要查：

```bash
php -v
php-fpm -v 2>/dev/null || ls /usr/sbin/php-fpm* 2>/dev/null   # Debian/Ubuntu 上常见 php-fpm8.3
# 容器内
docker exec <container> php -v
docker run --rm --entrypoint php <image:tag> -v
```

最可靠的做法是让 Web 服务器上的一个受控页面输出 `PHP_VERSION`，确认的是实际处理请求的进程，查完删掉这个页面。升级后要重启 PHP-FPM 或 Apache，或者替换掉所有旧的工作进程（[Datadog](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)，[Pentest-Tools.com](https://pentest-tools.com/research/php2shell-rce)）。

### 6.2 代码仓库里钉版本的地方

下面的命令覆盖雷达 PHP 定位器的几种写法（[products.py:37-44](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/products.py#L37)）：

```bash
# Dockerfile 基础镜像（含带仓库前缀的写法）
grep -rnE '^\s*FROM\s+\S*php:[0-9]' --include='Dockerfile*' .
# WordPress 镜像里的 PHP 分支（只到 x.y，无法精确比较）
grep -rnE '^\s*FROM\s+\S*wordpress:\S*-php[0-9.]+' --include='Dockerfile*' .
# CI 镜像
grep -rnE "image:\s*[\"']?\S*php:[0-9]" --include='*.yml' --include='*.yaml' .
# asdf / mise
grep -rnE '^php\s+[0-9]' --include='.tool-versions' .
```

### 6.3 composer 的 platform 配置

`config.platform.php` 只是告诉 composer"假装运行时是这个版本"，不代表实际运行时。但它通常和部署镜像保持一致，值得一起改：

```bash
composer config platform.php            # 读 config.platform.php
jq -r '.config.platform.php // empty, .require.php // empty' composer.json
composer show --platform | grep -E '^php\s'   # composer 看到的平台版本
```

### 6.4 系统包和回移植

发行版的回移植包可能不改上游版本号，要查包的更新日志里有没有这个 CVE（[Sansec](https://sansec.io/research/php2shell)）：

```bash
dpkg -l | grep -E '^ii\s+php[0-9.]*-(common|fpm|cli)'
zgrep CVE-2026-109618 /usr/share/doc/php8.3-common/changelog.Debian.gz
rpm -qa | grep -i '^php'
rpm -q --changelog php-common | grep CVE-2026-109618
```

### 6.5 用雷达自己的定位代码扫一遍

如果手上有雷达仓库，可以直接复用它的登记表做盘点和比较。下面这段对 demo-shop 实测输出了 3 处 `affected`：

```bash
cd sample-security-radar/src && python3 - /path/to/your/repo <<'PY'
import pathlib, sys
from radar import products
root = pathlib.Path(sys.argv[1])
files = {str(p.relative_to(root)): p.read_text(errors="ignore") for p in root.rglob("*")
         if p.is_file() and p.stat().st_size < 2_000_000 and ".git" not in p.parts}
fixed = ["8.5.12", "8.4.27", "8.3.36", "8.2.35"]
for pin in products.inventory(files):
    if pin.product_id == "php":
        print(pin.file, pin.line, pin.kind, pin.version, products.verdict(pin.version, fixed, []))
PY
```

输出里的 `unknown` 表示版本没钉到 `x.y.z`，或者分支不在修复列表里（例如 8.1）。这两种情况都要人去确认，不能当成"没事"。

## 可复用模式

1. **把"版本无法比较"作为一种明确的结果**
   - 问题：`8.3`、`^8.3`、`wordpress:…-php8.3` 这类写法无法和 8.3.36 比较，草率处理会得出"已修复"或"受影响"的错误结论。
   - 做法：只在完整的 `x.y.z` 且同一分支内比较；其他情况返回 `unknown`，页面上写明原因，并交给评审。
   - 代码位置：`src/radar/products.py` 的 `verdict`（[L146-158](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/products.py#L146)）；`src/radar/respond.py` 的 `to_response`（[L735](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/respond.py#L735)）。

2. **修复版本从证据里逐字抽取，不靠模型记忆**
   - 问题：漏洞刚披露时，模型不知道修复版本，可能编一个。
   - 做法：在证据文本中找"产品名 + 版本列表"，按前 80 个字符内最近的提示词判定是修复还是受影响，无法归类就丢弃；再用真实证据写测试锁定。
   - 代码位置：`src/radar/products.py` 的 `versions`（[L89-107](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/products.py#L89)）；`tests/test_respond.py` 的 `test_fixed_versions_are_extracted_verbatim_from_php2shell_evidence`（[L55](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/tests/test_respond.py#L55)）。

3. **只有上下文全部匹配时，才把补丁对应到仓库**
   - 问题：补丁路径是相对路径，每个服务都有 Dockerfile，按文件名匹配会把补丁应用到错误的仓库。本例的补丁上下文也和当前目标对不上。
   - 做法：要求补丁里的每个文件、每行上下文都在候选目标中存在，并且恰好只有一个目标匹配；否则跳过并打印。
   - 代码位置：`scripts/deliver_prs.py` 的 `target_of`（[L112-126](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/scripts/deliver_prs.py#L112)）。

4. **从更新日志取 WAF 规则，取"最新的点名版本"**
   - 问题：托管规则更新日志第一次提到某个 CVE 时，可能只是提到，真正能检测是在后面的版本。
   - 做法：解析更新日志，规则组只认第一格的链接；对每个（CVE、规则组）取最新的静态版本作为最低版本；先用 Count 上线，再用只读审计核对默认版本是否够新。
   - 代码位置：`src/radar/mitigate.py` 的 `parse_waf_changelog`、`waf_catalog`、`waf_check`（[L105](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/mitigate.py#L105)，[L140](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/mitigate.py#L140)，[L258](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/mitigate.py#L258)）。

5. **把扫描器的盲区记为"无法判断"，不记为"干净"**
   - 问题：依赖扫描器看不到容器镜像标签里的解释器版本，返回 0 条结果时容易被误读为没有风险。
   - 做法：输入里没有扫描器能判断的组件时，状态写成 `no_packages`；运行时版本交给另一套确定性定位逻辑判断。
   - 代码位置：`src/radar/mitigate_station.py` 的 `_inspector`（[L72-74](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/mitigate_station.py#L72)）；`src/radar/inspector.py` 文件头（[L3-5](https://github.com/aws-samples/sample-security-radar/blob/7d5362e/src/radar/inspector.py#L3)）。
