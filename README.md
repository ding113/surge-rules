# surge-rules

面向 Surge（macOS / iOS / tvOS）构建的多源融合双栈 GeoIP 数据库与复杂去广告规则/模块构建引擎，每 12 小时通过 GitHub Actions 自动拉取全球公开数据源、执行严格血统去重、多维可信度融合、复杂重写优先编译与金丝雀校验，并在单一 GitHub Release 中原子发布全部 5 个构建产物。

## 发布产物与直链

每次 Release 统一发布以下 5 个构建产物：

| 文件 | 格式 / 类型 | 说明 | 最新版直链 |
| :--- | :--- | :--- | :--- |
| `Country.mmdb` | `GeoLite2-City` MMDB v2.0 | 全球双栈全维度超集数据库，承载国家/地区、注册国、中英双语省市、经纬度、时区、ASN、ISP 及网络特征；私有网段与虚拟组网仅写 `traits` 并置空 `country` 与 `ASN` | `https://github.com/ding113/surge-rules/releases/latest/download/Country.mmdb` |
| `Country-cn.mmdb` | `GeoLite2-Country` MMDB v2.0 | 纯净中国大陆（`CN`）全字段子集，保留中英双语省/市/区县与运营商信息；严格剔除港澳台、私有局域网与虚拟组网地址段 | `https://github.com/ding113/surge-rules/releases/latest/download/Country-cn.mmdb` |
| `ASN.mmdb` | `GeoLite2-ASN` MMDB v2.0 | 全球公网可路由自治系统数据库（`autonomous_system_number`、`autonomous_system_organization`、`as_domain`）；严格剔除私有与虚拟组网段 | `https://github.com/ding113/surge-rules/releases/latest/download/ASN.mmdb` |
| `Adblock.list` | Surge 外部 `RULE-SET` | 面向全平台的广告与跟踪兜底规则集（含 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`DOMAIN-WILDCARD`、`IP-CIDR` / `IP-CIDR6` / `IP-ASN`、`USER-AGENT`、`PROCESS-NAME`）；已剔除功能性与复合模块精细处理域名 | `https://github.com/ding113/surge-rules/releases/latest/download/Adblock.list` |
| `Adblock.sgmodule` | Surge `.sgmodule` 模块 | 复杂去广告与隐私净化模块（`[General]`、`[Rule]`、`[Header Rewrite]`、`[URL Rewrite]`、`[Body Rewrite]` 含原生 `http-response-jq`、`[Map Local]`、`[Script]`、`[MITM]`） | `https://github.com/ding113/surge-rules/releases/latest/download/Adblock.sgmodule` |

## Surge 配置示例

在 Surge 中导入模块 `https://github.com/ding113/surge-rules/releases/latest/download/Adblock.sgmodule`，并参考如下主配置：

```ini
[General]
geoip-maxmind-url = https://github.com/ding113/surge-rules/releases/latest/download/Country.mmdb
disable-geoip-db-auto-update = false

[Rule]
# 局域网、Surge Fake-IP (198.18.0.0/15)、Tailscale、Cloudflare Zero Trust Mesh、ZeroTier
# 在 Country.mmdb 中均不携带 country.iso_code 与 ASN，可直接由 GEOIP,UNKNOWN 命中直连
GEOIP,UNKNOWN,DIRECT,no-resolve

# 兜底广告与跟踪拦截（RULE-SET 内含 PROCESS-NAME / USER-AGENT，支持 extended-matching，勿启用 pre-matching）
RULE-SET,https://github.com/ding113/surge-rules/releases/latest/download/Adblock.list,REJECT,extended-matching

GEOIP,CN,DIRECT
FINAL,Proxy,dns-failed
```

## 核心设计

### 1. Priority-0 局域网与虚拟组网最高优先级隔离

在任何上游 GeoIP 库或云厂商 Geofeed 参与投票之前，GeoIP 融合引擎率先切分并锁定非公网可路由与虚拟组网地址段（同时 `Adblock.list` 构建阶段也会剔除重叠的保留/虚拟组网 CIDR）：

- **RFC 6890 保留与私有局域网段**：`0.0.0.0/8`、`10.0.0.0/8`、`127.0.0.0/8`、`169.254.0.0/16`、`172.16.0.0/12`、`192.0.0.0/24`、`192.0.2.0/24`、`192.168.0.0/16`、`198.51.100.0/24`、`203.0.113.0/24`、`224.0.0.0/4`、`240.0.0.0/4`、`::1/128`、`fe80::/10`、`fc00::/7`、`2001:db8::/32`、`ff00::/8` 等。
- **Surge 专用网段**：Surge Enhanced Mode Fake-IP 地址池 `198.18.0.0/15` 与 Surge VIF 虚拟网卡 DNS `198.18.0.2/32`（`traits.virtual_network = "surge_vif"`）。
- **Tailscale / Headscale 虚拟组网**：CGNAT 共享段 `100.64.0.0/10`、MagicDNS `100.100.100.100/32`、IPv6 ULA `fd7a:115c:a1e0::/48` 及 `fd7a:115c:a1e0::53/128`（`traits.virtual_network = "tailscale"`）。
- **Cloudflare Zero Trust / WARP 虚拟组网**：WARP CGNAT 默认段 `100.96.0.0/12`、Client-to-Client Mesh 段 `100.112.0.0/16`、本地虚拟网关 `172.16.0.1/32` 与 DNS `172.16.0.2/32`、ULA `fd01:db8:1111::/48`（`traits.virtual_network = "cloudflare_mesh"`）。
- **ZeroTier 6PLANE / RFC4193**：`fc00::/8`（`traits.virtual_network = "zerotier"`）。

上述网段在 `Country.mmdb` 中仅写入精确 `traits` 属性，严格省略 `country`、`registered_country` 与 `autonomous_system_number`；在 `Country-cn.mmdb` 与 `ASN.mmdb` 中完全剔除。

### 2. 多源血统去重与分维度可信度融合（GeoIP / ASN）

`sources/` 定义了 98 个公开 GeoIP 数据源与镜像回退链（生成 `sources/generated/geoip-sources.json`），`metadata/` 从 18 个开源地理与行政区划/云区域上游同步字典（生成 `metadata/generated/geoip-metadata.json`）。融合引擎按血统（`lineage`）对同源镜像去重，并按维度裁决：

1. **Tier 0 — TypeScript 人工矫正层（`overrides/geoip-*.ts`、`overrides/special-networks.ts`）**：最高优先级覆盖特定前缀或 ASN 的国家、省市、ISP 与网络特征。
2. **Tier 1 — 运营商一手 Geofeed 与云官方清单**：RFC 8805 Geofeed、AWS / GCP / Oracle Cloud 官方区域前缀，直接确定云主机物理部署位置。
3. **Tier 2a — 中国大陆专项高精度源**：`ip2region`（v4/v6 XDB）、纯真 `QQWry`、`OpenIPDB`、`metowolf/iplist`、`gaoyifan/china-operator-ip`、`misakaio/chnroutes2`、`Hackl0us/GeoIP2-CN`、`Sukka` 规则集等，优先裁决中国大陆省市与运营商归属并严格隔离 `HK`、`MO`、`TW`。
4. **Tier 2b — 全球综合商业社区版**：IPinfo Lite、MaxMind GeoLite2、DB-IP Lite、IP2Location LITE DB11、IPFire `libloc`、Sypex Geo、IPLocate、sapics 等。
5. **Tier 3 — 实时 BGP 与五大 RIR 注册库**：`bgp.tools`、`IPtoASN`、`ipverse`、`ipscope` 及 APNIC / ARIN / RIPE / LACNIC / AFRINIC 扩展分配表。
6. **Trait Overlays — 网络特征叠加层**：Anycast、Cloudflare / Fastly / Gcore CDN、Apple iCloud Private Relay、VPN、Tor 出口节点、Starlink、搜索引擎爬虫及 Spamhaus DROP。

### 3. 紧凑双栈前缀树与深度结构化共享编码

MMDB 构建器在 `u32` 与 `u128` 地址空间上执行无重叠原子区间扫描合并，在 `::/96` 与 `::ffff:0:0/96` 挂载压缩后的 IPv4 子树，并对数据区 Map、Array 与字符串执行深度哈希驻留指针复用。

### 4. 复杂优先（Complex-Over-Host）Adblock 与隐私净化引擎

Adblock 子系统严格基于 Surge 官方规范区分“模块精密重写”与“兜底域名拦截”：

- **三层上游分类（52 源）**：`sources/adblock-allowlists.ts`（3 个解封白名单，含 uBO unbreak/quick-fixes、Loyalsoldier reject-need-to-remove）、`sources/adblock-complex.ts`（22 个 Surge `.sgmodule` / Quantumult X `.conf` / `$removeparam` 复杂规则源）与 `sources/adblock-rulesets.ts`（27 个域名前缀/ABP 兜底拦截源），统一生成至 `sources/generated/adblock-sources.json`。
- **复杂规则优先保护与反误伤机制**：被 `Adblock.sgmodule` 的 URL/Body/Header/Map Local/Script 精细处理的多用途宿主域名（如 `api.bilibili.com`、`edith.xiaohongshu.com`、`acs.m.taobao.com`），自动记入复杂保护集合与 `overrides/adblock-allowlist.ts`（47 条放行规则 + 53 个受保护根域），防止 `Adblock.list` 整域误杀；仅对纯广告/跟踪基础设施或 `overrides/adblock-ruleset.ts`（23 条 `forceRuleSetEntries`）中的明确项保留兜底拦截。
- **严格遵循 Surge 语义的转换与裁剪**：
  - 彻底丢弃浏览器 CSS 隐藏、扩展选择器、`#+js(...)` 脚本注入与 `$elemhide` 规则；尊重 ABP `$badfilter` 抵消与站点作用域修饰符。
  - `[Header Rewrite]` 严格禁止增删或修改 `Content-Length` 与 `Transfer-Encoding`。
  - `[URL Rewrite]` 仅保留 `header`、`302`、`307` 与 `reject`；上游 `reject-200` / `reject-dict` / `reject-array` / `reject-img` 自动升级为 Surge `[Map Local]`。
  - `[Body Rewrite]` 将安全 `$jsonprune=` 路径表达式转译为 Surge 原生 `http-response-jq`（`del(.a?.b?)`），并在 `[Script]` 冲突时保证每类同模式仅保留最高权重一条脚本、全局唯一脚本名。
  - 统一跟踪参数清理脚本 [`scripts/surge-removeparam.js`](./scripts/surge-removeparam.js) 使用 `jsc` 引擎并以最低权重追加至 `[Script]` 末尾，优先保留上游 App 专用请求脚本；批量站点规则不额外膨胀 `[MITM]`。
  - `[MITM]` 严格将 [`overrides/adblock-module.ts`](./overrides/adblock-module.ts) 的 19 条固定证书与系统/支付 `-` 排除规则置顶，自动剔除危险通配符（`*`、`*.com` 等）。
  - `Adblock.list` 通过反转标签 `DomainTrie` 执行精确 `subsumption` 去重压缩（仅合并无策略列的标准 Surge 外部 `RULE-SET` 语法），并对 `IP-CIDR` / `IP-CIDR6` 执行 CIDR 聚合与保留网段剔除。

## TypeScript 数据源、元数据与人工矫正维护

`sources/*.ts`、`overrides/*.ts`、`metadata/*.ts` 与 `scripts/*.js` 共享同一套严格 TypeScript 类型校验、Biome 格式/静态检查及测试体系：

- **GeoIP 数据源与矫正**：`sources/tier*.ts`、`sources/trait-overlays.ts`、`overrides/special-networks.ts`、`overrides/geoip-country.ts`、`overrides/geoip-asn.ts`
- **Adblock 数据源与矫正**：`sources/adblock-allowlists.ts`、`sources/adblock-complex.ts`、`sources/adblock-rulesets.ts`、`overrides/adblock-allowlist.ts`、`overrides/adblock-ruleset.ts`、`overrides/adblock-module.ts`
- **元数据与运行时脚本**：`metadata/sources.ts`、`metadata/sync.ts`、`metadata/verify.ts`、`scripts/surge-removeparam.js`、`scripts/surge-removeparam.test.ts`

修改 TypeScript 配置或脚本后执行：

```bash
bun run build:config
bun run sync:metadata
bun run check
bun test
```

## 本地构建与校验

环境要求：Rust `1.85+`（Edition 2024）、Bun `1.2+`。

```bash
# 校验 TypeScript 类型、Biome Lint、JSON 一致性与运行时脚本测试
bun run check
bun test

# 运行 Rust 单元测试与 proptest 属性测试
cargo test --release --all-targets

# 构建并校验 GeoIP MMDB（支持 .cache/upstream 缓存与 GITHUB_TOKEN）
cargo run --release -- geoip build --output dist
cargo run --release -- geoip verify --dir dist
cargo run --release -- geoip inspect 223.5.5.5 --dir dist
cargo run --release -- geoip inspect 100.64.0.1 --dir dist

# 构建并校验 Adblock.list 与 Adblock.sgmodule（支持 .cache/adblock 缓存）
cargo run --release -- adblock build --output dist
cargo run --release -- adblock verify --dir dist
```

## 开源许可

代码采用 [MIT License](./LICENSE) 发布，生成的规则与数据库产物遵循各上游公开数据源的署名要求。
