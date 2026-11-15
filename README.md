# surge-rules

面向 Surge（macOS / iOS / tvOS）构建的多源融合高精度双栈（IPv4 + IPv6）GeoIP 与 ASN 数据库引擎，每 12 小时通过 GitHub Actions 自动拉取全球公开数据源、完成血统去重与多维可信度融合并发布构建产物。

## 发布产物与直链

每次发布包含三个双栈 MaxMind MMDB v2.0（`ip_version = 6`）数据库文件：

| 文件 | `database_type` | 说明 | 最新版直链 |
| :--- | :--- | :--- | :--- |
| `Country.mmdb` | `GeoLite2-City` | 全球全维度超集数据库，同时承载国家/地区、注册国、省/州与城市（中英双语）、经纬度与时区、ASN 与组织域名、ISP 及网络特征标签；保留私有网段与虚拟组网网段的 `traits` 元数据并置空 `country` 与 `ASN` | `https://github.com/ding113/surge-rules/releases/latest/download/Country.mmdb` |
| `Country-cn.mmdb` | `GeoLite2-Country` | 纯净中国大陆（`country.iso_code = "CN"`）全字段子集，包含中英双语省份/城市/区县、运营商（ISP）、ASN、经纬度与网络特征；严格剔除港澳台、私有局域网与虚拟组网地址段 | `https://github.com/ding113/surge-rules/releases/latest/download/Country-cn.mmdb` |
| `ASN.mmdb` | `GeoLite2-ASN` | 全球公网可路由自治系统数据库（`autonomous_system_number`、`autonomous_system_organization`、`as_domain`）；严格剔除私有局域网与虚拟组网地址段 | `https://github.com/ding113/surge-rules/releases/latest/download/ASN.mmdb` |

## Surge 配置示例

```ini
[General]
geoip-maxmind-url = https://github.com/ding113/surge-rules/releases/latest/download/Country.mmdb
disable-geoip-db-auto-update = false

[Rule]
# 局域网、Surge Fake-IP (198.18.0.0/15)、Tailscale、Cloudflare Zero Trust Mesh、ZeroTier
# 在 Country.mmdb 中均不携带 country.iso_code 与 ASN，可直接由 GEOIP,UNKNOWN 命中直连
GEOIP,UNKNOWN,DIRECT,no-resolve
GEOIP,CN,DIRECT
FINAL,Proxy,dns-failed
```

## 核心设计

### 1. Priority-0 局域网与虚拟组网最高优先级隔离

在任何上游 GeoIP 库或云厂商 Geofeed 参与投票之前，融合引擎率先切分并锁定以下非公网可路由及虚拟组网地址段：

- **RFC 6890 保留与私有局域网段**：`0.0.0.0/8`、`10.0.0.0/8`、`127.0.0.0/8`、`169.254.0.0/16`、`172.16.0.0/12`、`192.0.0.0/24`、`192.0.2.0/24`、`192.168.0.0/16`、`198.51.100.0/24`、`203.0.113.0/24`、`224.0.0.0/4`、`240.0.0.0/4`、`::1/128`、`fe80::/10`、`fc00::/7`、`2001:db8::/32`、`ff00::/8` 等。
- **Surge 专用网段**：Surge Enhanced Mode Fake-IP 地址池 `198.18.0.0/15` 与 Surge VIF 虚拟网卡 DNS `198.18.0.2/32`（`traits.virtual_network = "surge_vif"`）。
- **Tailscale / Headscale 虚拟组网**：CGNAT 共享段 `100.64.0.0/10`、MagicDNS `100.100.100.100/32`、IPv6 ULA `fd7a:115c:a1e0::/48` 及 `fd7a:115c:a1e0::53/128`（`traits.virtual_network = "tailscale"`）。
- **Cloudflare Zero Trust / WARP 虚拟组网**：WARP CGNAT 默认段 `100.96.0.0/12`、Client-to-Client Mesh 段 `100.112.0.0/16`、本地虚拟网关 `172.16.0.1/32` 与 DNS `172.16.0.2/32`、ULA `fd01:db8:1111::/48`（`traits.virtual_network = "cloudflare_mesh"`）。
- **ZeroTier 6PLANE / RFC4193**：`fc00::/8`（`traits.virtual_network = "zerotier"`）。

上述网段在 `Country.mmdb` 中仅写入精确的 `traits` 属性（`is_bogon`、`is_private`、`is_virtual_mesh`、`network_type`、`virtual_network`），严格省略 `country`、`registered_country` 与 `autonomous_system_number`，从根源上杜绝上游数据库误标 `US` / `CA` / `CN` 引发代理回环；在 `Country-cn.mmdb` 与 `ASN.mmdb` 中则完全剔除。

### 2. 多源血统去重与分维度可信度融合

`sources/` 目录下通过 TypeScript 定义了 98 个上游公开数据源与镜像回退链（编译至 `sources/generated/geoip-sources.json`），`metadata/` 目录从 18 个开源地理与行政区划上游同步生成国家/区划/云区域字典（`metadata/generated/geoip-metadata.json`）。融合引擎按血统（`lineage`）对同源衍生镜像去重，避免同一上游被多次转载造成重复计票，并按数据维度分别裁决：

1. **Tier 0 — TypeScript 人工矫正层（`overrides/*.ts`）**：最高优先级覆盖特定前缀或 ASN 的国家、省市、ISP 与网络特征，支持中国大陆边界强制排除规则。
2. **Tier 1 — 运营商一手宣告与云官方清单**：RFC 8805 全球运营商 Geofeed（含 BGP 交叉验证的 GeoFeed-Harvester Parquet）、AWS / Google Cloud / Oracle Cloud 官方区域清单，直接决定云主机物理部署国与城市，克服 WHOIS 注册国滞后问题。
3. **Tier 2a — 中国大陆专项高精度源**：`ip2region`（v4/v6 XDB）、纯真 `QQWry`、`OpenIPDB`、`metowolf/iplist`、`gaoyifan/china-operator-ip`、`misakaio/chnroutes2`、`Hackl0us/GeoIP2-CN`、`Sukka` 规则集等，优先裁决中国大陆 IP 的省市行政区划与电信/联通/移动/广电/教育网/云厂商 ISP 归属，并严格隔离 `HK`、`MO`、`TW`。
4. **Tier 2b — 全球综合商业社区版**：IPinfo Lite、MaxMind GeoLite2（City / Country / ASN）、DB-IP Lite、IP2Location LITE DB11、IPFire `libloc`、Sypex Geo、IPLocate、sapics 等。
5. **Tier 3 — 实时 BGP 路由表与五大 RIR 注册库**：`bgp.tools` 实时 RIB 与 ASN 名称表、`IPtoASN`、`ipverse`、`ipscope` 以及 APNIC / ARIN / RIPE / LACNIC / AFRINIC 扩展分配表（RIR 分配国优先写入 `registered_country`，不覆盖云厂商物理部署国）。
6. **Trait Overlays — 网络特征叠加层**：Anycast、Cloudflare / Fastly / Gcore CDN、Apple iCloud Private Relay、VPN / 匿名代理、Tor 活跃出口节点（Onionoo）、Starlink 卫星互联网、搜索引擎爬虫及 Spamhaus DROP 恶意网段。

### 3. 紧凑双栈前缀树与深度结构化共享编码

构建器在 `u32` 与 `u128` 地址空间上并行执行无重叠原子区间扫描合并，将相邻且属性一致的网段折叠为最小 CIDR 集合；生成的双栈 `ip_version = 6` 搜索树同时在 `::/96` 与 `::ffff:0:0/96` 挂载压缩后的 IPv4 子树，并对数据区 Map、Array 与字符串执行深度哈希驻留指针复用，在保留全量 City + ASN + Traits 字段的同时显著压缩 `.mmdb` 体积。

## TypeScript 数据源、元数据与人工矫正维护

上游数据源目录（`sources/*.ts`）、行政与云区划元数据同步脚本（`metadata/*.ts`）与人工矫正配置（`overrides/*.ts`）共享同一套严格 TypeScript 类型检查与 Biome 格式/静态检查规范：

- **数据源目录（`sources/`）**：按分级拆分为 `sources/tier1-geofeed.ts`、`sources/tier2a-cn.ts`、`sources/tier2b-global.ts`、`sources/tier3-bgp-rir.ts` 与 `sources/trait-overlays.ts`，统一导出至 `sources/generated/geoip-sources.json`
- **元数据目录（`metadata/`）**：由 GeoNames、CLDR、mledoze/countries、dieghernan 欧盟成员表、IANA tz、modood 行政区划、AreaCity、dr5hn、Debian iso-codes 及 AWS/GCP/Oracle/Azure 官方清单转换生成 `metadata/generated/geoip-metadata.json`
- **特殊网络定义（`overrides/special-networks.ts`）**：局域网、RFC 6890 保留段、Surge Fake-IP、Tailscale、Cloudflare Mesh、ZeroTier 定义
- **国家与地域矫正（`overrides/geoip-country.ts`）**：公网前缀国家/省市矫正、Anycast DNS 标定与中国大陆误标排除列表
- **ASN / ISP 矫正（`overrides/geoip-asn.ts`）**：ASN 名称、ISP 归属与网络特征矫正

修改 `sources/*.ts`、`overrides/*.ts` 或 `metadata/*.ts` 后执行：

```bash
bun run build:config
bun run sync:metadata
bun run check
```

## 本地构建与校验

环境要求：Rust `1.85+`（Edition 2024）、Bun `1.2+`。

```bash
# 校验数据源目录与人工矫正的类型、代码格式及生成 JSON 一致性
bun run check

# 运行单元测试与 proptest 属性测试
cargo test --all-targets

# 拉取上游数据源（支持本地 .cache/upstream 增量缓存与 GITHUB_TOKEN 提速）并生成 dist/*.mmdb
cargo run --release -- geoip build --output dist

# 独立校验 dist 目录下的三个 MMDB 产物与金丝雀断言
cargo run --release -- geoip verify --dir dist

# 查询任意 IPv4 / IPv6 地址在三个数据库中的完整解析结果
cargo run --release -- geoip inspect 223.5.5.5 --dir dist
cargo run --release -- geoip inspect 100.64.0.1 --dir dist
```

## 开源许可

代码采用 [MIT License](./LICENSE) 发布，生成的数据库产物遵循各上游公开数据源的署名要求。
