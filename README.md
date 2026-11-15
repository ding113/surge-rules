# surge-rules

面向自用的 Surge 规则集、去广告模块与多源 GeoIP 数据集，每 12 小时自动构建更新。

## 构建产物

| 产物 | 说明 | 下载链接 | 最新更新 |
| :--- | :--- | :--- | :--- |
| `Country.mmdb` | 全球双栈全量 GeoIP 库（含省市、ASN、ISP 及内网/组网标记） | [GitHub](https://github.com/ding113/surge-rules/releases/latest/download/Country.mmdb) · [Cloudflare](https://rule-set.ygxz.de/Country.mmdb) | <!-- updated-at -->2026-11-16 00:23<!-- /updated-at --> |
| `Country-only.mmdb` | 全球双栈精简国家库（仅含 IP 与 `country` 字段） | [GitHub](https://github.com/ding113/surge-rules/releases/latest/download/Country-only.mmdb) · [Cloudflare](https://rule-set.ygxz.de/Country-only.mmdb) | <!-- updated-at -->2026-11-16 00:23<!-- /updated-at --> |
| `Country-cn.mmdb` | 中国大陆（`CN`）专属双栈 GeoIP 库 | [GitHub](https://github.com/ding113/surge-rules/releases/latest/download/Country-cn.mmdb) · [Cloudflare](https://rule-set.ygxz.de/Country-cn.mmdb) | <!-- updated-at -->2026-11-16 00:23<!-- /updated-at --> |
| `ASN.mmdb` | 全球公网自治系统（ASN）库 | [GitHub](https://github.com/ding113/surge-rules/releases/latest/download/ASN.mmdb) · [Cloudflare](https://rule-set.ygxz.de/ASN.mmdb) | <!-- updated-at -->2026-11-16 00:23<!-- /updated-at --> |
| `Adblock.sgmodule` | 去广告与隐私净化模块（重写、脚本、Map Local 与 HTTPDNS 拦截） | [GitHub](https://github.com/ding113/surge-rules/releases/latest/download/Adblock.sgmodule) · [Cloudflare](https://rule-set.ygxz.de/Adblock.sgmodule) · <kbd>[一键导入](https://rule-set.ygxz.de/install.html)</kbd> | <!-- updated-at -->2026-11-16 00:23<!-- /updated-at --> |
| `Adblock.list` | 广告与跟踪域名/IP 兜底拦截规则集 | [GitHub](https://github.com/ding113/surge-rules/releases/latest/download/Adblock.list) · [Cloudflare](https://rule-set.ygxz.de/Adblock.list) | <!-- updated-at -->2026-11-16 00:23<!-- /updated-at --> |
| `Direct.list` | 中国大陆服务、国内流媒体、国产 AI 及境外服务国内 CDN 直连规则集 | [GitHub](https://github.com/ding113/surge-rules/releases/latest/download/Direct.list) · [Cloudflare](https://rule-set.ygxz.de/Direct.list) | <!-- updated-at -->2026-11-16 00:23<!-- /updated-at --> |
| `AI.list` | 境外 AI、境外银行支付、PayPal、风控与遥测规则集 | [GitHub](https://github.com/ding113/surge-rules/releases/latest/download/AI.list) · [Cloudflare](https://rule-set.ygxz.de/AI.list) | <!-- updated-at -->2026-11-16 00:23<!-- /updated-at --> |
| `Proxy.list` | 境外服务与海外流媒体全量代理规则集（已包含 `AI.list`） | [GitHub](https://github.com/ding113/surge-rules/releases/latest/download/Proxy.list) · [Cloudflare](https://rule-set.ygxz.de/Proxy.list) | <!-- updated-at -->2026-11-16 00:23<!-- /updated-at --> |

## Surge 配置示例

导入 [`Adblock.sgmodule`](https://rule-set.ygxz.de/install.html) 模块后，可在主配置中按需引用规则集与 GeoIP 数据库：

```ini
[General]
geoip-maxmind-url = https://rule-set.ygxz.de/Country-only.mmdb
disable-geoip-db-auto-update = false

[Rule]
RULE-SET,https://rule-set.ygxz.de/Adblock.list,REJECT,extended-matching
RULE-SET,https://rule-set.ygxz.de/Direct.list,DIRECT
RULE-SET,https://rule-set.ygxz.de/AI.list,AI,extended-matching
RULE-SET,https://rule-set.ygxz.de/Proxy.list,Proxy
GEOIP,CN,DIRECT
FINAL,Proxy,dns-failed
```

> 如需完整省市、运营商及局域网/虚拟组网识别（配合 `GEOIP,UNKNOWN,DIRECT,no-resolve`），可将 `geoip-maxmind-url` 替换为 [`Country.mmdb`](https://rule-set.ygxz.de/Country.mmdb)。

## 数据源

<details>
<summary>展开查看全部上游数据源（共 277 项）</summary>

```text
Geofeed Harvester, https://github.com/ipanalytics/GeoFeed-Harvester/releases/latest
Opengeofeed, https://opengeofeed.org/feed/public.csv
NTT GIN Geofeed, https://geo.ip.gin.ntt.net/geofeeds/geofeeds.csv
LACNIC Geofeed, https://milacnic.lacnic.net/lacnic/geofeeds/geofeeds.csv
AWS Official IP Ranges, https://ip-ranges.amazonaws.com/ip-ranges.json
Aws Geofeed, https://ip-ranges.amazonaws.com/geo-ip-feed.csv
Gcp Cloud Ranges, https://www.gstatic.com/ipranges/cloud.json
Google Cloud Geofeed, https://www.gstatic.com/ipranges/cloud_geofeed
Google Corp Geofeed, https://www.gstatic.com/geofeed/corp_external
Google VPN Geofeed, https://www.gstatic.com/vpn/geofeed
Cloudflare Local Geofeed, https://api.cloudflare.com/local-ip-ranges.csv
Cloudflare Warp Geofeed, https://api.cloudflare.com/warp-egress-ip-ranges.csv
Apple iCloud Private Relay Ranges, https://mask-api.icloud.com/egress-ip-ranges.csv
Oracle Cloud Ranges, https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json
DigitalOcean Geofeed, https://digitalocean.com/geo/google.csv
Akamai Geofeed, https://ipgeo.akamai.com/akamai-geofeed.csv
Akamai Linode Geofeed, https://ipgeo.akamai.com/linode-geofeed.csv
Hetzner Geofeed, https://www.hetzner.com/geofeed.csv
Vultr Geofeed, https://geofeed.constant.com/
Starlink Geofeed, https://geoip.starlinkisp.net/feed.csv
Viasat Geofeed, https://raw.githubusercontent.com/Viasat/geofeed/main/geofeed.csv
Netflix Openconnect Geofeed, https://raw.githubusercontent.com/Netflix/nflx-geofeed/main/geofeed.csv
UpCloud Geofeed, https://upcloud.com/geofeed.csv
Cherry Servers Geofeed, https://geofeed.cherryservers.com/geofeed.csv
Hostinger Geofeed, https://raw.githubusercontent.com/hostinger/geofeed/main/geofeed.csv
Exoscale Geofeed, https://exoscale-prefixes.sos.exo.io/exoscale_geofeed
Clouvider Geofeed, https://clouvider.com/geoipfeed.csv
T-Mobile US Geofeed, https://raw.githubusercontent.com/tmobile/tmus-geofeed/main/tmus-geo-ip.txt
Verizon Geofeed, https://raw.githubusercontent.com/Verizon/verizon-geofeed/main/feed_5Ghome.csv
Microsoft Geofeed, https://download.microsoft.com/download/0b9dc6ca-68f9-43b2-b094-da4f6d509bc3/geoloc-Microsoft.csv
lionsoul2014 ip2region IPv4, https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb
lionsoul2014 ip2region IPv6, https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v6.xdb
Cz88 Qqwry, https://github.com/metowolf/qqwry.dat/releases/latest
Openipdb, https://www.npmjs.com/package/openipdb.ipdb
gaoyifan china-operator-ip China IPv4, https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt
gaoyifan china-operator-ip China IPv6, https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china6.txt
gaoyifan china-operator-ip ChinaNet IPv4, https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/chinanet.txt
gaoyifan china-operator-ip ChinaNet IPv6, https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/chinanet6.txt
gaoyifan china-operator-ip Unicom IPv4, https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/unicom.txt
gaoyifan china-operator-ip Unicom IPv6, https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/unicom6.txt
gaoyifan china-operator-ip CMCC IPv4, https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cmcc.txt
gaoyifan china-operator-ip CMCC IPv6, https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cmcc6.txt
gaoyifan china-operator-ip CERNET, https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cernet46.txt
gaoyifan china-operator-ip CSTNET, https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cstnet46.txt
gaoyifan china-operator-ip Dr.Peng, https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/drpeng46.txt
Metowolf China, https://metowolf.github.io/iplist/data/special/china.txt
SukkaW chnroutes2, https://chnroutes2.cdn.skk.moe/reversed-chnroutes.txt
Sukkaw China Ipv6, https://ruleset.skk.moe/Clash/ip/china_ip_ipv6.txt
Ipip 17Mon China, https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt
Hackl0us GeoIP2-CN, https://raw.githubusercontent.com/Hackl0us/GeoIP2-CN/release/CN-ip-cidr.txt
Chanthmiao Cn V4, https://raw.githubusercontent.com/ChanthMiao/China-IPv4-List/release/cn.txt
Chanthmiao Cn V6, https://raw.githubusercontent.com/ChanthMiao/China-IPv6-List/release/cn6.txt
IPinfo Lite Country & ASN, https://github.com/Alice39s/ipinfo-csv-lite/releases/latest
MaxMind GeoLite2 City, https://github.com/Skiddle-ID/geoip2-mirror/releases/latest
MaxMind GeoLite2 Country, https://github.com/Skiddle-ID/geoip2-mirror/releases/latest
DB-IP City Lite, https://github.com/Shoyu-Dev/mmdb-latest/releases/download/dbip-latest/dbip-city-lite.mmdb
DB-IP Country Lite, https://github.com/Shoyu-Dev/mmdb-latest/releases/download/dbip-latest/dbip-country-lite.mmdb
Ip2Location Db11, https://github.com/renfei/ip2location/releases/latest
Ip2Location Db1 Official, https://download.ip2location.com/lite/IP2LOCATION-LITE-DB1.CSV.ZIP
IPFire Location Database, https://location.ipfire.org/databases/1/location.db.xz
Sapics User Country, https://github.com/sapics/ip-location-db/releases/download/latest/user-country.mmdb
IPLocate IP-to-Country, https://media.githubusercontent.com/media/iplocate/ip-address-databases/HEAD/ip-to-country/ip-to-country.mmdb
IPScope Lite, https://api.ipscope.io/v1/lite/ipscope-lite.csv.gz
ip66.dev GeoIP Database, https://downloads.ip66.dev/db/ip66.mmdb
Sypex Geo Country, https://sypexgeo.net/files/SxGeoCountry.zip
bgp.tools Routing Table (with Alice39s/BGP.Tools-OpenDB mirror), https://bgp.tools/table.jsonl
bgp.tools ASN Registry (with Alice39s/BGP.Tools-OpenDB mirror), https://bgp.tools/asns.csv
ipverse AS Metadata, https://raw.githubusercontent.com/ipverse/as-metadata/master/as.csv
IPtoASN Combined Database, https://iptoasn.com/data/ip2asn-combined.tsv.gz
Sapics Origin Asn, https://github.com/sapics/ip-location-db/releases/download/latest/origin-asn.mmdb
MaxMind GeoLite2 ASN, https://github.com/Skiddle-ID/geoip2-mirror/releases/latest
DB-IP ASN Lite, https://github.com/Shoyu-Dev/mmdb-latest/releases/download/dbip-latest/dbip-asn-lite.mmdb
IPLocate IP-to-ASN, https://media.githubusercontent.com/media/iplocate/ip-address-databases/HEAD/ip-to-asn/ip-to-asn.mmdb
Rir Apnic, https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest
Rir Arin, https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest
Rir Ripencc, https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest
Rir Lacnic, https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest
Rir Afrinic, https://ftp.afrinic.net/stats/afrinic/delegated-afrinic-extended-latest
bgp.tools Anycast Prefixes IPv4, https://raw.githubusercontent.com/bgptools/anycast-prefixes/master/anycatch-v4-prefixes.txt
bgp.tools Anycast Prefixes IPv6, https://raw.githubusercontent.com/bgptools/anycast-prefixes/master/anycatch-v6-prefixes.txt
Alice39s BGP.Tools-OpenDB VPS & Hosting ASN Tags, https://raw.githubusercontent.com/Alice39s/BGP.Tools-OpenDB/auto-update/tags/vpsh/tags-vpsh.csv
Alice39s BGP.Tools-OpenDB CDN ASN Tags, https://raw.githubusercontent.com/Alice39s/BGP.Tools-OpenDB/auto-update/tags/cdn/tags-cdn.csv
Cloudflare Edge IPv4, https://www.cloudflare.com/ips-v4
Cloudflare Edge IPv6, https://www.cloudflare.com/ips-v6/
Fastly Public IP List, https://api.fastly.com/public-ip-list
Gcore CDN Public IP List, https://api.gcore.com/cdn/public-ip-list
GitHub Meta IP Ranges, https://api.github.com/meta
hexydec Verified Crawlers IP Ranges, https://raw.githubusercontent.com/hexydec/ip-ranges/main/output/crawlers.txt
Tor Project Bulk Exit List, https://check.torproject.org/torbulkexitlist
Tor Project Onionoo Exit Summary, https://onionoo.torproject.org/summary?flag=Exit&running=true
X4BNet VPN IPv4 List, https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt
X4BNet Datacenter IPv4 List, https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt
josephrocca VPN & Datacenter IPv6, https://raw.githubusercontent.com/josephrocca/is-vpn/main/vpn-or-datacenter-ipv6-ranges.txt
NetworkCats OpenProxyDB, https://github.com/NetworkCats/OpenProxyDB/releases/latest
jhassine Server & Datacenter IPs, https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.txt
ipanalytics Sat-geoip Prefixes, https://raw.githubusercontent.com/ipanalytics/Sat-geoip/main/outputs/sat-geoip-prefixes.jsonl
ipanalytics Sat-geoip Satellite ASNs, https://raw.githubusercontent.com/ipanalytics/Sat-geoip/main/outputs/satellite-asns.csv
Spamhaus DROP IPv4, https://www.spamhaus.org/drop/drop_v4.json
Spamhaus DROP IPv6, https://www.spamhaus.org/drop/drop_v6.json
abuse.ch Feodo Tracker IP Blocklist, https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt
GeoNames Country Info, https://download.geonames.org/export/dump/countryInfo.txt
GeoNames Cities5000, https://download.geonames.org/export/dump/cities5000.zip
mledoze Countries, https://raw.githubusercontent.com/mledoze/countries/master/dist/countries.json
CLDR Country List zh-CN (umpirsky), https://raw.githubusercontent.com/umpirsky/country-list/master/data/zh_CN/country.json
CLDR Country List en (umpirsky), https://raw.githubusercontent.com/umpirsky/country-list/master/data/en/country.json
dieghernan Country Codes & International Orgs, https://raw.githubusercontent.com/dieghernan/Country-Codes-and-International-Organizations/master/outputs/Countrycodesfull.json
IANA Time Zone Database zone1970, https://raw.githubusercontent.com/eggert/tz/main/zone1970.tab
modood Administrative Divisions of China, https://raw.githubusercontent.com/modood/Administrative-divisions-of-China/master/dist/pca-code.json
xiangyuecn AreaCity China Level-3 Divisions, https://raw.githubusercontent.com/xiangyuecn/AreaCity-JsSpider-StatsGov/master/src/%E9%87%87%E9%9B%86%E5%88%B0%E7%9A%84%E6%95%B0%E6%8D%AE/ok_data_level3.csv
dr5hn Countries States Cities Database, https://github.com/dr5hn/countries-states-cities-database/releases/latest
Debian iso-codes ISO 3166-2, https://salsa.debian.org/iso-codes-team/iso-codes/-/raw/main/data/iso_3166-2.json
jsonmaur AWS Regions, https://raw.githubusercontent.com/jsonmaur/aws-regions/master/regions.json
Green Software Foundation Azure Regions, https://raw.githubusercontent.com/Green-Software-Foundation/carbon-aware-sdk/dev/src/data/location-sources/azure-regions.json
Ubo Unbreak, https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt
Ubo Quick Fixes, https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/quick-fixes.txt
Loyalsoldier Reject Remove, https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/hidden/reject-need-to-remove.txt
Biliverse Bilibili Adblock, https://github.com/Biliverse/ADBlock/releases/latest
App2Smile Youtube, https://raw.githubusercontent.com/app2smile/rules/master/module/youtube.sgmodule
Walvez Startup Ads, https://raw.githubusercontent.com/Walvez/surge-startup-ads/main/dist/StartUpAds_Selected.sgmodule
App2Smile Spotify, https://raw.githubusercontent.com/app2smile/rules/master/module/spotify.module
App2Smile Zhihu, https://raw.githubusercontent.com/app2smile/rules/master/module/zhihu.sgmodule
App2Smile Tieba, https://raw.githubusercontent.com/app2smile/rules/master/module/tieba.sgmodule
Ddgksf Weibo Ads, https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/WeiboAds.conf
Ddgksf Amap Ads, https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/AmapAds.conf
Adguard Url Tracking, https://filters.adtidy.org/extension/ublock/filters/17.txt
App2Smile Qqnews, https://raw.githubusercontent.com/app2smile/rules/master/module/qqnews.sgmodule
Maasea Keep Ads, https://raw.githubusercontent.com/Maasea/sgmodule/master/KeepAds.sgmodule
Ddgksf Xiaohongshu Ads, https://raw.githubusercontent.com/ifflagged/Romeo/main/Modules/Surge/ddgksf2013/XiaoHongShuAds.sgmodule
App2Smile Adsense, https://raw.githubusercontent.com/app2smile/rules/master/module/adsense.sgmodule
Ddgksf Ximalaya Ads, https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/Ximalaya.conf
Ddgksf Cainiao Ads, https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/CainiaoAds.conf
Ddgksf Smzdm Ads, https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/SmzdmAds.conf
Ddgksf Goofish Ads, https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/GoofishAds.conf
Ddgksf Wechat Ads, https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/WeChat.conf
Ddgksf Netease Ads, https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/NeteaseAds.conf
Qingrex Httpdns Block, https://raw.githubusercontent.com/QingRex/LoonKissSurge/main/Surge/Beta/%E6%8B%A6%E6%88%AAHTTPDNS.beta.sgmodule
Ddgksf Applet Ads, https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/Applet.conf
Fmz200 Blockads Module, https://raw.githubusercontent.com/fmz200/wool_scripts/main/Surge/module/blockAds.module
Awavenue Ads Surge, https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Surge-RULE-SET.list
Sukka Reject Ruleset, https://ruleset.skk.moe/Clash/non_ip/reject.txt
Sukka Reject Drop, https://ruleset.skk.moe/Clash/non_ip/reject-drop.txt
Sukka Reject Domainset, https://ruleset.skk.moe/List/domainset/reject.conf
Sukka Reject Ip, https://ruleset.skk.moe/List/ip/reject.conf
Adguard Mobile Ads, https://filters.adtidy.org/extension/ublock/filters/11.txt
Ubo Filters, https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt
Adguard Base, https://filters.adtidy.org/extension/ublock/filters/2.txt
Adguard Chinese, https://filters.adtidy.org/extension/ublock/filters/224.txt
Ubo Privacy, https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt
Adguard Tracking, https://filters.adtidy.org/extension/ublock/filters/3.txt
Mieqq In App Tracker, https://raw.githubusercontent.com/mieqq/mieqq/master/In-AppTracker.txt
Ubo Badware, https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt
Peter Lowe, https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=1&mimetype=plaintext
Adguard Dns Filter, https://filters.adtidy.org/windows/filters/15.txt
Easyprivacy, https://easylist.to/easylist/easyprivacy.txt
Hagezi Pro Domains, https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt
Hackl0Us Video Ad, https://raw.githubusercontent.com/Hackl0us/SS-Rule-Snippet/master/Rulesets/Surge/Custom/video-ad.list
Easylist, https://easylist.to/easylist/easylist.txt
Easylist China, https://raw.githubusercontent.com/easylist/easylistchina/master/easylistchina.txt
Oisd Big, https://big.oisd.nl/
Acl4Ssr Ban Program Ad, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanProgramAD.list
Acl4Ssr Ban Ad, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanAD.list
Onehosts Lite, https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/domains.wildcards
Cats Adrules Domainset, https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules_surge_domainset.txt
Anti Ad Surge, https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-surge.txt
Stevenblack Hosts, https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
Loyalsoldier surge-rules direct ruleset, https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/direct.txt
MetaCubeX meta-rules-dat geolocation-cn, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/geolocation-cn.list
MetaCubeX category-ai-cn, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-ai-cn.list
MetaCubeX apple-cn, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/apple-cn.list
MetaCubeX apple@cn CDN & connectivity, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/apple%40cn.list
MetaCubeX microsoft@cn CDN & connectivity, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/microsoft%40cn.list
MetaCubeX steam@cn download CDN, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/steam%40cn.list
MetaCubeX google@cn localized endpoints, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/google%40cn.list
v2fly domain-list-community category-games-cn, https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/category-games-cn
v2fly domain-list-community category-scholar-cn, https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/category-scholar-cn
SukkaW Surge domestic rules, https://raw.githubusercontent.com/SukkaW/Surge/master/Source/non_ip/domestic.conf
SukkaW Surge direct rules, https://raw.githubusercontent.com/SukkaW/Surge/master/Source/non_ip/direct.conf
SukkaW Surge domestic CDN rules, https://raw.githubusercontent.com/SukkaW/Surge/master/Source/non_ip/domestic_cdn.conf
SukkaW Surge Apple China CDN rules, https://raw.githubusercontent.com/SukkaW/Surge/master/Source/non_ip/apple_cn.conf
SukkaW Surge domestic IP rules, https://raw.githubusercontent.com/SukkaW/Surge/master/Source/ip/domestic.conf
VPSDance ai-proxy-rules Mainland China AI, https://raw.githubusercontent.com/VPSDance/ai-proxy-rules/main/rules/surge/cn.list
felixonmars dnsmasq-china-list accelerated-domains, https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf
felixonmars dnsmasq-china-list apple.china, https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/apple.china.conf
blackmatrix7 ChinaMax Surge ruleset, https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/ChinaMax/ChinaMax.list
blackmatrix7 ChinaMedia Surge ruleset, https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/ChinaMedia/ChinaMedia.list
blackmatrix7 SteamCN Surge ruleset, https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/SteamCN/SteamCN.list
blackmatrix7 ChinaIPsBGP Surge ruleset, https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/ChinaIPsBGP/ChinaIPsBGP.list
ACL4SSR ChinaDomain, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaDomain.list
ACL4SSR ChinaMedia, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaMedia.list
ACL4SSR ChinaCompanyIp, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaCompanyIp.list
ACL4SSR ChinaIp IPv4, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaIp.list
ACL4SSR ChinaIpV6, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaIpV6.list
Repcz Tool ChinaDomain, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/ChinaDomain.list
Repcz Tool ChinaASN, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/ChinaASN.list
Repcz Tool DownloadCDN_CN, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/DownloadCDN_CN.list
Hackl0us SS-Rule-Snippet Apple-direct, https://raw.githubusercontent.com/Hackl0us/SS-Rule-Snippet/main/Rulesets/Surge/Basic/Apple-direct.list
Hackl0us SS-Rule-Snippet academic-direct, https://raw.githubusercontent.com/Hackl0us/SS-Rule-Snippet/main/Rulesets/Surge/Custom/academic-direct.list
LM-Firefly Domestic Surge ruleset, https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic.list
Clash-FX CN Apps Direct Domains, https://raw.githubusercontent.com/Clash-FX/cn-apps-direct-domains/main/apps-direct-domains.list
TannayeJ AI CN Vendor Rules, https://raw.githubusercontent.com/TannayeJ/ai-vendor-rules/main/generated/clash/all-ai-cn.yaml
NSZA156 Surge GeoX category-ai-cn, https://raw.githubusercontent.com/NSZA156/surge-geox-rules/release/geo/geosite/category-ai-cn.conf
VPSDance ai-proxy-rules Global AI, https://raw.githubusercontent.com/VPSDance/ai-proxy-rules/main/rules/surge/global.list
VPSDance Apple Intelligence custom Surge list, https://raw.githubusercontent.com/VPSDance/ai-proxy-rules/main/custom/surge/apple.list
SukkaW Surge AI rules, https://raw.githubusercontent.com/SukkaW/Surge/master/Source/non_ip/ai.conf
SukkaW Surge Apple Intelligence rules, https://raw.githubusercontent.com/SukkaW/Surge/master/Source/non_ip/apple_intelligence.conf
SukkaW Surge AI IP rules, https://raw.githubusercontent.com/SukkaW/Surge/master/Source/ip/ai.conf
xiaolai Anthropic & Claude Code Surge ruleset, https://raw.githubusercontent.com/xiaolai/anthropic-claude-surge-rules-set/main/dist/anthropic.list
viewer12 OverseasAI with third-party auth & verification hosts, https://raw.githubusercontent.com/viewer12/OverseasAI.list/HEAD/rule/Loon/OverseasAI/OverseasAI.list
zfdang clash-ruleset-ai-providers, https://raw.githubusercontent.com/zfdang/clash-ruleset-ai-providers/main/rules/ai-providers.yaml
zfdang Antigravity & Cloud Code YAML, https://raw.githubusercontent.com/zfdang/clash-ruleset-ai-providers/main/rules/antigravity.yaml
MetaCubeX category-ai-!cn, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-ai-%21cn.list
MetaCubeX category-ai-chat-!cn, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-ai-chat-%21cn.list
MetaCubeX openai, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/openai.list
MetaCubeX anthropic, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/anthropic.list
MetaCubeX google-gemini, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/google-gemini.list
MetaCubeX apple-intelligence, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/apple-intelligence.list
blackmatrix7 OpenAI Surge ruleset, https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/OpenAI/OpenAI.list
blackmatrix7 Claude Surge ruleset, https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Claude/Claude.list
blackmatrix7 Anthropic Surge ruleset, https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Anthropic/Anthropic.list
blackmatrix7 Gemini Surge ruleset, https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Gemini/Gemini.list
blackmatrix7 Copilot Surge ruleset, https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Copilot/Copilot.list
blackmatrix7 BardAI Surge ruleset, https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/BardAI/BardAI.list
max1874 funnysurge AI rules, https://raw.githubusercontent.com/max1874/funnysurge/main/rules/AI.txt
max1874 funnysurge Apple Intelligence rules, https://raw.githubusercontent.com/max1874/funnysurge/main/rules/Apple-Intelligence.txt
blankmagic Surge AI list, https://raw.githubusercontent.com/blankmagic/Surge/main/rule/ai.list
ACL4SSR AI ruleset, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/AI.list
Repcz Tool AI Surge ruleset, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/AI.list
blackmatrix7 PayPal Surge ruleset, https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/PayPal/PayPal.list
blackmatrix7 Stripe Surge ruleset, https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Stripe/Stripe.list
MetaCubeX paypal, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/paypal.list
MetaCubeX stripe, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/stripe.list
MetaCubeX wise, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/wise.list
MetaCubeX hsbc, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/hsbc.list
MetaCubeX visa, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/visa.list
MetaCubeX mastercard, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/mastercard.list
MetaCubeX intuit, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/intuit.list
MetaCubeX hcaptcha, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/hcaptcha.list
TannayeJ AI Global Vendor Rules, https://raw.githubusercontent.com/TannayeJ/ai-vendor-rules/main/generated/clash/all-ai-global.yaml
NSZA156 Surge GeoX category-ai-!cn, https://raw.githubusercontent.com/NSZA156/surge-geox-rules/release/geo/geosite/category-ai-!cn.conf
qianchongyang OpenClash AI Rules, https://raw.githubusercontent.com/qianchongyang/openclash-ai-rules/main/Rules/AI.list
Loyalsoldier surge-rules proxy ruleset, https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/proxy.txt
Loyalsoldier surge-rules gfw ruleset, https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/gfw.txt
Loyalsoldier surge-rules greatfire ruleset, https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/greatfire.txt
Loyalsoldier surge-rules tld-not-cn ruleset, https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/tld-not-cn.txt
MetaCubeX geolocation-!cn, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/geolocation-%21cn.list
MetaCubeX category-proxy-tunnels, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-proxy-tunnels.list
GFWList official Base64 AutoProxy list, https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt
SukkaW Surge global rules, https://raw.githubusercontent.com/SukkaW/Surge/master/Source/non_ip/global.conf
SukkaW Surge my_proxy rules, https://raw.githubusercontent.com/SukkaW/Surge/master/Source/non_ip/my_proxy.conf
SukkaW Surge Telegram domain rules, https://raw.githubusercontent.com/SukkaW/Surge/master/Source/non_ip/telegram.conf
SukkaW Surge Telegram ASN & IP rules, https://raw.githubusercontent.com/SukkaW/Surge/master/Source/ip/telegram_asn.conf
blackmatrix7 Global Surge ruleset, https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Global/Global.list
blackmatrix7 Proxy Surge ruleset, https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Proxy/Proxy.list
blackmatrix7 Telegram Surge ruleset, https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Telegram/Telegram.list
ACL4SSR Telegram ruleset, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Telegram.list
ACL4SSR GitHub ruleset, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Github.list
ACL4SSR Google ruleset, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Google.list
Repcz Tool Proxy Surge ruleset, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/Proxy.list
Repcz Tool ProxyGFW Surge ruleset, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/ProxyGFW.list
Repcz Tool AppleProxy Surge ruleset, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/AppleProxy.list
Repcz Tool DownloadCDN_Global Surge ruleset, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/DownloadCDN_Global.list
Hackl0us SS-Rule-Snippet Apple-proxy, https://raw.githubusercontent.com/Hackl0us/SS-Rule-Snippet/main/Rulesets/Surge/Basic/Apple-proxy.list
Hackl0us SS-Rule-Snippet academic-proxy, https://raw.githubusercontent.com/Hackl0us/SS-Rule-Snippet/main/Rulesets/Surge/Custom/academic-proxy.list
LM-Firefly PROXY Surge ruleset, https://raw.githubusercontent.com/LM-Firefly/Rules/master/PROXY.list
LM-Firefly CCC-Global Surge ruleset, https://raw.githubusercontent.com/LM-Firefly/Rules/master/CCC-Global.list
blackmatrix7 GlobalMedia Surge ruleset, https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/GlobalMedia/GlobalMedia.list
ACL4SSR ProxyMedia ruleset, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ProxyMedia.list
ACL4SSR TikTok ruleset, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/TikTok.list
ACL4SSR Netflix ruleset, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Netflix.list
ACL4SSR DisneyPlus ruleset, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/DisneyPlus.list
ACL4SSR Bahamut ruleset, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Bahamut.list
ACL4SSR AbemaTV ruleset, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/AbemaTV.list
ACL4SSR DMM ruleset, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Dmm.list
ACL4SSR MyTVSuper ruleset, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/MyTVSuper.list
ACL4SSR ViuTV ruleset, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/ViuTV.list
Repcz Tool ProxyMedia Surge ruleset, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/ProxyMedia.list
LM-Firefly GlobalMedia Surge ruleset, https://raw.githubusercontent.com/LM-Firefly/Rules/master/GlobalMedia.list
```

</details>

## 本地构建

环境依赖：[Bun](https://bun.sh/) >= 1.2 与 [Rust](https://www.rust-lang.org/) stable 工具链。

```bash
# 1. 安装依赖并生成配置、同步上游地理元数据
bun install
bun run build:config
bun run sync:metadata

# 2. 构建并校验全部产物（输出至 dist/）
cargo run --release -- geoip build --output dist
cargo run --release -- adblock build --output dist
cargo run --release -- routing build --output dist
```

## 开源许可

本项目采用 [MIT License](./LICENSE) 开源许可协议发布。

## 免责声明

本项目仅对公开的开源规则与网络数据进行自动化聚合与格式转换，不对数据的准确性、完整性或时效性作任何保证，亦不对用户使用本项目产物所产生的任何行为及后果承担责任。
