# surge-rules

面向自用的 Surge 规则集、去广告模块与多源 GeoIP 数据集，每小时自动更新。

[![最新更新](https://rule-set.ygxz.de/updated-at.svg)](https://github.com/ding113/surge-rules/releases/latest)

## 构建产物

| 产物 | 说明 | 下载链接 |
| :--- | :--- | :--- |
| `Country.mmdb` | 全球双栈全量 GeoIP 库（含省市、ASN、ISP 及内网/组网标记） | [Country.mmdb](https://rule-set.ygxz.de/Country.mmdb) |
| `Country-only.mmdb` | 全球双栈精简国家库（仅含 IP 与 `country` 字段） | [Country-only.mmdb](https://rule-set.ygxz.de/Country-only.mmdb) |
| `Country-cn.mmdb` | 中国大陆（`CN`）专属双栈 GeoIP 库 | [Country-cn.mmdb](https://rule-set.ygxz.de/Country-cn.mmdb) |
| `ASN.mmdb` | 全球公网自治系统（ASN）库 | [ASN.mmdb](https://rule-set.ygxz.de/ASN.mmdb) |
| `Adblock.sgmodule` | 去广告与隐私净化模块（重写、脚本、Map Local 与 HTTPDNS 拦截） | [Adblock.sgmodule](https://rule-set.ygxz.de/Adblock.sgmodule) · <kbd>[一键导入](https://rule-set.ygxz.de/install.html)</kbd> |
| `Adblock.list` | 广告与跟踪域名/IP 兜底拦截规则集 | [Adblock.list](https://rule-set.ygxz.de/Adblock.list) |
| `Direct.list` | 中国大陆服务、国内流媒体、国产 AI 及境外服务国内 CDN 直连规则集 | [Direct.list](https://rule-set.ygxz.de/Direct.list) |
| `AI.list` | 境外 AI、境外银行支付、PayPal、风控与遥测规则集 | [AI.list](https://rule-set.ygxz.de/AI.list) |
| `Proxy.list` | 境外服务与海外流媒体全量代理规则集（已包含 `AI.list`） | [Proxy.list](https://rule-set.ygxz.de/Proxy.list) |

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

<!-- sources:start -->
<details>
<summary>去广告模块与高级重写数据源（共 24 项）</summary>

```text
app2smile YouTube Adblock Module, https://raw.githubusercontent.com/app2smile/rules/master/module/youtube.sgmodule
Walvez Surge StartUp Ads Module, https://raw.githubusercontent.com/Walvez/surge-startup-ads/main/dist/StartUpAds_Selected.sgmodule
app2smile Spotify Adblock Module, https://raw.githubusercontent.com/app2smile/rules/master/module/spotify.module
app2smile Zhihu Adblock Module, https://raw.githubusercontent.com/app2smile/rules/master/module/zhihu.sgmodule
app2smile Baidu Tieba Adblock Module, https://raw.githubusercontent.com/app2smile/rules/master/module/tieba.sgmodule
app2smile Baidu Map Adblock Module, https://raw.githubusercontent.com/app2smile/rules/master/module/baidumap.sgmodule
app2smile Qidian Reader Adblock Module, https://raw.githubusercontent.com/app2smile/rules/master/module/qidian.sgmodule
AdGuard URL Tracking Protection Filter (CoreLibs), https://filters.adtidy.org/windows/filters/17.txt
uBlock Origin Privacy Query Parameter Stripping ($removeparam), https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy-removeparam.txt
AdGuard Spyware Filter General Extensions ($removeparam / $removeheader), https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/general_extensions.txt
AdGuard Legitimate URL Shortener Filter ($removeparam Pre-Compiled), https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_251_LegitimateURLShortener/filter.txt
AdGuard Dandelion Sprout Annoyances ($removeparam Pre-Compiled), https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_250_DandelionSproutAnnoyances/filter.txt
RU AdList Counter & Parameter Block ($removeparam), https://raw.githubusercontent.com/easylist/ruadlist/master/cntblock.txt
app2smile Tencent News Adblock Module, https://raw.githubusercontent.com/app2smile/rules/master/module/qqnews.sgmodule
Maasea Keep Adblock Module, https://raw.githubusercontent.com/Maasea/sgmodule/master/KeepAds.sgmodule
app2smile Google AdSense Module, https://raw.githubusercontent.com/app2smile/rules/master/module/adsense.sgmodule
fmz200 X (Twitter) Web Adblock Module, https://raw.githubusercontent.com/fmz200/wool_scripts/main/Surge/module/XWebAds.module
AdGuard Mail Tracking Protection Filter (CoreLibs), https://filters.adtidy.org/windows/filters/25.txt
Repcz / Kelee General Adblock Surge Module, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Module/Kelee/Remove_ads_by_keli.sgmodule
Repcz / Kelee WeChat Mini-Programs Adblock Module, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Module/Kelee/WexinMiniPrograms_Remove_ads.sgmodule
Repcz / Kelee Mobile Ad SDKs Module, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Module/Kelee/BlockAdvertisers.sgmodule
Aioneas Qzone Adblock Module, https://raw.githubusercontent.com/Aioneas/Surge/main/Module/qqzone.adblock.aioneas.sgmodule
zirawell R-Store All-in-One Surge Adblock Module, https://raw.githubusercontent.com/zirawell/R-Store/main/Rule/Surge/Adblock/All/allAdBlock.sgmodule
fmz200 Wool Scripts BlockAds Module, https://raw.githubusercontent.com/fmz200/wool_scripts/main/Surge/module/blockAds.module
```

</details>

<details>
<summary>去广告与隐私安全拦截数据源（共 164 项）</summary>

```text
AdGuard Mobile Ads Filter (CoreLibs), https://filters.adtidy.org/windows/filters/11.txt
AdGuard Base Filter (CoreLibs), https://filters.adtidy.org/windows/filters/2.txt
AdGuard Chinese Filter (CoreLibs), https://filters.adtidy.org/windows/filters/224.txt
AdGuard Tracking Protection Filter (CoreLibs), https://filters.adtidy.org/windows/filters/3.txt
AdGuard Social Media Filter (CoreLibs), https://filters.adtidy.org/windows/filters/4.txt
AdGuard Annoyances Filter (CoreLibs Combined 18-22), https://filters.adtidy.org/windows/filters/14.txt
AdGuard Online Malicious URL Blocklist (CoreLibs), https://filters.adtidy.org/windows/filters/208.txt
AdGuard DNS Filter, https://filters.adtidy.org/windows/filters/15.txt
AdGuard DNS Popup Hosts Filter, https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt
AdGuard CNAME Disguised Ads List, https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_ads.txt
AdGuard CNAME Disguised Trackers List, https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers.txt
AdGuard CNAME Disguised Clickthroughs List, https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_clickthroughs.txt
AdGuard Japanese Filter (CoreLibs), https://filters.adtidy.org/windows/filters/7.txt
List-KR Korean Filter (AdGuard CoreLibs), https://filters.adtidy.org/windows/filters/227.txt
AdGuard German Filter (CoreLibs), https://filters.adtidy.org/windows/filters/6.txt
AdGuard French Filter (CoreLibs), https://filters.adtidy.org/windows/filters/16.txt
AdGuard Russian Filter (CoreLibs), https://filters.adtidy.org/windows/filters/1.txt
AdGuard Spanish/Portuguese Filter (CoreLibs), https://filters.adtidy.org/windows/filters/9.txt
AdGuard Turkish Filter (CoreLibs), https://filters.adtidy.org/windows/filters/13.txt
AdGuard Dutch Filter (CoreLibs), https://filters.adtidy.org/windows/filters/8.txt
AdGuard Ukrainian Filter (CoreLibs), https://filters.adtidy.org/windows/filters/23.txt
AdGuard Italian Filter (CoreLibs), https://filters.adtidy.org/windows/filters/26.txt
AdGuard Polish Filter (CoreLibs), https://filters.adtidy.org/windows/filters/27.txt
uBlock Origin Built-in Filters (Pre-Expanded), https://ublockorigin.github.io/uAssetsCDN/filters/filters.min.txt
uBlock Origin Privacy Filters (Pre-Expanded), https://ublockorigin.github.io/uAssetsCDN/filters/privacy.min.txt
uBlock Origin Badware Risks (Pre-Expanded), https://ublockorigin.github.io/uAssetsCDN/filters/badware.min.txt
uBlock Origin Resource Abuse Filter, https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt
uBlock Origin Cookie Notices Filter, https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-cookies.txt
uBlock Origin Annoyances Filter, https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-others.txt
Brave First-Party Adblock Filters, https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-firstparty.txt
Brave First-Party Regional Adblock Filters, https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-firstparty-regional.txt
Brave First-Party CNAME Cloaking Trackers, https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-firstparty-cname.txt
Brave Specific Adblock Rules, https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-specific.txt
Brave iOS Specific Adblock Rules, https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-ios-specific.txt
EasyPrivacy Official, https://easylist.to/easylist/easyprivacy.txt
EasyList Official, https://easylist.to/easylist/easylist.txt
EasyList China, https://raw.githubusercontent.com/easylist/easylistchina/master/easylistchina.txt
Fanboy's Annoyance List, https://secure.fanboy.co.nz/fanboy-annoyance.txt
EasyList / Fanboy Cookie Monster (uBO), https://secure.fanboy.co.nz/fanboy-cookiemonster_ubo.txt
Fanboy Mobile App Promo & Notifications Blocker, https://secure.fanboy.co.nz/fanboy-mobile-notifications.txt
Anti-Adblock Killer / EasyList Anti-Adblock Filters, https://raw.githubusercontent.com/easylist/antiadblockfilters/master/antiadblockfilters/antiadblock_english.txt
AWAvenue Ads Rule (Surge RULE-SET), https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Surge-RULE-SET.list
AWAvenue Ads Rule (ABP Filter), https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt
SukkaW Reject Ruleset, https://ruleset.skk.moe/Clash/non_ip/reject.txt
SukkaW Reject-Drop Ruleset, https://ruleset.skk.moe/Clash/non_ip/reject-drop.txt
SukkaW Reject DomainSet, https://ruleset.skk.moe/List/domainset/reject.conf
SukkaW Reject IP Ruleset, https://ruleset.skk.moe/List/ip/reject.conf
8680 GOODBYEADS Adblock Filter, https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/adblock.txt
8680 GOODBYEADS DNS Blocklist, https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt
217heidai AdBlock Filters Full Release, https://github.com/217heidai/adblockfilters/releases/download/rule/adblockdns.txt
Cats-Team AdRules Surge DomainSet, https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules_surge_domainset.txt
Cats-Team / damengzhu jiekouAD Filter, https://raw.githubusercontent.com/Cats-Team/AdRules/main/rules/jiekouAD.txt
anti-AD Surge Ruleset, https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-surge.txt
HalfLife Merged Adblock Filter, https://raw.githubusercontent.com/sbwml/halflife-list/master/ad.txt
cjxlist Annoyance Filter, https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt
ACL4SSR BanProgramAD, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanProgramAD.list
ACL4SSR BanAD, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanAD.list
geekdada Surge Ads List, https://raw.githubusercontent.com/geekdada/surge-list/master/ads.list
Yuki2718 Japanese Filters Plus, https://raw.githubusercontent.com/Yuki2718/adblock2/main/japanese/jpf-plus.txt
Yuki2718 Japanese Filters Plus (AdGuard Modifiers), https://raw.githubusercontent.com/Yuki2718/adblock2/main/japanese/jpfp-ag.txt
YousList Korean Adblock Filter, https://adguardteam.github.io/HostlistsRegistry/assets/filter_15.txt
HaGeZi Multi ULTIMATE DNS Blocklist, https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt
HaGeZi Anti-Pop-Up Ads Blocklist, https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/popupads.txt
HaGeZi Fake Stores & Scam Blocklist, https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/fake.txt
HaGeZi Badware Hoster Blocklist, https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/hoster.txt
HaGeZi Threat Intelligence Feeds (Full), https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt
HaGeZi Native Referral Tracker Blocklist, https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/blocklist-referral-native.txt
HaGeZi Native Tracker Blocklist (Apple), https://adguardteam.github.io/HostlistsRegistry/assets/filter_67.txt
HaGeZi Native Tracker Blocklist (Xiaomi), https://adguardteam.github.io/HostlistsRegistry/assets/filter_60.txt
HaGeZi Native Tracker Blocklist (Huawei), https://adguardteam.github.io/HostlistsRegistry/assets/filter_73.txt
HaGeZi Native Tracker Blocklist (OPPO & Realme), https://adguardteam.github.io/HostlistsRegistry/assets/filter_66.txt
HaGeZi Native Tracker Blocklist (vivo), https://adguardteam.github.io/HostlistsRegistry/assets/filter_65.txt
HaGeZi Native Tracker Blocklist (Samsung), https://adguardteam.github.io/HostlistsRegistry/assets/filter_61.txt
HaGeZi Native Tracker Blocklist (Windows & Office), https://adguardteam.github.io/HostlistsRegistry/assets/filter_63.txt
HaGeZi Native Tracker Blocklist (TikTok Extended), https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.tiktok.extended.txt
HaGeZi Native Tracker Blocklist (Amazon), https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.amazon.txt
HaGeZi Native Tracker Blocklist (LG webOS), https://adguardteam.github.io/HostlistsRegistry/assets/filter_72.txt
HaGeZi Native Tracker Blocklist (Roku), https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.roku.txt
OISD Blocklist Big, https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt
1Hosts (Xtra), https://raw.githubusercontent.com/badmojr/1Hosts/master/Xtra/adblock.txt
hBlock Unified Ad · Tracking & Malware Domains, https://hblock.molinero.dev/hosts_domains.txt
NEO DEV HOST Adblocker, https://raw.githubusercontent.com/neodevpro/neodevhost/master/adblocker
Frogeye First-Party Trackers Hosts, https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt
Frogeye Multi-Party Trackers Hosts, https://hostfiles.frogeye.fr/multiparty-trackers-hosts.txt
Quidsup NoTrack Blocklist, https://gitlab.com/quidsup/notrack-blocklists/-/raw/master/notrack-blocklist.txt
Quidsup NoTrack Malware Blocklist, https://gitlab.com/quidsup/notrack-blocklists/-/raw/master/notrack-malware.txt
wBlock Ad and Tracking Hosts, https://raw.githubusercontent.com/0xCUB3/wBlock/main/filters/ad-tracking-hosts.txt
KADhosts Polish Ad & Fraud Blocklist, https://adguardteam.github.io/HostlistsRegistry/assets/filter_14.txt
ABPVN Vietnamese Adblock Filter, https://adguardteam.github.io/HostlistsRegistry/assets/filter_16.txt
ABPindo Indonesian Adblock Filter, https://adguardteam.github.io/HostlistsRegistry/assets/filter_22.txt
Dandelion Sprout Nordic Filters, https://adguardteam.github.io/HostlistsRegistry/assets/filter_13.txt
Frellwit's Swedish Hosts Filter, https://adguardteam.github.io/HostlistsRegistry/assets/filter_17.txt
StevenBlack Unified Hosts, https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
Peter Lowe's Ad and Tracking Server List, https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt
Dan Pollock's someonewhocares Blocklist, https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt
Dandelion Sprout Game Console Adblock List, https://adguardteam.github.io/HostlistsRegistry/assets/filter_6.txt
Perflyst & Dandelion Sprout Smart-TV Blocklist, https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt
Dandelion Sprout Anti Push Notifications, https://adguardteam.github.io/HostlistsRegistry/assets/filter_39.txt
celenityy BadBlock Ad & Tracking Filter, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/badblock.txt
celenityy BadBlock Click-Tracking Filter, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/click-tracking.txt
celenityy BadBlock Data Brokers Filter, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/data-brokers.txt
Yokoffing Click2Load Filter, https://raw.githubusercontent.com/yokoffing/filterlists/main/click2load.txt
Yokoffing Privacy Essentials, https://raw.githubusercontent.com/yokoffing/filterlists/main/privacy_essentials.txt
Suurp Crypto Faucet & Scam Ad Filter, https://raw.githubusercontent.com/Suurp/uBlock-CustomFilters/main/filters-faucets.txt
Suurp Monetized Ad-Shortlink Filter, https://raw.githubusercontent.com/Suurp/uBlock-CustomFilters/main/filters-shortlinks.txt
NoCoin Cryptomining Filter List, https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt
zachlagden Custom Advertising Domains, https://raw.githubusercontent.com/zachlagden/Pi-hole-Optimized-Blocklists/main/custom/advertising.txt
zachlagden Custom Tracking Domains, https://raw.githubusercontent.com/zachlagden/Pi-hole-Optimized-Blocklists/main/custom/tracking.txt
ShadowWhisperer Tracking List, https://adguardteam.github.io/HostlistsRegistry/assets/filter_69.txt
ShadowWhisperer Malware List, https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt
AssoEchap Stalkerware Indicators List, https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt
DurableNapkin Scam Blocklist, https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt
Dandelion Sprout Anti-Malware List, https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt
abuse.ch URLHaus Malicious URL Blocklist, https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh-online.txt
PhishTank & OpenPhish Phishing URL Blocklist, https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt
Phishing Army Extended Blocklist, https://phishing.army/download/phishing_army_blocklist_extended.txt
CERT Polska Malicious & Phishing Domains, https://adguardteam.github.io/HostlistsRegistry/assets/filter_41.txt
PhishDestroy Content-Verified Active Phishing Blocklist, https://raw.githubusercontent.com/phishdestroy/destroylist/main/dns/content_active.txt
PhishIndex Malicious Domains, https://raw.githubusercontent.com/PhishIndex/phishindex-blocklist/main/Data/Malicious%20Domains/adblock/phishindex_domains-adblock.txt
PhishIndex IP Logger Domains, https://raw.githubusercontent.com/PhishIndex/phishindex-blocklist/main/Data/IP%20Logger%20Domains/ip_logger_domains-adblock.txt
PersianBlocker Regional Adblock Filter, https://adguardteam.github.io/HostlistsRegistry/assets/filter_19.txt
Macedonian Pi-hole Adblock List, https://adguardteam.github.io/HostlistsRegistry/assets/filter_20.txt
turk-adlist Turkish DNS Blocklist, https://adguardteam.github.io/HostlistsRegistry/assets/filter_26.txt
Hufilter Hungarian Adblock List, https://adguardteam.github.io/HostlistsRegistry/assets/filter_35.txt
EasyList Lithuania DNS Filter, https://adguardteam.github.io/HostlistsRegistry/assets/filter_36.txt
Turkish Ad Hosts Blocklist, https://adguardteam.github.io/HostlistsRegistry/assets/filter_40.txt
EasyList Hebrew DNS Filter, https://adguardteam.github.io/HostlistsRegistry/assets/filter_43.txt
Ukrainian Security & Phishing Filter, https://adguardteam.github.io/HostlistsRegistry/assets/filter_62.txt
zachlagden Custom Malicious Domains, https://raw.githubusercontent.com/zachlagden/Pi-hole-Optimized-Blocklists/main/custom/malicious.txt
AdBlockID Plus Indonesian Filter (CoreLibs), https://raw.githubusercontent.com/realodix/AdBlockID/main/dist/adblockid_plus.adfl.txt
ABPVN Vietnamese AdGuard Advanced Filter, https://raw.githubusercontent.com/abpvn/abpvn/master/filter/abpvn_adguard.txt
MajkiIT Official Polish AdGuard Filter, https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-adblock-filters/adblock_adguard.txt
FiltersHeroes KAD Polish Anti-Scam & Fraud Filter, https://raw.githubusercontent.com/FiltersHeroes/KAD/master/KAD.txt
FiltersHeroes Polish Annoyances Filters (CoreLibs), https://filters.adtidy.org/windows/filters/237.txt
EasyList Czech and Slovak, https://raw.githubusercontent.com/tomasko126/easylistczechandslovak/master/filters.txt
Adblock List for Finland, https://raw.githubusercontent.com/finnish-easylist-addition/finnish-easylist-addition/master/Finland_adb.txt
EasyList Thailand, https://raw.githubusercontent.com/easylist-thailand/easylist-thailand/master/subscription/easylist-thailand.txt
Xfiles Italian Adblock Filter, https://raw.githubusercontent.com/gioxx/xfiles/master/filtri.txt
Dandelion Sprout Serbo-Croatian Filter (CoreLibs), https://filters.adtidy.org/windows/filters/252.txt
IndianList Regional Adblock Filter (CoreLibs), https://filters.adtidy.org/windows/filters/253.txt
Liste AR Arabic Adblock Filter (CoreLibs), https://filters.adtidy.org/windows/filters/112.txt
EasyList Italy (CoreLibs), https://filters.adtidy.org/windows/filters/109.txt
EasyList Portuguese (CoreLibs), https://filters.adtidy.org/windows/filters/124.txt
Greek AdBlock Filter (CoreLibs), https://filters.adtidy.org/windows/filters/121.txt
Bulgarian Adblock List (CoreLibs), https://filters.adtidy.org/windows/filters/103.txt
Latvian Adblock List (CoreLibs), https://filters.adtidy.org/windows/filters/111.txt
Icelandic ABP Adblock List (CoreLibs), https://filters.adtidy.org/windows/filters/119.txt
Loyalsoldier surge-rules reject ruleset, https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/reject.txt
GMOogway Shadowrocket Reject List, https://raw.githubusercontent.com/GMOogway/shadowrocket-rules/master/sr_reject_list.module
MetaCubeX category-httpdns-cn (Anti-HTTPDNS Bypass), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-httpdns-cn.list
Combined Privacy Block Lists (ABP), https://raw.githubusercontent.com/bongochong/CombinedPrivacyBlockLists/master/cpbl-abp-list.txt
hostsVN Vietnamese & Global Adservers Filter, https://raw.githubusercontent.com/bigdargon/hostsVN/master/filters/adservers-all.txt
hostsVN Malicious & Threat Extension Filter, https://raw.githubusercontent.com/bigdargon/hostsVN/master/extensions/threat/filter.txt
FMHY Unsafe · Fake-Download & Scamware Filterlist, https://raw.githubusercontent.com/fmhy/FMHYFilterlist/main/filterlist-abp.txt
MetaMask Web3 & Crypto Drainer Phishing Blocklist, https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/master/src/hosts.txt
Global Anti-Scam Organization (GASO) Blocklist, https://raw.githubusercontent.com/elliotwutingfeng/GlobalAntiScamOrg-blocklist/main/global-anti-scam-org-scam-urls-ABP.txt
ShadowWhisperer Scam & Fraud Domains, https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Scam
ShadowWhisperer Typosquatting & Homograph Domains, https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Typo
HaGeZi The World's Most Abused TLDs, https://adguardteam.github.io/HostlistsRegistry/assets/filter_56.txt
UT1 Toulouse University Malware Domains, https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/malware/domains
UT1 Toulouse University Phishing Domains, https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/phishing/domains
UT1 Toulouse University Cryptojacking Domains, https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/cryptojacking/domains
RPiList Specials Malware Blocklist, https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/malware
RPiList Specials Phishing Blocklist, https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Phishing-Angriffe
```

</details>

<details>
<summary>去广告防误伤白名单数据源（共 74 项）</summary>

```text
uBlock Origin Unbreak Allowlist, https://ublockorigin.github.io/uAssetsCDN/filters/unbreak.min.txt
uBlock Origin Quick Fixes, https://ublockorigin.github.io/uAssetsCDN/filters/quick-fixes.min.txt
Brave Adblock Unbreak List, https://raw.githubusercontent.com/brave/adblock-lists/master/brave-unbreak.txt
AdGuard DNS Filter Exceptions, https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exceptions.txt
AdGuard DNS Filter Exclusions, https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt
AdGuard Base Filter Allowlist, https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/allowlist.txt
AdGuard Base Stealth Protection Allowlist, https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/allowlist_stealth.txt
AdGuard Tracking Protection Allowlist, https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/allowlist.txt
AdGuard Mobile Tracking Protection Allowlist, https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile_allowlist.txt
AdGuard URL Tracking Protection Allowlist, https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/TrackParamFilter/sections/allowlist.txt
AdGuard Mobile Ads App Allowlist, https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/allowlist_app.txt
AdGuard Mobile Ads Web Allowlist, https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/allowlist_web.txt
AdGuard Chinese Filter Allowlist, https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/allowlist.txt
AdGuard Social Media Filter Allowlist, https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/allowlist.txt
AdGuard Cookie Notices Allowlist, https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_allowlist.txt
AdGuard Tracking Protection Cookies Allowlist, https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/cookies_allowlist.txt
AdGuard Japanese Filter Allowlist, https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/JapaneseFilter/sections/allowlist.txt
AdGuard German Filter Allowlist, https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/GermanFilter/sections/allowlist.txt
AdGuard French Filter Allowlist, https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/FrenchFilter/sections/allowlist.txt
AdGuard Russian Filter Allowlist, https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/CyrillicFilters/RussianFilter/sections/allowlist.txt
AdGuard Spanish/Portuguese Filter Allowlist, https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpanishFilter/sections/allowlist.txt
AdGuard Turkish Filter Allowlist, https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/TurkishFilter/sections/allowlist.txt
AdGuard Dutch Filter Allowlist, https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/DutchFilter/sections/allowlist.txt
AdGuard Ukrainian Filter Allowlist, https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/CyrillicFilters/UkrainianFilter/sections/allowlist.txt
EasyList Official Allowlist, https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist.txt
EasyPrivacy Official Allowlist, https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_allowlist.txt
EasyPrivacy International Allowlist, https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_allowlist_international.txt
EasyList Cookie Allowlist, https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_allowlist.txt
List-KR Shared Allowlist, https://raw.githubusercontent.com/List-KR/List-KR/master/filterslists/adblocking/filters-share/allowlist.txt
Cats-Team AdRules DNS Allowlist, https://raw.githubusercontent.com/Cats-Team/AdRules/main/mod/rules/dns-allowlist.txt
8680 GOODBYEADS Allow Rules, https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/allow.txt
8680 GOODBYEADS Curated Mod Whitelist, https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/mod/whitelist.txt
045200 ad-filter Curated Mod Whitelist, https://raw.githubusercontent.com/045200/ad-filter/multi/data/mod/whitelist.txt
Yuki2718 Japanese DNS Unbreak, https://raw.githubusercontent.com/Yuki2718/adblock2/main/japanese/dns-unbreak.txt
HaGeZi Legitimate URL Shortener Allowlist, https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-urlshortener.txt
HaGeZi Referral & Affiliate Tracking Unbreak Allowlist, https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral.txt
HaGeZi Native Referral Unbreak Allowlist, https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral-native.txt
HaGeZi Abused TLDs Legitimate Allowlist, https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock-allow.txt
Dandelion Sprout Legitimate URL Shorteners, https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LegitimateURLShortener.txt
Dandelion Sprout Legitimate URL Shortener Affiliate Allowlist, https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LegitimateURLShortener-AffiliateTagAllowlist.txt
zachlagden Pi-hole Optimized Whitelist, https://raw.githubusercontent.com/zachlagden/Pi-hole-Optimized-Blocklists/main/whitelist.txt
1Hosts Global Exclusion Allowlist, https://raw.githubusercontent.com/badmojr/1Hosts/master/-data/lists/exclude_for_all.txt
1Hosts Mini & Lite Exclusion Allowlist, https://raw.githubusercontent.com/badmojr/1Hosts/master/-data/lists/exclude_for_mini_Lite_only.txt
NEO DEV HOST Official Allowlist, https://raw.githubusercontent.com/neodevpro/neodevhost/master/allow
ShadowWhisperer Curated Whitelist, https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Whitelists/Whitelist
Ultimate Hosts Blacklist Official Whitelist, https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/whitelist/master/domains.list
Sefinek Blocklist Collection Main Whitelist, https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/main/whitelists/main.txt
Combined Privacy Block Lists Official Whitelist, https://raw.githubusercontent.com/bongochong/CombinedPrivacyBlockLists/master/NoFormatting/WhitelistedDomains.txt
UT1 Toulouse University Official Allowlist (liste_blanche), https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/liste_blanche/domains
ACL4SSR UnBan False-Positive Allowlist, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/UnBan.list
Dandelion Sprout Nordic Domains Allowlist, https://raw.githubusercontent.com/DandelionSprout/adfilt/master/NorwegianExperimentalList%20alternate%20versions/NordicFiltersDomainsAllowlist.txt
EasyList Fanboy Social Allowlist, https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_allowlist.txt
EasyList Fanboy Notifications Allowlist, https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_allowlist.txt
EasyList Fanboy Newsletter Allowlist, https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_allowlist.txt
BadBlock Apple Services Whitelist, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/apple_whitelist.txt
BadBlock Browser Services Whitelist, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/browser_whitelist.txt
BadBlock CAPTCHA Verification Whitelist, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/captcha_whitelist.txt
BadBlock Captive Portal Whitelist, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/captive_whitelist.txt
BadBlock PKI / OCSP / CRL Whitelist, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/certs_whitelist.txt
BadBlock Filter Update Mirrors Whitelist, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/content-blocking_whitelist.txt
BadBlock Emergency Alert Services Whitelist, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/emergency_whitelist.txt
BadBlock Local Network Discovery Whitelist, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/lan_whitelist.txt
BadBlock Microsoft Services Whitelist, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/microsoft_whitelist.txt
BadBlock Mobile App Infrastructure Whitelist, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/mobile_whitelist.txt
BadBlock Mozilla Firefox Whitelist, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/mozilla_whitelist.txt
BadBlock Push Notification Services Whitelist, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/push_whitelist.txt
BadBlock Safe Browsing Whitelist, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/safe-browsing_whitelist.txt
BadBlock NTP Time Sync Whitelist, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/time_whitelist.txt
BadBlock Combined Unbreak Whitelist, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/whitelist.txt
BadBlock Android System Services Whitelist, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/android_whitelist.txt
BadBlock Linux Distro & Package Mirror Whitelist, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/linux_whitelist.txt
BadBlock Nintendo Online Services Whitelist, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/nintendo_whitelist.txt
BadBlock Privacy-Respecting Analytics Whitelist, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/ethical_whitelist.txt
BadBlock Miscellaneous Functional Services Whitelist, https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/misc_whitelist.txt
```

</details>

<details>
<summary>国内直连分流数据源（Direct.list）（共 68 项）</summary>

```text
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
blackmatrix7 ChinaIPsBGP Surge ruleset, https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/ChinaIPsBGP/ChinaIPsBGP.list
ACL4SSR ChinaDomain, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaDomain.list
ACL4SSR ChinaMedia, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaMedia.list
ACL4SSR ChinaCompanyIp, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaCompanyIp.list
ACL4SSR ChinaIp IPv4, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaIp.list
ACL4SSR ChinaIpV6, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaIpV6.list
Repcz Tool ChinaDomain, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/ChinaDomain.list
Repcz Tool ChinaASN, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/ChinaASN.list
Repcz Tool DownloadCDN_CN, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/DownloadCDN_CN.list
LM-Firefly Domestic Surge ruleset, https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic.list
Clash-FX CN Apps Direct Domains, https://raw.githubusercontent.com/Clash-FX/cn-apps-direct-domains/main/apps-direct-domains.list
TannayeJ AI CN Vendor Rules, https://raw.githubusercontent.com/TannayeJ/ai-vendor-rules/main/generated/clash/all-ai-cn.yaml
NSZA156 Surge GeoX category-ai-cn, https://raw.githubusercontent.com/NSZA156/surge-geox-rules/release/geo/geosite/category-ai-cn.conf
Aethersailor Custom OpenClash Direct Rules, https://raw.githubusercontent.com/Aethersailor/Custom_OpenClash_Rules/main/rule/Custom_Direct.list
Aethersailor Domestic Steam Download CDN Rules, https://raw.githubusercontent.com/Aethersailor/Custom_OpenClash_Rules/main/rule/Steam_CDN.list
217heidai RoutingRules Domestic Direct Domains, https://raw.githubusercontent.com/217heidai/RoutingRules/main/rules/direct.txt
217heidai RoutingRules China IPv4 CIDR, https://raw.githubusercontent.com/217heidai/RoutingRules/main/rules/ipv4_china.txt
Loyalsoldier surge-rules cncidr IPv4/IPv6, https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/cncidr.txt
GMOogway Shadowrocket Direct List, https://raw.githubusercontent.com/GMOogway/shadowrocket-rules/master/sr_direct_list.module
ACL4SSR China Carrier One-Key SIM Login, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/ChinaOneKeyLogin.list
ACL4SSR Domestic Public DNS Endpoints, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/ChinaDNS.list
ACL4SSR Steam China & Domestic CDN, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/SteamCN.list
Repcz Tool Direct Surge Ruleset, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/Direct.list
Repcz Tool Custom Direct Overrides, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Custom/Direct.list
Repcz Tool Apple China CDN & Services, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/AppleCN.list
Repcz Tool ChinaIP Ruleset, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/ChinaIP.list
VPSDance Mainland China AI Coding Tools, https://raw.githubusercontent.com/VPSDance/ai-proxy-rules/main/rules/surge/cn-coding.list
VPSDance Mainland China LLM & Model APIs, https://raw.githubusercontent.com/VPSDance/ai-proxy-rules/main/rules/surge/cn-model.list
MetaCubeX tld-cn (.cn & Chinese IDN TLDs), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/tld-cn.list
MetaCubeX category-companies@cn, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-companies%40cn.list
MetaCubeX category-bank-cn (Domestic Banks), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-bank-cn.list
MetaCubeX category-securities-cn (Domestic Brokerages), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-securities-cn.list
MetaCubeX category-finance@cn (Domestic Finance), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-finance%40cn.list
MetaCubeX category-cas@cn (Domestic Certificate Authorities), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-cas%40cn.list
MetaCubeX category-ip-geo-detect@cn (Domestic IP Lookup), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-ip-geo-detect%40cn.list
MetaCubeX category-education-cn (Domestic Universities & MOOCs), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-education-cn.list
MetaCubeX category-hospital-cn (Domestic Healthcare), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-hospital-cn.list
MetaCubeX category-automobile-cn (Domestic Smart EV & Auto), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-automobile-cn.list
MetaCubeX category-logistics-cn (Domestic Express & Logistics), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-logistics-cn.list
MetaCubeX category-food-cn (Domestic Dining & Delivery), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-food-cn.list
MetaCubeX category-netdisk-cn (Domestic Cloud Drives), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-netdisk-cn.list
MetaCubeX category-entertainment-cn (Domestic Streaming & Video), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-entertainment-cn.list
MetaCubeX category-media-cn (Domestic News & Media), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-media-cn.list
MetaCubeX category-social-media-cn (Domestic Social Platforms), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-social-media-cn.list
MetaCubeX category-game-accelerator-cn, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-game-accelerator-cn.list
MetaCubeX category-game-platforms-download@cn, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-game-platforms-download%40cn.list
MetaCubeX category-wiki-cn, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-wiki-cn.list
MetaCubeX category-ntp-cn (Domestic NTP Servers), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-ntp-cn.list
MetaCubeX category-number-verification-cn (Carrier SIM Auth), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-number-verification-cn.list
```

</details>

<details>
<summary>境外 AI、支付与风控数据源（AI.list）（共 72 项）</summary>

```text
VPSDance ai-proxy-rules Global AI, https://raw.githubusercontent.com/VPSDance/ai-proxy-rules/main/rules/surge/global.list
VPSDance Apple Intelligence custom Surge list, https://raw.githubusercontent.com/VPSDance/ai-proxy-rules/main/custom/surge/apple.list
SukkaW Surge AI rules, https://raw.githubusercontent.com/SukkaW/Surge/master/Source/non_ip/ai.conf
SukkaW Surge Apple Intelligence rules, https://raw.githubusercontent.com/SukkaW/Surge/master/Source/non_ip/apple_intelligence.conf
SukkaW Surge AI IP rules, https://raw.githubusercontent.com/SukkaW/Surge/master/Source/ip/ai.conf
VPSDance ai-proxy-rules Global AI Coding Agents, https://raw.githubusercontent.com/VPSDance/ai-proxy-rules/main/rules/surge/global-coding.list
VPSDance ai-proxy-rules Global LLM & Model APIs, https://raw.githubusercontent.com/VPSDance/ai-proxy-rules/main/rules/surge/global-model.list
VPSDance ai-proxy-rules Global Generative Media AI, https://raw.githubusercontent.com/VPSDance/ai-proxy-rules/main/rules/surge/global-media.list
viewer12 OverseasAI with third-party auth & verification hosts, https://raw.githubusercontent.com/viewer12/OverseasAI.list/HEAD/rule/Loon/OverseasAI/OverseasAI.list
zfdang clash-ruleset-ai-providers, https://raw.githubusercontent.com/zfdang/clash-ruleset-ai-providers/main/rules/ai-providers.yaml
zfdang Antigravity & Cloud Code YAML, https://raw.githubusercontent.com/zfdang/clash-ruleset-ai-providers/main/rules/antigravity.yaml
MetaCubeX category-ai-!cn, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-ai-%21cn.list
MetaCubeX category-ai-chat-!cn, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-ai-chat-%21cn.list
MetaCubeX openai, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/openai.list
MetaCubeX anthropic, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/anthropic.list
MetaCubeX google-gemini, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/google-gemini.list
MetaCubeX apple-intelligence, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/apple-intelligence.list
max1874 funnysurge AI rules, https://raw.githubusercontent.com/max1874/funnysurge/main/rules/AI.txt
max1874 funnysurge Apple Intelligence rules, https://raw.githubusercontent.com/max1874/funnysurge/main/rules/Apple-Intelligence.txt
blankmagic Surge AI list, https://raw.githubusercontent.com/blankmagic/Surge/main/rule/ai.list
ACL4SSR AI ruleset, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/AI.list
Repcz Tool AI Surge ruleset, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/AI.list
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
Repcz Tool Custom AI Overrides, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Custom/AI.list
Repcz Tool OpenAI Surge Ruleset, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/OpenAI.list
Repcz Tool Claude Surge Ruleset, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/Claude.list
Repcz Tool xAI / Grok Surge Ruleset, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/xAI.list
ACL4SSR OpenAI Ruleset, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/OpenAi.list
ACL4SSR Claude Ruleset, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Claude.list
ACL4SSR Gemini Ruleset, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Gemini.list
MetaCubeX perplexity, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/perplexity.list
MetaCubeX xai (Grok), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/xai.list
MetaCubeX cursor, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/cursor.list
MetaCubeX windsurf (Codeium), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/windsurf.list
MetaCubeX github-copilot, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/github-copilot.list
MetaCubeX jetbrains-ai, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/jetbrains-ai.list
MetaCubeX groq, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/groq.list
MetaCubeX poe, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/poe.list
MetaCubeX elevenlabs, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/elevenlabs.list
MetaCubeX huggingface, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/huggingface.list
itdoginfo Google AI & Gemini Regional Bypass Domains, https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Services/google_ai.lst
UT1 Toulouse University AI Domains (Repurposed as AI Inventory), https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/ai/domains
Repcz Tool PayPal Surge Ruleset, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/PayPal.list
MetaCubeX ibkr (Interactive Brokers), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/ibkr.list
MetaCubeX schwab (Charles Schwab), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/schwab.list
MetaCubeX standardchartered, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/standardchartered.list
MetaCubeX citic@!cn (CITIC Bank International HK), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/citic%40%21cn.list
MetaCubeX category-bank-jp (Japanese Banking), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-bank-jp.list
MetaCubeX squareup (Square / Block Payments), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/squareup.list
MetaCubeX redotpay (Overseas Card & Payment), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/redotpay.list
MetaCubeX straitsx (Singapore Payment Gateway), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/straitsx.list
MetaCubeX category-finance (Overseas Finance & Exchanges), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-finance.list
UT1 Toulouse University Global Banking Inventory (Repurposed), https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/bank/domains
UT1 Toulouse University Global Financial Inventory (Repurposed), https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/financial/domains
MetaCubeX category-ip-geo-detect (IP Risk & Geo Scoring), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-ip-geo-detect.list
BadBlock CAPTCHA Verification Allowlist (Repurposed for Risk-Control), https://raw.githubusercontent.com/celenityy/BadBlock/pages/wildcards-no-star/captcha_whitelist.txt
MetaCubeX category-password-management (Passkey & Vault Sync), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-password-management.list
MetaCubeX category-ai-!cn@telemetry (AI Attestation & Telemetry), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-ai-%21cn%40telemetry.list
MetaCubeX openai@telemetry, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/openai%40telemetry.list
MetaCubeX anthropic@telemetry, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/anthropic%40telemetry.list
MetaCubeX paypal@telemetry (PayPal Risk & Device Telemetry), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/paypal%40telemetry.list
MetaCubeX category-telemetry (Overseas OS & SDK Telemetry), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-telemetry.list
```

</details>

<details>
<summary>境外代理与流媒体数据源（Proxy.list）（共 125 项）</summary>

```text
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
ACL4SSR Telegram ruleset, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Telegram.list
ACL4SSR GitHub ruleset, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Github.list
ACL4SSR Google ruleset, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Google.list
Repcz Tool Proxy Surge ruleset, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/Proxy.list
Repcz Tool ProxyGFW Surge ruleset, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/ProxyGFW.list
Repcz Tool AppleProxy Surge ruleset, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/AppleProxy.list
Repcz Tool DownloadCDN_Global Surge ruleset, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/DownloadCDN_Global.list
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
Aethersailor Custom OpenClash Proxy Rules, https://raw.githubusercontent.com/Aethersailor/Custom_OpenClash_Rules/main/rule/Custom_Proxy.list
217heidai RoutingRules Overseas Proxy Domains, https://raw.githubusercontent.com/217heidai/RoutingRules/main/rules/proxy.txt
GMOogway Shadowrocket Proxy List, https://raw.githubusercontent.com/GMOogway/shadowrocket-rules/master/sr_proxy_list.module
hezhijie0327 GFWList2AGH Full Overseas Blacklist (Repurposed), https://raw.githubusercontent.com/hezhijie0327/GFWList2AGH/main/gfwlist2adguardhome/blacklist_full.txt
Loyalsoldier surge-rules iCloud ruleset, https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/icloud.txt
Loyalsoldier surge-rules Google ruleset, https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/google.txt
MetaCubeX category-scholar-!cn (Global Academic & Research), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-scholar-%21cn.list
MetaCubeX google-scholar, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/google-scholar.list
ACL4SSR Overseas Scholar & Journals, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Scholar.list
MetaCubeX wikimedia (Wikipedia & Wikimedia), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/wikimedia.list
MetaCubeX category-web-archive (Internet Archive & Mirrors), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-web-archive.list
MetaCubeX category-dev (Global Developer Ecosystem), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-dev.list
MetaCubeX category-container (OCI & Container Registries), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-container.list
MetaCubeX github, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/github.list
MetaCubeX gitlab, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/gitlab.list
MetaCubeX docker, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/docker.list
MetaCubeX npmjs, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/npmjs.list
MetaCubeX vercel, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/vercel.list
ACL4SSR Developer Ecosystem, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Developer.list
ACL4SSR Docker & Registries, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Docker.list
MetaCubeX category-entertainment@!cn, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-entertainment%40%21cn.list
MetaCubeX category-games-!cn (Global Gaming Platforms), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-games-%21cn.list
MetaCubeX category-social-media-!cn, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-social-media-%21cn.list
MetaCubeX category-forums (Overseas Communities), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-forums.list
MetaCubeX category-communication (Global IM & VoIP), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-communication.list
MetaCubeX youtube, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/youtube.list
MetaCubeX spotify, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/spotify.list
MetaCubeX netflix, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/netflix.list
MetaCubeX disney, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/disney.list
MetaCubeX hbo, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/hbo.list
MetaCubeX primevideo, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/primevideo.list
MetaCubeX tiktok, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/tiktok.list
MetaCubeX twitter (X), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/twitter.list
MetaCubeX meta (Facebook / Instagram / Threads), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/meta.list
MetaCubeX whatsapp, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/whatsapp.list
MetaCubeX signal, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/signal.list
MetaCubeX reddit, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/reddit.list
MetaCubeX pixiv, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/pixiv.list
MetaCubeX line, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/line.list
MetaCubeX steam (Community & Store; CN CDN stays Direct), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/steam.list
MetaCubeX epicgames, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/epicgames.list
MetaCubeX playstation, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/playstation.list
MetaCubeX xbox, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/xbox.list
MetaCubeX nintendo, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/nintendo.list
MetaCubeX category-cryptocurrency (Web3 & Exchanges), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-cryptocurrency.list
MetaCubeX category-anticensorship, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-anticensorship.list
MetaCubeX category-vpnservices, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-vpnservices.list
MetaCubeX category-doh (Encrypted DNS Endpoints), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-doh.list
MetaCubeX category-ipfs (IPFS Gateways), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-ipfs.list
MetaCubeX category-pt (Private Trackers), https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-pt.list
MetaCubeX category-public-tracker, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-public-tracker.list
Repcz Tool Crypto & Web3 Surge Ruleset, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/Crypto.list
HaGeZi Encrypted DNS · VPN · TOR · Proxy Endpoints, https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh-vpn-proxy-bypass.txt
ShadowWhisperer VPN · Proxy & Tunnel Domains, https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Tunnels
HaGeZi Global Social Networks Inventory, https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/social.txt
NoGoogle Exhaustive Google Ecosystem Domains, https://adguardteam.github.io/HostlistsRegistry/assets/filter_37.txt
NoAmazon Exhaustive Amazon · PrimeVideo · Twitch · IMDb Ecosystem, https://raw.githubusercontent.com/nickspaargaren/no-amazon/master/amazon-adguard.txt
StevenBlack Social Media Hosts Extension, https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social-only/hosts
MetaCubeX Geosite Discord, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/discord.list
MetaCubeX Geosite Twitch, https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/twitch.list
itdoginfo Overseas Anime & Manga Platforms, https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Categories/anime.lst
itdoginfo Censored International News Media, https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Categories/news.lst
itdoginfo Geo-Restricted Global Services, https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Categories/geoblock.lst
itdoginfo Adult Streaming Inventory, https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Categories/porn.lst
HaGeZi NSFW & Adult Platforms, https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/nsfw.txt
OISD NSFW & Adult Platforms (Full Inventory), https://raw.githubusercontent.com/sjhgvr/oisd/main/domainswild_nsfw.txt
ShadowWhisperer Adult Platforms, https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Adult
ShadowWhisperer Overseas Dating Platforms, https://adguardteam.github.io/HostlistsRegistry/assets/filter_57.txt
ShadowWhisperer Overseas Gambling Platforms, https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Gambling
ShadowWhisperer Cryptocurrency & Web3 Platforms, https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Cryptocurrency
StevenBlack Adult Media Hosts Extension, https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts
StevenBlack Overseas Gambling Hosts Extension, https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts
HaGeZi Overseas Gambling Platforms (Full), https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/gambling.txt
HaGeZi Anti-Piracy · Sci-Hub · LibGen · DDL & Streaming Mirrors, https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/anti.piracy.txt
RPiList Adult & NSFW Content Inventory (pornblock1), https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/pornblock1
Stevo's AI & Generative Media Blocklist (Repurposed for Proxy), https://filters.adtidy.org/windows/filters/260.txt
UT1 Toulouse University Gambling Platforms, https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/gambling/domains
UT1 Toulouse University Dating Platforms, https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/dating/domains
UT1 Toulouse University Social Networks, https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/social_networks/domains
UT1 Toulouse University VPN Endpoints, https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/vpn/domains
UT1 Toulouse University Residential Proxy & Circumvention Endpoints, https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/residential-proxies/domains
UT1 Toulouse University Warez & DDL Mirrors, https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/warez/domains
UT1 Toulouse University Manga & Anime Portals, https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/manga/domains
UT1 Toulouse University Bitcoin & Crypto Portals, https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/bitcoin/domains
RPiList Specials Proxy & Bypass Endpoints, https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/proxies
RPiList Specials Overseas Streaming Mirrors, https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Streaming
cbuijs Accomplist Encrypted DoH & Bypass Inventory, https://raw.githubusercontent.com/cbuijs/accomplist/master/doh/deugniets.black.list
Sinfonietta Gambling Hosts Inventory, https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/gambling-hosts
Sinfonietta Adult Media Hosts Inventory, https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/pornography-hosts
Sinfonietta Global Social Media Hosts Inventory, https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/social-hosts
hostsVN Overseas Gambling Extension, https://raw.githubusercontent.com/bigdargon/hostsVN/master/extensions/gambling/hosts
```

</details>

<details>
<summary>GeoIP、ASN 与行政区划元数据数据源（共 113 项）</summary>

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
217heidai RoutingRules China IPv4, https://raw.githubusercontent.com/217heidai/RoutingRules/main/rules/ipv4_china.txt
Hackl0us GeoIP2-CN, https://raw.githubusercontent.com/Hackl0us/GeoIP2-CN/release/CN-ip-cidr.txt
Chanthmiao Cn V4, https://raw.githubusercontent.com/ChanthMiao/China-IPv4-List/release/cn.txt
Chanthmiao Cn V6, https://raw.githubusercontent.com/ChanthMiao/China-IPv6-List/release/cn6.txt
IPinfo Lite Country & ASN, https://github.com/Alice39s/ipinfo-csv-lite/releases/latest
MaxMind GeoLite2 City / Country / ASN, https://github.com/Skiddle-ID/geoip2-mirror/releases/latest
DB-IP City Lite, https://github.com/jcjc-dev/mmdb-latest/releases/download/dbip-latest/dbip-city-lite.mmdb
DB-IP Country Lite, https://github.com/jcjc-dev/mmdb-latest/releases/download/dbip-latest/dbip-country-lite.mmdb
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
DB-IP ASN Lite, https://github.com/jcjc-dev/mmdb-latest/releases/download/dbip-latest/dbip-asn-lite.mmdb
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
Alice39s BGP.Tools-OpenDB Anycast ASN Tags, https://raw.githubusercontent.com/Alice39s/BGP.Tools-OpenDB/auto-update/tags/anycast/tags-anycast.csv
Alice39s BGP.Tools-OpenDB Satellite Network ASN Tags, https://raw.githubusercontent.com/Alice39s/BGP.Tools-OpenDB/auto-update/tags/satnet/tags-satnet.csv
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
```

</details>
<!-- sources:end -->

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
