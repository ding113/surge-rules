# surge-rules

面向自用的 Surge 规则集、去广告模块与多源 GeoIP 数据集，每小时自动更新。

[![最新更新](https://rule-set.ygxz.de/updated-at.svg)](https://github.com/ding113/surge-rules/releases/latest)

## 构建产物

| 产物 | 说明 | 下载链接 |
| :--- | :--- | :--- |
| `Country.mmdb` | 全球双栈全量 GeoIP 库（含省市、ASN、ISP 及内网/组网标记） | [GitHub](https://github.com/ding113/surge-rules/releases/latest/download/Country.mmdb) · [Cloudflare](https://rule-set.ygxz.de/Country.mmdb) |
| `Country-only.mmdb` | 全球双栈精简国家库（仅含 IP 与 `country` 字段） | [GitHub](https://github.com/ding113/surge-rules/releases/latest/download/Country-only.mmdb) · [Cloudflare](https://rule-set.ygxz.de/Country-only.mmdb) |
| `Country-cn.mmdb` | 中国大陆（`CN`）专属双栈 GeoIP 库 | [GitHub](https://github.com/ding113/surge-rules/releases/latest/download/Country-cn.mmdb) · [Cloudflare](https://rule-set.ygxz.de/Country-cn.mmdb) |
| `ASN.mmdb` | 全球公网自治系统（ASN）库 | [GitHub](https://github.com/ding113/surge-rules/releases/latest/download/ASN.mmdb) · [Cloudflare](https://rule-set.ygxz.de/ASN.mmdb) |
| `Adblock.sgmodule` | 去广告与隐私净化模块（重写、脚本、Map Local 与 HTTPDNS 拦截） | [GitHub](https://github.com/ding113/surge-rules/releases/latest/download/Adblock.sgmodule) · [Cloudflare](https://rule-set.ygxz.de/Adblock.sgmodule) · <kbd>[一键导入](https://rule-set.ygxz.de/install.html)</kbd> |
| `Adblock.list` | 广告与跟踪域名/IP 兜底拦截规则集 | [GitHub](https://github.com/ding113/surge-rules/releases/latest/download/Adblock.list) · [Cloudflare](https://rule-set.ygxz.de/Adblock.list) |
| `Direct.list` | 中国大陆服务、国内流媒体、国产 AI 及境外服务国内 CDN 直连规则集 | [GitHub](https://github.com/ding113/surge-rules/releases/latest/download/Direct.list) · [Cloudflare](https://rule-set.ygxz.de/Direct.list) |
| `AI.list` | 境外 AI、境外银行支付、PayPal、风控与遥测规则集 | [GitHub](https://github.com/ding113/surge-rules/releases/latest/download/AI.list) · [Cloudflare](https://rule-set.ygxz.de/AI.list) |
| `Proxy.list` | 境外服务与海外流媒体全量代理规则集（已包含 `AI.list`） | [GitHub](https://github.com/ding113/surge-rules/releases/latest/download/Proxy.list) · [Cloudflare](https://rule-set.ygxz.de/Proxy.list) |

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
<summary>去广告模块与高级重写数据源（共 38 项）</summary>

```text
app2smile YouTube Adblock Module, https://raw.githubusercontent.com/app2smile/rules/master/module/youtube.sgmodule
Walvez Surge StartUp Ads Module, https://raw.githubusercontent.com/Walvez/surge-startup-ads/main/dist/StartUpAds_Selected.sgmodule
app2smile Spotify Adblock Module, https://raw.githubusercontent.com/app2smile/rules/master/module/spotify.module
app2smile Zhihu Adblock Module, https://raw.githubusercontent.com/app2smile/rules/master/module/zhihu.sgmodule
app2smile Baidu Tieba Adblock Module, https://raw.githubusercontent.com/app2smile/rules/master/module/tieba.sgmodule
app2smile Baidu Map Adblock Module, https://raw.githubusercontent.com/app2smile/rules/master/module/baidumap.sgmodule
app2smile Qidian Reader Adblock Module, https://raw.githubusercontent.com/app2smile/rules/master/module/qidian.sgmodule
ddgksf2013 Weibo Adblock Rewrite, https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/WeiboAds.conf
ddgksf2013 Amap Adblock Rewrite, https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/AmapAds.conf
AdGuard URL Tracking Protection Filter (CoreLibs), https://filters.adtidy.org/windows/filters/17.txt
uBlock Origin Privacy Query Parameter Stripping ($removeparam), https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy-removeparam.txt
AdGuard Spyware Filter General Extensions ($removeparam / $removeheader), https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/general_extensions.txt
AdGuard Legitimate URL Shortener Filter ($removeparam Pre-Compiled), https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_251_LegitimateURLShortener/filter.txt
Dandelion Sprout ClearURLs ($removeparam), https://raw.githubusercontent.com/DandelionSprout/adfilt/master/ClearURLs%20for%20uBo/clear_urls_uboified.txt
AdGuard Dandelion Sprout Annoyances ($removeparam Pre-Compiled), https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_250_DandelionSproutAnnoyances/filter.txt
RU AdList Counter & Parameter Block ($removeparam), https://raw.githubusercontent.com/easylist/ruadlist/master/cntblock.txt
app2smile Tencent News Adblock Module, https://raw.githubusercontent.com/app2smile/rules/master/module/qqnews.sgmodule
Maasea Keep Adblock Module, https://raw.githubusercontent.com/Maasea/sgmodule/master/KeepAds.sgmodule
app2smile Google AdSense Module, https://raw.githubusercontent.com/app2smile/rules/master/module/adsense.sgmodule
fmz200 X (Twitter) Web Adblock Module, https://raw.githubusercontent.com/fmz200/wool_scripts/main/Surge/module/XWebAds.module
ddgksf2013 Ximalaya Adblock Rewrite, https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/Ximalaya.conf
ddgksf2013 Cainiao Adblock Rewrite, https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/CainiaoAds.conf
ddgksf2013 SMZDM Adblock Rewrite, https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/SmzdmAds.conf
ddgksf2013 Goofish (Xianyu) Adblock Rewrite, https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/GoofishAds.conf
ddgksf2013 WeChat Official Account Adblock Rewrite, https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/WeChat.conf
ddgksf2013 NetEase Cloud Music Adblock Rewrite, https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/NeteaseAds.conf
ddgksf2013 Soda Music (QiShui) Adblock Rewrite, https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/QiShuiMusicAds.conf
ddgksf2013 Xiaoyuzhou Podcast Adblock Rewrite, https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/XiaoYuZhouAds.conf
ddgksf2013 ColorfulClouds Weather Adblock Rewrite, https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/CaiYunAds.conf
ddgksf2013 Reddit Adblock Rewrite, https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/RedditAds.conf
QingRex HTTPDNS Block Module, https://raw.githubusercontent.com/QingRex/LoonKissSurge/main/Surge/Beta/%E6%8B%A6%E6%88%AAHTTPDNS.beta.sgmodule
ddgksf2013 WeChat Mini-Program Adblock Rewrite, https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/Applet.conf
Repcz / Kelee General Adblock Surge Module, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Module/Kelee/Remove_ads_by_keli.sgmodule
Repcz / Kelee WeChat Mini-Programs Adblock Module, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Module/Kelee/WexinMiniPrograms_Remove_ads.sgmodule
Repcz / Kelee Mobile Ad SDKs Module, https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Module/Kelee/BlockAdvertisers.sgmodule
Aioneas Qzone Adblock Module, https://raw.githubusercontent.com/Aioneas/Surge/main/Module/qqzone.adblock.aioneas.sgmodule
zirawell R-Store All-in-One Surge Adblock Module, https://raw.githubusercontent.com/zirawell/R-Store/main/Rule/Surge/Adblock/All/allAdBlock.sgmodule
fmz200 Wool Scripts BlockAds Module, https://raw.githubusercontent.com/fmz200/wool_scripts/main/Surge/module/blockAds.module
```

</details>

<details>
<summary>去广告与隐私安全拦截数据源（共 126 项）</summary>

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
ABP Anti-Circumvention Filter List, https://raw.githubusercontent.com/abp-filters/abp-filters-anti-cv/master/english.txt
Anti-Adblock Killer / EasyList Anti-Adblock Filters, https://raw.githubusercontent.com/easylist/antiadblockfilters/master/antiadblockfilters/antiadblock_english.txt
AWAvenue Ads Rule (Surge RULE-SET), https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Surge-RULE-SET.list
AWAvenue Ads Rule (ABP Filter), https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt
AWAvenue Ads Rule Replenish, https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Replenish.txt
SukkaW Reject Ruleset, https://ruleset.skk.moe/Clash/non_ip/reject.txt
SukkaW Reject-Drop Ruleset, https://ruleset.skk.moe/Clash/non_ip/reject-drop.txt
SukkaW Reject DomainSet, https://ruleset.skk.moe/List/domainset/reject.conf
SukkaW Reject IP Ruleset, https://ruleset.skk.moe/List/ip/reject.conf
mieqq In-App Tracker Ruleset, https://raw.githubusercontent.com/mieqq/mieqq/master/In-AppTracker.txt
Hackl0us Video Ad Ruleset, https://raw.githubusercontent.com/Hackl0us/SS-Rule-Snippet/master/Rulesets/Surge/Custom/video-ad.list
8680 GOODBYEADS Adblock Filter, https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/adblock.txt
8680 GOODBYEADS DNS Blocklist, https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt
217heidai AdBlock Surge Lite, https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblocksurgelite.list
Cats-Team AdRules Surge DomainSet, https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules_surge_domainset.txt
Cats-Team / damengzhu jiekouAD Filter, https://raw.githubusercontent.com/Cats-Team/AdRules/main/rules/jiekouAD.txt
anti-AD Surge Ruleset, https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-surge.txt
HalfLife Merged Adblock Filter, https://raw.githubusercontent.com/sbwml/halflife-list/master/ad.txt
NobyDa ND-AD Surge Ruleset, https://raw.githubusercontent.com/NobyDa/ND-AD/master/Surge/AD_Block.txt
xinggsf Chengfeng Adblock Rule, https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/rule.txt
xinggsf Chengfeng Video Ad Rule, https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt
cjxlist Annoyance Filter, https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt
ACL4SSR BanProgramAD, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanProgramAD.list
ACL4SSR BanAD, https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanAD.list
geekdada Surge Ads List, https://raw.githubusercontent.com/geekdada/surge-list/master/ads.list
Yuki2718 Japanese Filters Plus, https://raw.githubusercontent.com/Yuki2718/adblock2/main/japanese/jpf-plus.txt
Yuki2718 Japanese Filters Plus (AdGuard Modifiers), https://raw.githubusercontent.com/Yuki2718/adblock2/main/japanese/jpfp-ag.txt
YousList Korean Adblock Filter, https://adguardteam.github.io/HostlistsRegistry/assets/filter_15.txt
HaGeZi Multi Pro++ DNS Blocklist, https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt
HaGeZi Anti-Pop-Up Ads Blocklist, https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/popupads.txt
HaGeZi Fake Stores & Scam Blocklist, https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/fake.txt
HaGeZi Badware Hoster Blocklist, https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/hoster.txt
HaGeZi Threat Intelligence Feeds (Mini), https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt
HaGeZi Native Tracker Blocklist (Apple), https://adguardteam.github.io/HostlistsRegistry/assets/filter_67.txt
HaGeZi Native Tracker Blocklist (Xiaomi), https://adguardteam.github.io/HostlistsRegistry/assets/filter_60.txt
HaGeZi Native Tracker Blocklist (Huawei), https://adguardteam.github.io/HostlistsRegistry/assets/filter_73.txt
HaGeZi Native Tracker Blocklist (OPPO & Realme), https://adguardteam.github.io/HostlistsRegistry/assets/filter_66.txt
HaGeZi Native Tracker Blocklist (vivo), https://adguardteam.github.io/HostlistsRegistry/assets/filter_65.txt
HaGeZi Native Tracker Blocklist (Samsung), https://adguardteam.github.io/HostlistsRegistry/assets/filter_61.txt
HaGeZi Native Tracker Blocklist (Windows & Office), https://adguardteam.github.io/HostlistsRegistry/assets/filter_63.txt
HaGeZi Native Tracker Blocklist (TikTok), https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.tiktok.txt
HaGeZi Native Tracker Blocklist (Amazon), https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.amazon.txt
HaGeZi Native Tracker Blocklist (LG webOS), https://adguardteam.github.io/HostlistsRegistry/assets/filter_72.txt
HaGeZi Native Tracker Blocklist (Roku), https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.roku.txt
OISD Blocklist Big, https://big.oisd.nl/
1Hosts (Lite), https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/adblock.txt
Disconnect Simple Ad Filter List, https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt
Disconnect Simple Malvertising List, https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt
wBlock Ad and Tracking Hosts, https://raw.githubusercontent.com/0xCUB3/wBlock/main/filters/ad-tracking-hosts.txt
WindowsSpyBlocker Telemetry & Spy Hosts, https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt
KADhosts Polish Ad & Fraud Blocklist, https://adguardteam.github.io/HostlistsRegistry/assets/filter_14.txt
ABPVN Vietnamese Adblock Filter, https://adguardteam.github.io/HostlistsRegistry/assets/filter_16.txt
ABPindo Indonesian Adblock Filter, https://adguardteam.github.io/HostlistsRegistry/assets/filter_22.txt
Dandelion Sprout Nordic Filters, https://adguardteam.github.io/HostlistsRegistry/assets/filter_13.txt
Frellwit's Swedish Hosts Filter, https://adguardteam.github.io/HostlistsRegistry/assets/filter_17.txt
StevenBlack Unified Hosts, https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
AdAway Official Mobile Adblock Hosts, https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt
Peter Lowe's Ad and Tracking Server List, https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt
Dan Pollock's someonewhocares Blocklist, https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt
Dandelion Sprout Game Console Adblock List, https://adguardteam.github.io/HostlistsRegistry/assets/filter_6.txt
Perflyst & Dandelion Sprout Smart-TV Blocklist, https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt
Dandelion Sprout Anti Push Notifications, https://adguardteam.github.io/HostlistsRegistry/assets/filter_39.txt
LanikSJ Web Annoyances Ultralist, https://raw.githubusercontent.com/LanikSJ/webannoyances/master/filters/web_annoyances.txt
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
mitchellkrogza Hacked Malware Web Sites, https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt
abuse.ch URLHaus Malicious URL Blocklist, https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh-online.txt
PhishTank & OpenPhish Phishing URL Blocklist, https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt
Phishing Army Blocklist, https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt
CERT Polska Malicious & Phishing Domains, https://adguardteam.github.io/HostlistsRegistry/assets/filter_41.txt
PhishDestroy Content-Verified Active Phishing Blocklist, https://raw.githubusercontent.com/phishdestroy/destroylist/main/dns/content_active.txt
PhishIndex Malicious Domains, https://raw.githubusercontent.com/PhishIndex/phishindex-blocklist/main/Data/Malicious%20Domains/adblock/phishindex_domains-adblock.txt
PhishIndex IP Logger Domains, https://raw.githubusercontent.com/PhishIndex/phishindex-blocklist/main/Data/IP%20Logger%20Domains/ip_logger_domains-adblock.txt
The Block List Project Ransomware, https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/ransomware-ags.txt
The Block List Project Scam, https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/scam-ags.txt
zachlagden Custom Malicious Domains, https://raw.githubusercontent.com/zachlagden/Pi-hole-Optimized-Blocklists/main/custom/malicious.txt
```

</details>

<details>
<summary>去广告防误伤白名单数据源（共 60 项）</summary>

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
anudeepND Curated Domain Whitelist, https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt
SystemJargon DNS Allowlist, https://raw.githubusercontent.com/SystemJargon/filters/main/allowlist.txt
Ealenn AdGuard Home Service Allowlist, https://raw.githubusercontent.com/Ealenn/AdGuard-Home-List/master/allowlist/concat/allowlist.external.adguard.list
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
```

</details>

<details>
<summary>国内直连分流数据源（Direct.list）（共 36 项）</summary>

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
```

</details>

<details>
<summary>境外 AI、支付与风控数据源（AI.list）（共 39 项）</summary>

```text
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
```

</details>

<details>
<summary>境外代理与流媒体数据源（Proxy.list）（共 37 项）</summary>

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

<details>
<summary>GeoIP、ASN 与行政区划元数据数据源（共 111 项）</summary>

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
MaxMind GeoLite2 City / Country / ASN, https://github.com/Skiddle-ID/geoip2-mirror/releases/latest
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
