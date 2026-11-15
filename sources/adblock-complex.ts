import type { AdblockSourceEntry } from "./adblock-schema.ts";

/**
 * Specialized Surge modules, Quantumult X HTTP rewrites, and AdGuard CoreLibs / uBO
 * surgical URL/Header/Body/Parameter/Script transformation rules (`complex_first`).
 * Ordered by source authority so specialized app scripts win on single-script-per-request rules.
 */
export const ADBLOCK_COMPLEX_SOURCES: readonly AdblockSourceEntry[] = [
  {
    id: "app2smile_youtube",
    name: "app2smile YouTube Adblock Module",
    role: "complex_first",
    format: "surge_module",
    platform: "universal",
    lineage: "app2smile_rules",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/app2smile/rules/master/module/youtube.sgmodule",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/app2smile/rules@master/module/youtube.sgmodule",
      },
    ],
  },
  {
    id: "walvez_startup_ads",
    name: "Walvez Surge StartUp Ads Module",
    role: "complex_first",
    format: "surge_module",
    platform: "mobile",
    lineage: "walvez_startup_ads",
    weight: 95,
    core: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/Walvez/surge-startup-ads/main/dist/StartUpAds_Selected.sgmodule",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/Walvez/surge-startup-ads@main/dist/StartUpAds_Selected.sgmodule",
      },
    ],
  },
  {
    id: "app2smile_spotify",
    name: "app2smile Spotify Adblock Module",
    role: "complex_first",
    format: "surge_module",
    platform: "universal",
    lineage: "app2smile_rules",
    weight: 94,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/app2smile/rules/master/module/spotify.module",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/app2smile/rules@master/module/spotify.module",
      },
    ],
  },
  {
    id: "app2smile_zhihu",
    name: "app2smile Zhihu Adblock Module",
    role: "complex_first",
    format: "surge_module",
    platform: "universal",
    lineage: "app2smile_rules",
    weight: 94,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/app2smile/rules/master/module/zhihu.sgmodule",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/app2smile/rules@master/module/zhihu.sgmodule",
      },
    ],
  },
  {
    id: "app2smile_tieba",
    name: "app2smile Baidu Tieba Adblock Module",
    role: "complex_first",
    format: "surge_module",
    platform: "mobile",
    lineage: "app2smile_rules",
    weight: 94,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/app2smile/rules/master/module/tieba.sgmodule",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/app2smile/rules@master/module/tieba.sgmodule",
      },
    ],
  },
  {
    id: "app2smile_baidumap",
    name: "app2smile Baidu Map Adblock Module",
    role: "complex_first",
    format: "surge_module",
    platform: "mobile",
    lineage: "app2smile_rules",
    weight: 93,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/app2smile/rules/master/module/baidumap.sgmodule",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/app2smile/rules@master/module/baidumap.sgmodule",
      },
    ],
  },
  {
    id: "app2smile_qidian",
    name: "app2smile Qidian Reader Adblock Module",
    role: "complex_first",
    format: "surge_module",
    platform: "mobile",
    lineage: "app2smile_rules",
    weight: 93,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/app2smile/rules/master/module/qidian.sgmodule",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/app2smile/rules@master/module/qidian.sgmodule",
      },
    ],
  },
  {
    id: "ddgksf_weibo_ads",
    name: "ddgksf2013 Weibo Adblock Rewrite",
    role: "complex_first",
    format: "qx_rewrite",
    platform: "universal",
    lineage: "ddgksf2013_rewrite",
    weight: 94,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/WeiboAds.conf",
      },
    ],
  },
  {
    id: "ddgksf_amap_ads",
    name: "ddgksf2013 Amap Adblock Rewrite",
    role: "complex_first",
    format: "qx_rewrite",
    platform: "mobile",
    lineage: "ddgksf2013_rewrite",
    weight: 93,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/AmapAds.conf",
      },
    ],
  },
  {
    id: "adguard_url_tracking",
    name: "AdGuard URL Tracking Protection Filter (CoreLibs)",
    role: "complex_first",
    format: "abp_filter",
    platform: "universal",
    lineage: "adguard_filters",
    weight: 93,
    core: true,
    extractComplexNetworkRules: true,
    extractFallbackDomainRules: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://filters.adtidy.org/windows/filters/17.txt",
      },
    ],
  },
  {
    id: "ubo_privacy_removeparam",
    name: "uBlock Origin Privacy Query Parameter Stripping ($removeparam)",
    role: "complex_first",
    format: "abp_filter",
    platform: "universal",
    lineage: "ubo_uassets",
    weight: 93,
    core: true,
    extractComplexNetworkRules: true,
    extractFallbackDomainRules: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy-removeparam.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/uBlockOrigin/uAssets@master/filters/privacy-removeparam.txt",
      },
    ],
  },
  {
    id: "adguard_spyware_general_extensions",
    name: "AdGuard Spyware Filter General Extensions ($removeparam / $removeheader)",
    role: "complex_first",
    format: "abp_filter",
    platform: "universal",
    lineage: "adguard_filters",
    weight: 92,
    core: false,
    extractComplexNetworkRules: true,
    extractFallbackDomainRules: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/general_extensions.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters@master/SpywareFilter/sections/general_extensions.txt",
      },
    ],
  },
  {
    id: "adguard_dandelion_shorteners",
    name: "AdGuard Legitimate URL Shortener Filter ($removeparam Pre-Compiled)",
    role: "complex_first",
    format: "abp_filter",
    platform: "universal",
    lineage: "dandelion_adfilt",
    weight: 92,
    core: false,
    extractComplexNetworkRules: true,
    extractFallbackDomainRules: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_251_LegitimateURLShortener/filter.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/FiltersRegistry@master/filters/ThirdParty/filter_251_LegitimateURLShortener/filter.txt",
      },
    ],
  },
  {
    id: "dandelion_clearurls_ubo",
    name: "Dandelion Sprout ClearURLs ($removeparam)",
    role: "complex_first",
    format: "abp_filter",
    platform: "universal",
    lineage: "dandelion_adfilt",
    weight: 91,
    core: false,
    extractComplexNetworkRules: true,
    extractFallbackDomainRules: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/ClearURLs%20for%20uBo/clear_urls_uboified.txt",
      },
    ],
  },
  {
    id: "adguard_dandelion_annoyances",
    name: "AdGuard Dandelion Sprout Annoyances ($removeparam Pre-Compiled)",
    role: "complex_first",
    format: "abp_filter",
    platform: "universal",
    lineage: "dandelion_adfilt",
    weight: 91,
    core: false,
    extractComplexNetworkRules: true,
    extractFallbackDomainRules: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_250_DandelionSproutAnnoyances/filter.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/FiltersRegistry@master/filters/ThirdParty/filter_250_DandelionSproutAnnoyances/filter.txt",
      },
    ],
  },
  {
    id: "ruadlist_cntblock",
    name: "RU AdList Counter & Parameter Block ($removeparam)",
    role: "complex_first",
    format: "abp_filter",
    platform: "universal",
    lineage: "easylist_official",
    weight: 89,
    core: false,
    extractComplexNetworkRules: true,
    extractFallbackDomainRules: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/easylist/ruadlist/master/cntblock.txt",
      },
      {
        kind: "direct",
        url: "https://easylist-downloads.adblockplus.org/cntblock.txt",
      },
    ],
  },
  {
    id: "app2smile_qqnews",
    name: "app2smile Tencent News Adblock Module",
    role: "complex_first",
    format: "surge_module",
    platform: "mobile",
    lineage: "app2smile_rules",
    weight: 92,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/app2smile/rules/master/module/qqnews.sgmodule",
      },
    ],
  },
  {
    id: "maasea_keep_ads",
    name: "Maasea Keep Adblock Module",
    role: "complex_first",
    format: "surge_module",
    platform: "mobile",
    lineage: "maasea_sgmodule",
    weight: 92,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/Maasea/sgmodule/master/KeepAds.sgmodule",
      },
    ],
  },
  {
    id: "app2smile_adsense",
    name: "app2smile Google AdSense Module",
    role: "complex_first",
    format: "surge_module",
    platform: "universal",
    lineage: "app2smile_rules",
    weight: 91,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/app2smile/rules/master/module/adsense.sgmodule",
      },
    ],
  },
  {
    id: "fmz200_x_web_ads",
    name: "fmz200 X (Twitter) Web Adblock Module",
    role: "complex_first",
    format: "surge_module",
    platform: "universal",
    lineage: "fmz200_wool_scripts",
    weight: 91,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/fmz200/wool_scripts/main/Surge/module/XWebAds.module",
      },
    ],
  },
  {
    id: "ddgksf_ximalaya_ads",
    name: "ddgksf2013 Ximalaya Adblock Rewrite",
    role: "complex_first",
    format: "qx_rewrite",
    platform: "mobile",
    lineage: "ddgksf2013_rewrite",
    weight: 91,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/Ximalaya.conf",
      },
    ],
  },
  {
    id: "ddgksf_cainiao_ads",
    name: "ddgksf2013 Cainiao Adblock Rewrite",
    role: "complex_first",
    format: "qx_rewrite",
    platform: "mobile",
    lineage: "ddgksf2013_rewrite",
    weight: 91,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/CainiaoAds.conf",
      },
    ],
  },
  {
    id: "ddgksf_smzdm_ads",
    name: "ddgksf2013 SMZDM Adblock Rewrite",
    role: "complex_first",
    format: "qx_rewrite",
    platform: "mobile",
    lineage: "ddgksf2013_rewrite",
    weight: 91,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/SmzdmAds.conf",
      },
    ],
  },
  {
    id: "ddgksf_goofish_ads",
    name: "ddgksf2013 Goofish (Xianyu) Adblock Rewrite",
    role: "complex_first",
    format: "qx_rewrite",
    platform: "mobile",
    lineage: "ddgksf2013_rewrite",
    weight: 91,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/GoofishAds.conf",
      },
    ],
  },
  {
    id: "ddgksf_wechat_ads",
    name: "ddgksf2013 WeChat Official Account Adblock Rewrite",
    role: "complex_first",
    format: "qx_rewrite",
    platform: "mobile",
    lineage: "ddgksf2013_rewrite",
    weight: 91,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/WeChat.conf",
      },
    ],
  },
  {
    id: "ddgksf_netease_ads",
    name: "ddgksf2013 NetEase Cloud Music Adblock Rewrite",
    role: "complex_first",
    format: "qx_rewrite",
    platform: "mobile",
    lineage: "ddgksf2013_rewrite",
    weight: 90,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/NeteaseAds.conf",
      },
    ],
  },
  {
    id: "ddgksf_qishui_ads",
    name: "ddgksf2013 Soda Music (QiShui) Adblock Rewrite",
    role: "complex_first",
    format: "qx_rewrite",
    platform: "mobile",
    lineage: "ddgksf2013_rewrite",
    weight: 90,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/QiShuiMusicAds.conf",
      },
    ],
  },
  {
    id: "ddgksf_xiaoyuzhou_ads",
    name: "ddgksf2013 Xiaoyuzhou Podcast Adblock Rewrite",
    role: "complex_first",
    format: "qx_rewrite",
    platform: "mobile",
    lineage: "ddgksf2013_rewrite",
    weight: 90,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/XiaoYuZhouAds.conf",
      },
    ],
  },
  {
    id: "ddgksf_caiyun_ads",
    name: "ddgksf2013 ColorfulClouds Weather Adblock Rewrite",
    role: "complex_first",
    format: "qx_rewrite",
    platform: "mobile",
    lineage: "ddgksf2013_rewrite",
    weight: 90,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/CaiYunAds.conf",
      },
    ],
  },
  {
    id: "ddgksf_reddit_ads",
    name: "ddgksf2013 Reddit Adblock Rewrite",
    role: "complex_first",
    format: "qx_rewrite",
    platform: "universal",
    lineage: "ddgksf2013_rewrite",
    weight: 90,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/RedditAds.conf",
      },
    ],
  },
  {
    id: "qingrex_httpdns_block",
    name: "QingRex HTTPDNS Block Module",
    role: "complex_first",
    format: "surge_module",
    platform: "universal",
    lineage: "qingrex_loon_kiss_surge",
    weight: 90,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/QingRex/LoonKissSurge/main/Surge/Beta/%E6%8B%A6%E6%88%AAHTTPDNS.beta.sgmodule",
      },
    ],
  },
  {
    id: "ddgksf_applet_ads",
    name: "ddgksf2013 WeChat Mini-Program Adblock Rewrite",
    role: "complex_first",
    format: "qx_rewrite",
    platform: "mobile",
    lineage: "ddgksf2013_rewrite",
    weight: 89,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/Applet.conf",
      },
    ],
  },
  {
    id: "repcz_kelee_remove_ads",
    name: "Repcz / Kelee General Adblock Surge Module",
    role: "complex_first",
    format: "surge_module",
    platform: "mobile",
    lineage: "repcz_tool",
    weight: 88,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Module/Kelee/Remove_ads_by_keli.sgmodule",
      },
    ],
  },
  {
    id: "repcz_kelee_wx_mini",
    name: "Repcz / Kelee WeChat Mini-Programs Adblock Module",
    role: "complex_first",
    format: "surge_module",
    platform: "mobile",
    lineage: "repcz_tool",
    weight: 88,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Module/Kelee/WexinMiniPrograms_Remove_ads.sgmodule",
      },
    ],
  },
  {
    id: "repcz_kelee_block_advertisers",
    name: "Repcz / Kelee Mobile Ad SDKs Module",
    role: "complex_first",
    format: "surge_module",
    platform: "mobile",
    lineage: "repcz_tool",
    weight: 88,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Module/Kelee/BlockAdvertisers.sgmodule",
      },
    ],
  },
  {
    id: "aioneas_qqzone_adblock",
    name: "Aioneas Qzone Adblock Module",
    role: "complex_first",
    format: "surge_module",
    platform: "mobile",
    lineage: "aioneas_surge",
    weight: 87,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/Aioneas/Surge/main/Module/qqzone.adblock.aioneas.sgmodule",
      },
    ],
  },
  {
    id: "zirawell_rstore_all_adblock",
    name: "zirawell R-Store All-in-One Surge Adblock Module",
    role: "complex_first",
    format: "surge_module",
    platform: "mobile",
    lineage: "zirawell_rstore",
    weight: 86,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/zirawell/R-Store/main/Rule/Surge/Adblock/All/allAdBlock.sgmodule",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/zirawell/R-Store@main/Rule/Surge/Adblock/All/allAdBlock.sgmodule",
      },
    ],
  },
  {
    id: "fmz200_blockads_module",
    name: "fmz200 Wool Scripts BlockAds Module",
    role: "complex_first",
    format: "surge_module",
    platform: "mobile",
    lineage: "fmz200_wool_scripts",
    weight: 85,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/fmz200/wool_scripts/main/Surge/module/blockAds.module",
      },
    ],
  },
];
