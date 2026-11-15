import type { AdblockSourceEntry } from "./adblock-schema.ts";

/**
 * Specialized Surge modules, Quantumult X HTTP rewrites, and complex URL-tracking rules.
 * Ordered by source authority so specialized app scripts win on single-script-per-request rules.
 */
export const ADBLOCK_COMPLEX_SOURCES: readonly AdblockSourceEntry[] = [
  {
    id: "biliverse_bilibili_adblock",
    role: "complex_first",
    format: "surge_module",
    platform: "universal",
    lineage: "biliverse_adblock",
    weight: 97,
    core: false,
    endpoints: [
      {
        kind: "github_release",
        repo: "Biliverse/ADBlock",
        assetPattern: "^BiliBili\\.ADBlock\\.sgmodule$",
      },
      {
        kind: "direct",
        url: "https://github.com/Biliverse/ADBlock/releases/latest/download/BiliBili.ADBlock.sgmodule",
      },
    ],
  },
  {
    id: "app2smile_youtube",
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
    ],
  },
  {
    id: "app2smile_zhihu",
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
    ],
  },
  {
    id: "app2smile_tieba",
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
    ],
  },
  {
    id: "ddgksf_weibo_ads",
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
    role: "complex_first",
    format: "abp_filter",
    platform: "universal",
    lineage: "adguard_filters",
    weight: 93,
    core: false,
    extractComplexNetworkRules: true,
    extractFallbackDomainRules: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://filters.adtidy.org/extension/ublock/filters/17.txt",
      },
    ],
  },
  {
    id: "app2smile_qqnews",
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
    id: "ddgksf_xiaohongshu_ads",
    role: "complex_first",
    format: "surge_module",
    platform: "mobile",
    lineage: "ddgksf2013_rewrite",
    weight: 92,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/ifflagged/Romeo/main/Modules/Surge/ddgksf2013/XiaoHongShuAds.sgmodule",
      },
    ],
  },
  {
    id: "app2smile_adsense",
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
    id: "ddgksf_ximalaya_ads",
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
    id: "qingrex_httpdns_block",
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
    id: "fmz200_blockads_module",
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
