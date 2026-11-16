import type { ForceRuleSetEntry } from "./adblock-schema.ts";

/**
 * Curated Surge RULE-SET entries (Tier P0b) for `Adblock.list` covering desktop macOS adware
 * processes, plain HTTP mobile ad SDK user agents, and unambiguous pure-ad networks that must
 * never be accidentally unblocked by overly broad upstream allowlists (Tier P1).
 */
export const ADBLOCK_FORCE_RULESET_ENTRIES: readonly ForceRuleSetEntry[] = [
  // macOS desktop adware, bundlers & unwanted background updater daemons (ignored automatically on iOS)
  {
    target: "ad",
    kind: "PROCESS-NAME",
    value: "MacKeeper",
    rationale: "Known macOS scareware / adware helper",
  },
  {
    target: "ad",
    kind: "PROCESS-NAME",
    value: "MacAutoFixer",
    rationale: "Known macOS adware helper",
  },
  {
    target: "ad",
    kind: "PROCESS-NAME",
    value: "AdvancedMacCleaner",
    rationale: "Known macOS adware helper",
  },
  {
    target: "ad",
    kind: "PROCESS-NAME",
    value: "CleanupMyMac",
    rationale: "Known macOS PUAs / adware updater",
  },
  {
    target: "ad",
    kind: "PROCESS-NAME",
    value: "Genieo",
    rationale: "Known macOS browser-hijacking adware",
  },
  {
    target: "ad",
    kind: "PROCESS-NAME",
    value: "InstallMac",
    rationale: "Known macOS ad-bundling installer",
  },
  {
    target: "ad",
    kind: "PROCESS-NAME",
    value: "VSearch",
    rationale: "Known macOS ad injection daemon",
  },
  {
    target: "ad",
    kind: "PROCESS-NAME",
    value: "Conduit",
    rationale: "Known macOS toolbar / adware daemon",
  },
  {
    target: "ad",
    kind: "PROCESS-NAME",
    value: "Chrysaor",
    rationale: "Known unwanted ad/spyware threat process",
  },
  {
    target: "ad",
    kind: "PROCESS-NAME",
    value: "FlashHelperService",
    rationale: "Flash Center China background pop-up ad daemon",
  },
  {
    target: "ad",
    kind: "PROCESS-NAME",
    value: "FFFlashHelperService",
    rationale: "Flash helper background ad popup daemon",
  },
  {
    target: "ad",
    kind: "PROCESS-NAME",
    value: "WPSNotify",
    rationale: "WPS China background marketing popup helper",
  },
  {
    target: "ad",
    kind: "PROCESS-NAME",
    value: "2345PicMini",
    rationale: "2345 background ad news popup daemon",
  },
  {
    target: "ad",
    kind: "PROCESS-NAME",
    value: "MiniPage",
    rationale: "Third-party bundled ad mini-window helper",
  },

  // Plain-HTTP mobile ad SDK signatures
  {
    target: "ad",
    kind: "USER-AGENT",
    value: "Mintegral*",
    rationale: "Mintegral mobile ad SDK traffic",
  },
  {
    target: "ad",
    kind: "USER-AGENT",
    value: "Pangolin*",
    rationale: "Pangle / CSJ mobile ad SDK traffic",
  },
  {
    target: "ad",
    kind: "USER-AGENT",
    value: "GDTMobSDK*",
    rationale: "Tencent Youlianghui mobile ad SDK traffic",
  },
  {
    target: "ad",
    kind: "USER-AGENT",
    value: "KSAdSDK*",
    rationale: "Kuaishou mobile ad SDK traffic",
  },

  // High-confidence global & domestic pure-ad SDKs guaranteed against upstream allowlist leaks (Tier P0b)
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "doubleclick.net",
    rationale: "Google DoubleClick ad serving network",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "googlesyndication.com",
    rationale: "Google AdSense / syndication ad network",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "googleadservices.com",
    rationale: "Google Ads conversion & click-ad server",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "adservice.google.com",
    rationale: "Google AdService ad auction endpoint",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "adsrvr.org",
    rationale: "The Trade Desk programmatic ad network",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "adnxs.com",
    rationale: "Xandr / AppNexus programmatic ad exchange",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "criteo.com",
    rationale: "Criteo retargeting ad network",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "criteo.net",
    rationale: "Criteo retargeting ad delivery network",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "taboola.com",
    rationale: "Taboola sponsored content ad network",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "outbrain.com",
    rationale: "Outbrain sponsored content ad network",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "rubiconproject.com",
    rationale: "Magnite / Rubicon ad exchange",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "pubmatic.com",
    rationale: "PubMatic programmatic ad exchange",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "openx.net",
    rationale: "OpenX programmatic ad exchange",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "casalemedia.com",
    rationale: "Index Exchange ad network",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "adsafeprotected.com",
    rationale: "Integral Ad Science ad verification beacon",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "moatads.com",
    rationale: "Oracle Moat ad measurement beacon",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "unityads.unity3d.com",
    rationale: "Unity Ads mobile game ad SDK",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "applovin.com",
    rationale: "AppLovin mobile ad mediation SDK",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "applvn.com",
    rationale: "AppLovin mobile ad asset delivery",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "vungle.com",
    rationale: "Liftoff / Vungle mobile video ad SDK",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "inmobi.com",
    rationale: "InMobi mobile ad SDK",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "ironsrc.mobi",
    rationale: "ironSource mobile ad mediation SDK",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "chartboost.com",
    rationale: "Chartboost mobile game ad SDK",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "adcolony.com",
    rationale: "AdColony mobile video ad SDK",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "adkwai.com",
    rationale: "Kuaishou magnetic engine ad SDK",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "adukwai.com",
    rationale: "Kuaishou overseas ad SDK",
  },
  {
    target: "ad",
    kind: "DOMAIN",
    value: "e.kuaishou.com",
    rationale: "Kuaishou commercial ad attribution gateway",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "pangolin-sdk-toutiao.com",
    rationale: "ByteDance Pangle / CSJ mobile ad SDK",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "pangolin-sdk-toutiao-b.com",
    rationale: "ByteDance Pangle / CSJ mobile ad SDK backup",
  },
  {
    target: "ad",
    kind: "DOMAIN-SUFFIX",
    value: "pglstatp-toutiao.com",
    rationale: "ByteDance Pangle static ad creative CDN",
  },
  {
    target: "ad",
    kind: "DOMAIN",
    value: "mi.gdt.qq.com",
    rationale: "Tencent Youlianghui mobile ad SDK",
  },
  {
    target: "ad",
    kind: "DOMAIN",
    value: "win.gdt.qq.com",
    rationale: "Tencent Youlianghui ad auction win notice",
  },
  {
    target: "ad",
    kind: "DOMAIN",
    value: "v.gdt.qq.com",
    rationale: "Tencent Youlianghui video ad endpoint",
  },
  {
    target: "ad",
    kind: "DOMAIN",
    value: "c.gdt.qq.com",
    rationale: "Tencent Youlianghui click ad endpoint",
  },
  {
    target: "ad",
    kind: "DOMAIN",
    value: "adsmind.gdtimg.com",
    rationale: "Tencent splash and OTT video ad creative CDN",
  },
  {
    target: "ad",
    kind: "DOMAIN",
    value: "mobads.baidu.com",
    rationale: "Baidu mobile splash/feed ad server",
  },
  {
    target: "ad",
    kind: "DOMAIN",
    value: "pos.baidu.com",
    rationale: "Baidu ad slot placement endpoint",
  },
  {
    target: "ad",
    kind: "DOMAIN",
    value: "cpro.baidustatic.com",
    rationale: "Baidu Union ad script delivery",
  },
  {
    target: "ad",
    kind: "DOMAIN",
    value: "als.baidu.com",
    rationale: "Baidu mobile splash ad dispatch",
  },
];

/**
 * Curated Surge RULE-SET entries (Tier P0b) for `Privacy.list` covering unambiguous
 * pure-analytics and audience-measurement collectors that must never be accidentally
 * unblocked by overly broad upstream allowlists (Tier P1).
 */
export const PRIVACY_FORCE_RULESET_ENTRIES: readonly ForceRuleSetEntry[] = [
  {
    target: "privacy",
    kind: "DOMAIN",
    value: "app-measurement.com",
    rationale: "Firebase mobile analytics & attribution collector",
  },
  {
    target: "privacy",
    kind: "DOMAIN-SUFFIX",
    value: "scorecardresearch.com",
    rationale: "Comscore audience tracking beacon",
  },
  {
    target: "privacy",
    kind: "DOMAIN",
    value: "hm.baidu.com",
    rationale: "Baidu Tongji analytics beacon",
  },
];

export const FORCE_RULESET_ENTRIES: readonly ForceRuleSetEntry[] = [
  ...ADBLOCK_FORCE_RULESET_ENTRIES,
  ...PRIVACY_FORCE_RULESET_ENTRIES,
];
