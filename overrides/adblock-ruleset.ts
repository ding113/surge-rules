import type { ForceRuleSetEntry } from "./adblock-schema.ts";

/**
 * Curated Surge RULE-SET entries (Tier P0b) covering desktop macOS adware processes,
 * plain HTTP ad SDK user agents, and unambiguous pure-ad/attribution networks that must
 * never be accidentally unblocked by overly broad upstream allowlists (Tier P1).
 */
export const FORCE_RULESET_ENTRIES: readonly ForceRuleSetEntry[] = [
  // macOS desktop adware, bundlers & unwanted background updater daemons (ignored automatically on iOS)
  {
    kind: "PROCESS-NAME",
    value: "MacKeeper",
    rationale: "Known macOS scareware / adware helper",
  },
  {
    kind: "PROCESS-NAME",
    value: "MacAutoFixer",
    rationale: "Known macOS adware helper",
  },
  {
    kind: "PROCESS-NAME",
    value: "AdvancedMacCleaner",
    rationale: "Known macOS adware helper",
  },
  {
    kind: "PROCESS-NAME",
    value: "CleanupMyMac",
    rationale: "Known macOS PUAs / adware updater",
  },
  {
    kind: "PROCESS-NAME",
    value: "Genieo",
    rationale: "Known macOS browser-hijacking adware",
  },
  {
    kind: "PROCESS-NAME",
    value: "InstallMac",
    rationale: "Known macOS ad-bundling installer",
  },
  {
    kind: "PROCESS-NAME",
    value: "VSearch",
    rationale: "Known macOS ad injection daemon",
  },
  {
    kind: "PROCESS-NAME",
    value: "Conduit",
    rationale: "Known macOS toolbar / adware daemon",
  },
  {
    kind: "PROCESS-NAME",
    value: "Chrysaor",
    rationale: "Known unwanted ad/telemetry process",
  },
  {
    kind: "PROCESS-NAME",
    value: "FlashHelperService",
    rationale: "Flash Center China background pop-up ad daemon",
  },
  {
    kind: "PROCESS-NAME",
    value: "FFFlashHelperService",
    rationale: "Flash helper background ad popup daemon",
  },
  {
    kind: "PROCESS-NAME",
    value: "WPSNotify",
    rationale: "WPS China background marketing popup helper",
  },
  {
    kind: "PROCESS-NAME",
    value: "2345PicMini",
    rationale: "2345 background ad news popup daemon",
  },
  {
    kind: "PROCESS-NAME",
    value: "MiniPage",
    rationale: "Third-party bundled ad mini-window helper",
  },

  // Plain-HTTP mobile ad SDK signatures
  {
    kind: "USER-AGENT",
    value: "Mintegral*",
    rationale: "Mintegral mobile ad SDK traffic",
  },
  {
    kind: "USER-AGENT",
    value: "Pangolin*",
    rationale: "Pangle / CSJ mobile ad SDK traffic",
  },
  {
    kind: "USER-AGENT",
    value: "GDTMobSDK*",
    rationale: "Tencent Youlianghui mobile ad SDK traffic",
  },
  {
    kind: "USER-AGENT",
    value: "KSAdSDK*",
    rationale: "Kuaishou mobile ad SDK traffic",
  },

  // High-confidence global & domestic pure-ad SDKs guaranteed against upstream allowlist leaks (Tier P0b)
  {
    kind: "DOMAIN-SUFFIX",
    value: "doubleclick.net",
    rationale: "Google DoubleClick ad serving network",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "googlesyndication.com",
    rationale: "Google AdSense / syndication ad network",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "googleadservices.com",
    rationale: "Google Ads conversion & click-ad server",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "adservice.google.com",
    rationale: "Google AdService ad auction endpoint",
  },
  {
    kind: "DOMAIN",
    value: "app-measurement.com",
    rationale: "Firebase mobile analytics & attribution collector",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "adsrvr.org",
    rationale: "The Trade Desk programmatic ad network",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "adnxs.com",
    rationale: "Xandr / AppNexus programmatic ad exchange",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "criteo.com",
    rationale: "Criteo retargeting ad network",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "criteo.net",
    rationale: "Criteo retargeting ad delivery network",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "taboola.com",
    rationale: "Taboola sponsored content ad network",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "outbrain.com",
    rationale: "Outbrain sponsored content ad network",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "rubiconproject.com",
    rationale: "Magnite / Rubicon ad exchange",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "pubmatic.com",
    rationale: "PubMatic programmatic ad exchange",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "openx.net",
    rationale: "OpenX programmatic ad exchange",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "casalemedia.com",
    rationale: "Index Exchange ad network",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "adsafeprotected.com",
    rationale: "Integral Ad Science ad verification beacon",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "moatads.com",
    rationale: "Oracle Moat ad measurement beacon",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "scorecardresearch.com",
    rationale: "Comscore audience tracking beacon",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "unityads.unity3d.com",
    rationale: "Unity Ads mobile game ad SDK",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "applovin.com",
    rationale: "AppLovin mobile ad mediation SDK",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "applvn.com",
    rationale: "AppLovin mobile ad asset delivery",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "vungle.com",
    rationale: "Liftoff / Vungle mobile video ad SDK",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "inmobi.com",
    rationale: "InMobi mobile ad SDK",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "ironsrc.mobi",
    rationale: "ironSource mobile ad mediation SDK",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "chartboost.com",
    rationale: "Chartboost mobile game ad SDK",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "adcolony.com",
    rationale: "AdColony mobile video ad SDK",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "adkwai.com",
    rationale: "Kuaishou magnetic engine ad SDK",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "adukwai.com",
    rationale: "Kuaishou overseas ad SDK",
  },
  {
    kind: "DOMAIN",
    value: "e.kuaishou.com",
    rationale: "Kuaishou commercial ad attribution gateway",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "pangolin-sdk-toutiao.com",
    rationale: "ByteDance Pangle / CSJ mobile ad SDK",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "pangolin-sdk-toutiao-b.com",
    rationale: "ByteDance Pangle / CSJ mobile ad SDK backup",
  },
  {
    kind: "DOMAIN-SUFFIX",
    value: "pglstatp-toutiao.com",
    rationale: "ByteDance Pangle static ad creative CDN",
  },
  {
    kind: "DOMAIN",
    value: "mi.gdt.qq.com",
    rationale: "Tencent Youlianghui mobile ad SDK",
  },
  {
    kind: "DOMAIN",
    value: "win.gdt.qq.com",
    rationale: "Tencent Youlianghui ad auction win notice",
  },
  {
    kind: "DOMAIN",
    value: "v.gdt.qq.com",
    rationale: "Tencent Youlianghui video ad endpoint",
  },
  {
    kind: "DOMAIN",
    value: "c.gdt.qq.com",
    rationale: "Tencent Youlianghui click ad endpoint",
  },
  {
    kind: "DOMAIN",
    value: "adsmind.gdtimg.com",
    rationale: "Tencent splash and OTT video ad creative CDN",
  },
  {
    kind: "DOMAIN",
    value: "mobads.baidu.com",
    rationale: "Baidu mobile splash/feed ad server",
  },
  {
    kind: "DOMAIN",
    value: "pos.baidu.com",
    rationale: "Baidu ad slot placement endpoint",
  },
  {
    kind: "DOMAIN",
    value: "cpro.baidustatic.com",
    rationale: "Baidu Union ad script delivery",
  },
  {
    kind: "DOMAIN",
    value: "hm.baidu.com",
    rationale: "Baidu Tongji analytics beacon",
  },
  {
    kind: "DOMAIN",
    value: "als.baidu.com",
    rationale: "Baidu mobile splash ad dispatch",
  },
];
