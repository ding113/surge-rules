import type { ForceRuleSetEntry } from "./adblock-schema.ts";

/**
 * Curated Surge RULE-SET entries covering desktop macOS adware processes,
 * plain HTTP ad SDK user agents, and unambiguous ad/tracking infrastructure.
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

  // High-confidence tracking/ad domain guarantees
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
    kind: "DOMAIN",
    value: "app-measurement.com",
    rationale: "Firebase mobile analytics & attribution collector",
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
];
