import type { AdblockSourceEntry } from "./adblock-schema.ts";

/**
 * Upstream unbreak and false-positive allowlists evaluated before fallback host blocking.
 */
export const ADBLOCK_ALLOWLIST_SOURCES: readonly AdblockSourceEntry[] = [
  {
    id: "ubo_unbreak",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "ubo_uassets",
    weight: 98,
    core: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/uBlockOrigin/uAssets@master/filters/unbreak.txt",
      },
    ],
  },
  {
    id: "ubo_quick_fixes",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "ubo_uassets",
    weight: 95,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/quick-fixes.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/uBlockOrigin/uAssets@master/filters/quick-fixes.txt",
      },
    ],
  },
  {
    id: "loyalsoldier_reject_remove",
    role: "allowlist",
    format: "domain_list",
    platform: "universal",
    lineage: "loyalsoldier_v2ray",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/hidden/reject-need-to-remove.txt",
      },
    ],
  },
];
