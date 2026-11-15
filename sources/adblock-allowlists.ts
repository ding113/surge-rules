import type { AdblockSourceEntry } from "./adblock-schema.ts";

/**
 * Upstream unbreak, false-positive, and functional service allowlists (Tier P1)
 * evaluated above all upstream blocklists (Tier P3) and beneath human overrides (Tier P0a/P0b).
 */
export const ADBLOCK_ALLOWLIST_SOURCES: readonly AdblockSourceEntry[] = [
  // Official Adblock Engine Unbreak & Exception Lists
  {
    id: "ubo_unbreak",
    name: "uBlock Origin Unbreak Allowlist",
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
    name: "uBlock Origin Quick Fixes",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "ubo_uassets",
    weight: 96,
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
    id: "brave_unbreak",
    name: "Brave Adblock Unbreak List",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "brave_adblock",
    weight: 97,
    core: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/brave/adblock-lists/master/brave-unbreak.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/brave/adblock-lists@master/brave-unbreak.txt",
      },
    ],
  },
  {
    id: "adguard_sdns_exceptions",
    name: "AdGuard DNS Filter Exceptions",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "adguard_dns",
    weight: 98,
    core: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exceptions.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/AdGuardSDNSFilter@master/Filters/exceptions.txt",
      },
    ],
  },
  {
    id: "adguard_sdns_exclusions",
    name: "AdGuard DNS Filter Exclusions",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "adguard_dns",
    weight: 98,
    core: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/AdGuardSDNSFilter@master/Filters/exclusions.txt",
      },
    ],
  },
  {
    id: "adguard_base_allowlist",
    name: "AdGuard Base Filter Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "adguard_filters",
    weight: 97,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters@master/BaseFilter/sections/allowlist.txt",
      },
    ],
  },
  {
    id: "adguard_spyware_allowlist",
    name: "AdGuard Tracking Protection Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "adguard_filters",
    weight: 97,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters@master/SpywareFilter/sections/allowlist.txt",
      },
    ],
  },
  {
    id: "adguard_chinese_allowlist",
    name: "AdGuard Chinese Filter Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "adguard_filters",
    weight: 97,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters@master/ChineseFilter/sections/allowlist.txt",
      },
    ],
  },

  // Chinese & East Asian False-Positive Whitelists
  {
    id: "loyalsoldier_reject_remove",
    name: "Loyalsoldier Reject False-Positive Removals",
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
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@hidden/reject-need-to-remove.txt",
      },
    ],
  },
  {
    id: "goodbyeads_allow",
    name: "8680 GOODBYEADS Allow Rules",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "goodbyeads",
    weight: 95,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/allow.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/8680/GOODBYEADS@master/data/rules/allow.txt",
      },
    ],
  },
  {
    id: "goodbyeads_mod_whitelist",
    name: "8680 GOODBYEADS Curated Mod Whitelist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "goodbyeads",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/mod/whitelist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/8680/GOODBYEADS@master/data/mod/whitelist.txt",
      },
    ],
  },
  {
    id: "cats_dns_allowlist",
    name: "Cats-Team AdRules DNS Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "cats_adrules",
    weight: 95,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/Cats-Team/AdRules/main/mod/rules/dns-allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/Cats-Team/AdRules@main/mod/rules/dns-allowlist.txt",
      },
    ],
  },
  {
    id: "cats_adblock_need_remove",
    name: "Cats-Team AdRules False-Positive Removals",
    role: "allowlist",
    format: "domain_list",
    platform: "universal",
    lineage: "cats_adrules",
    weight: 95,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/Cats-Team/AdRules/main/mod/rules/adblock-need-remove.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/Cats-Team/AdRules@main/mod/rules/adblock-need-remove.txt",
      },
    ],
  },
  {
    id: "ad_filter_045200_whitelist",
    name: "045200 ad-filter Curated Mod Whitelist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "ad_filter_045200",
    weight: 94,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/045200/ad-filter/multi/data/mod/whitelist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/045200/ad-filter@multi/data/mod/whitelist.txt",
      },
    ],
  },
  {
    id: "yuki2718_jp_dns_unbreak",
    name: "Yuki2718 Japanese DNS Unbreak",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "yuki2718_adblock2",
    weight: 93,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/Yuki2718/adblock2/main/japanese/dns-unbreak.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/Yuki2718/adblock2@main/japanese/dns-unbreak.txt",
      },
    ],
  },

  // Global DNS, Shortener, System & Functional Service Whitelists
  {
    id: "hagezi_urlshortener_allow",
    name: "HaGeZi Legitimate URL Shortener Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "hagezi_dns",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-urlshortener.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@main/adblock/whitelist-urlshortener.txt",
      },
    ],
  },
  {
    id: "hagezi_spamtlds_allow",
    name: "HaGeZi Abused TLDs Legitimate Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "hagezi_dns",
    weight: 95,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock-allow.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@main/adblock/spam-tlds-adblock-allow.txt",
      },
    ],
  },
  {
    id: "dandelion_legitimate_shorteners",
    name: "Dandelion Sprout Legitimate URL Shorteners",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "dandelion_adfilt",
    weight: 95,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LegitimateURLShortener.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/DandelionSprout/adfilt@master/LegitimateURLShortener.txt",
      },
    ],
  },
  {
    id: "anudeep_whitelist",
    name: "anudeepND Curated Domain Whitelist",
    role: "allowlist",
    format: "domain_list",
    platform: "universal",
    lineage: "anudeep_whitelist",
    weight: 95,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/anudeepND/whitelist@master/domains/whitelist.txt",
      },
    ],
  },
  {
    id: "pihole_optimized_whitelist",
    name: "zachlagden Pi-hole Optimized Whitelist",
    role: "allowlist",
    format: "domain_list",
    platform: "universal",
    lineage: "zachlagden_pihole",
    weight: 94,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/zachlagden/Pi-hole-Optimized-Blocklists/main/whitelist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/zachlagden/Pi-hole-Optimized-Blocklists@main/whitelist.txt",
      },
    ],
  },
  {
    id: "systemjargon_allowlist",
    name: "SystemJargon DNS Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "systemjargon",
    weight: 93,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/SystemJargon/filters/main/allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/SystemJargon/filters@main/allowlist.txt",
      },
    ],
  },
  {
    id: "ealenn_adguard_allowlist",
    name: "Ealenn AdGuard Home Service Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "ealenn_agh",
    weight: 93,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/Ealenn/AdGuard-Home-List/master/allowlist/concat/allowlist.external.adguard.list",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/Ealenn/AdGuard-Home-List@master/allowlist/concat/allowlist.external.adguard.list",
      },
    ],
  },

  // celenityy BadBlock Functional Infrastructure Whitelists (excluding click-tracking allowlist)
  {
    id: "badblock_apple_whitelist",
    name: "BadBlock Apple Services Whitelist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "celenityy_badblock",
    weight: 95,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/apple_whitelist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/celenityy/BadBlock@pages/abp/apple_whitelist.txt",
      },
    ],
  },
  {
    id: "badblock_browser_whitelist",
    name: "BadBlock Browser Services Whitelist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "celenityy_badblock",
    weight: 95,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/browser_whitelist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/celenityy/BadBlock@pages/abp/browser_whitelist.txt",
      },
    ],
  },
  {
    id: "badblock_captcha_whitelist",
    name: "BadBlock CAPTCHA Verification Whitelist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "celenityy_badblock",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/captcha_whitelist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/celenityy/BadBlock@pages/abp/captcha_whitelist.txt",
      },
    ],
  },
  {
    id: "badblock_captive_whitelist",
    name: "BadBlock Captive Portal Whitelist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "celenityy_badblock",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/captive_whitelist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/celenityy/BadBlock@pages/abp/captive_whitelist.txt",
      },
    ],
  },
  {
    id: "badblock_certs_whitelist",
    name: "BadBlock PKI / OCSP / CRL Whitelist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "celenityy_badblock",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/certs_whitelist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/celenityy/BadBlock@pages/abp/certs_whitelist.txt",
      },
    ],
  },
  {
    id: "badblock_content_blocking_whitelist",
    name: "BadBlock Filter Update Mirrors Whitelist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "celenityy_badblock",
    weight: 95,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/content-blocking_whitelist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/celenityy/BadBlock@pages/abp/content-blocking_whitelist.txt",
      },
    ],
  },
  {
    id: "badblock_emergency_whitelist",
    name: "BadBlock Emergency Alert Services Whitelist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "celenityy_badblock",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/emergency_whitelist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/celenityy/BadBlock@pages/abp/emergency_whitelist.txt",
      },
    ],
  },
  {
    id: "badblock_lan_whitelist",
    name: "BadBlock Local Network Discovery Whitelist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "celenityy_badblock",
    weight: 95,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/lan_whitelist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/celenityy/BadBlock@pages/abp/lan_whitelist.txt",
      },
    ],
  },
  {
    id: "badblock_microsoft_whitelist",
    name: "BadBlock Microsoft Services Whitelist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "celenityy_badblock",
    weight: 95,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/microsoft_whitelist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/celenityy/BadBlock@pages/abp/microsoft_whitelist.txt",
      },
    ],
  },
  {
    id: "badblock_mobile_whitelist",
    name: "BadBlock Mobile App Infrastructure Whitelist",
    role: "allowlist",
    format: "abp_filter",
    platform: "mobile",
    lineage: "celenityy_badblock",
    weight: 94,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/mobile_whitelist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/celenityy/BadBlock@pages/abp/mobile_whitelist.txt",
      },
    ],
  },
  {
    id: "badblock_mozilla_whitelist",
    name: "BadBlock Mozilla Firefox Whitelist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "celenityy_badblock",
    weight: 95,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/mozilla_whitelist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/celenityy/BadBlock@pages/abp/mozilla_whitelist.txt",
      },
    ],
  },
  {
    id: "badblock_push_whitelist",
    name: "BadBlock Push Notification Services Whitelist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "celenityy_badblock",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/push_whitelist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/celenityy/BadBlock@pages/abp/push_whitelist.txt",
      },
    ],
  },
  {
    id: "badblock_safebrowsing_whitelist",
    name: "BadBlock Safe Browsing Whitelist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "celenityy_badblock",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/safe-browsing_whitelist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/celenityy/BadBlock@pages/abp/safe-browsing_whitelist.txt",
      },
    ],
  },
  {
    id: "badblock_time_whitelist",
    name: "BadBlock NTP Time Sync Whitelist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "celenityy_badblock",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/time_whitelist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/celenityy/BadBlock@pages/abp/time_whitelist.txt",
      },
    ],
  },
];
