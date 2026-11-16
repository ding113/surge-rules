import type { AdblockSourceEntry } from "./adblock-schema.ts";

/**
 * Upstream unbreak, false-positive, and functional service allowlists (Tier P1)
 * evaluated above all upstream blocklists (Tier P3) and beneath human overrides (Tier P0a/P0b).
 */
export const ADBLOCK_ALLOWLIST_SOURCES: readonly AdblockSourceEntry[] = [
  // Official Adblock Engine Unbreak & Exception Lists (ranked by authority & 2026-11 file freshness)
  {
    id: "ubo_unbreak",
    name: "uBlock Origin Unbreak Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "ubo_uassets",
    weight: 99,
    core: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://ublockorigin.github.io/uAssetsCDN/filters/unbreak.min.txt",
      },
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt",
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
    weight: 97,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://ublockorigin.github.io/uAssetsCDN/filters/quick-fixes.min.txt",
      },
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/quick-fixes.txt",
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
    weight: 99,
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
    weight: 98,
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
    id: "adguard_stealth_allowlist",
    name: "AdGuard Base Stealth Protection Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "adguard_filters",
    weight: 97,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/allowlist_stealth.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters@master/BaseFilter/sections/allowlist_stealth.txt",
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
    weight: 98,
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
    id: "adguard_spyware_mobile_allowlist",
    name: "AdGuard Mobile Tracking Protection Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "mobile",
    lineage: "adguard_filters",
    weight: 98,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile_allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters@master/SpywareFilter/sections/mobile_allowlist.txt",
      },
    ],
  },
  {
    id: "adguard_trackparam_allowlist",
    name: "AdGuard URL Tracking Protection Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "adguard_filters",
    weight: 98,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/TrackParamFilter/sections/allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters@master/TrackParamFilter/sections/allowlist.txt",
      },
    ],
  },
  {
    id: "adguard_mobile_app_allowlist",
    name: "AdGuard Mobile Ads App Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "mobile",
    lineage: "adguard_filters",
    weight: 98,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/allowlist_app.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters@master/MobileFilter/sections/allowlist_app.txt",
      },
    ],
  },
  {
    id: "adguard_mobile_web_allowlist",
    name: "AdGuard Mobile Ads Web Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "mobile",
    lineage: "adguard_filters",
    weight: 98,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/allowlist_web.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters@master/MobileFilter/sections/allowlist_web.txt",
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
    weight: 98,
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
  {
    id: "adguard_social_allowlist",
    name: "AdGuard Social Media Filter Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "adguard_filters",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters@master/SocialFilter/sections/allowlist.txt",
      },
    ],
  },
  {
    id: "adguard_cookies_allowlist",
    name: "AdGuard Cookie Notices Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "adguard_filters",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters@master/AnnoyancesFilter/Cookies/sections/cookies_allowlist.txt",
      },
    ],
  },
  {
    id: "adguard_spyware_cookies_allowlist",
    name: "AdGuard Tracking Protection Cookies Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "adguard_filters",
    weight: 97,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/cookies_allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters@master/SpywareFilter/sections/cookies_allowlist.txt",
      },
    ],
  },
  {
    id: "adguard_japanese_allowlist",
    name: "AdGuard Japanese Filter Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "adguard_filters",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/JapaneseFilter/sections/allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters@master/JapaneseFilter/sections/allowlist.txt",
      },
    ],
  },
  {
    id: "adguard_german_allowlist",
    name: "AdGuard German Filter Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "adguard_filters",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/GermanFilter/sections/allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters@master/GermanFilter/sections/allowlist.txt",
      },
    ],
  },
  {
    id: "adguard_french_allowlist",
    name: "AdGuard French Filter Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "adguard_filters",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/FrenchFilter/sections/allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters@master/FrenchFilter/sections/allowlist.txt",
      },
    ],
  },
  {
    id: "adguard_russian_allowlist",
    name: "AdGuard Russian Filter Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "adguard_filters",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/CyrillicFilters/RussianFilter/sections/allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters@master/CyrillicFilters/RussianFilter/sections/allowlist.txt",
      },
    ],
  },
  {
    id: "adguard_spanish_allowlist",
    name: "AdGuard Spanish/Portuguese Filter Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "adguard_filters",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpanishFilter/sections/allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters@master/SpanishFilter/sections/allowlist.txt",
      },
    ],
  },
  {
    id: "adguard_turkish_allowlist",
    name: "AdGuard Turkish Filter Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "adguard_filters",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/TurkishFilter/sections/allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters@master/TurkishFilter/sections/allowlist.txt",
      },
    ],
  },
  {
    id: "adguard_dutch_allowlist",
    name: "AdGuard Dutch Filter Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "adguard_filters",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/DutchFilter/sections/allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters@master/DutchFilter/sections/allowlist.txt",
      },
    ],
  },
  {
    id: "adguard_ukrainian_allowlist",
    name: "AdGuard Ukrainian Filter Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "adguard_filters",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/CyrillicFilters/UkrainianFilter/sections/allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters@master/CyrillicFilters/UkrainianFilter/sections/allowlist.txt",
      },
    ],
  },
  {
    id: "easylist_allowlist",
    name: "EasyList Official Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "easylist_official",
    weight: 97,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/easylist/easylist@master/easylist/easylist_allowlist.txt",
      },
    ],
  },
  {
    id: "easyprivacy_allowlist",
    name: "EasyPrivacy Official Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "easylist_official",
    weight: 97,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/easylist/easylist@master/easyprivacy/easyprivacy_allowlist.txt",
      },
    ],
  },
  {
    id: "easyprivacy_intl_allowlist",
    name: "EasyPrivacy International Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "easylist_official",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_allowlist_international.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/easylist/easylist@master/easyprivacy/easyprivacy_allowlist_international.txt",
      },
    ],
  },
  {
    id: "easylist_cookie_allowlist",
    name: "EasyList Cookie Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "easylist_official",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/easylist/easylist@master/easylist_cookie/easylist_cookie_allowlist.txt",
      },
    ],
  },
  {
    id: "list_kr_allowlist",
    name: "List-KR Shared Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "list_kr",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/List-KR/List-KR/master/filterslists/adblocking/filters-share/allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/List-KR/List-KR@master/filterslists/adblocking/filters-share/allowlist.txt",
      },
    ],
  },

  // Chinese & East Asian False-Positive Whitelists
  {
    id: "cats_dns_allowlist",
    name: "Cats-Team AdRules DNS Allowlist",
    role: "allowlist",
    format: "domain_list",
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
    id: "goodbyeads_allow",
    name: "8680 GOODBYEADS Allow Rules",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "goodbyeads",
    weight: 94,
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
    weight: 93,
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
    weight: 94,
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

  // Global DNS, Referral, Shortener, System & Functional Service Whitelists
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
    id: "hagezi_referral_allow",
    name: "HaGeZi Referral & Affiliate Tracking Unbreak Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "hagezi_dns",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral.txt",
      },
      {
        kind: "direct",
        url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_45.txt",
      },
    ],
  },
  {
    id: "hagezi_referral_native_allow",
    name: "HaGeZi Native Referral Unbreak Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "hagezi_dns",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral-native.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@main/adblock/whitelist-referral-native.txt",
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
    id: "dandelion_shortener_affiliate_allow",
    name: "Dandelion Sprout Legitimate URL Shortener Affiliate Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "dandelion_adfilt",
    weight: 95,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LegitimateURLShortener-AffiliateTagAllowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/DandelionSprout/adfilt@master/LegitimateURLShortener-AffiliateTagAllowlist.txt",
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
    weight: 95,
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
    id: "onehosts_exclude_all",
    name: "1Hosts Global Exclusion Allowlist",
    role: "allowlist",
    format: "domain_list",
    platform: "universal",
    lineage: "onehosts",
    weight: 93,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/badmojr/1Hosts/master/-data/lists/exclude_for_all.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/badmojr/1Hosts@master/-data/lists/exclude_for_all.txt",
      },
    ],
  },
  {
    id: "onehosts_exclude_mini_lite",
    name: "1Hosts Mini & Lite Exclusion Allowlist",
    role: "allowlist",
    format: "domain_list",
    platform: "universal",
    lineage: "onehosts",
    weight: 93,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/badmojr/1Hosts/master/-data/lists/exclude_for_mini_Lite_only.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/badmojr/1Hosts@master/-data/lists/exclude_for_mini_Lite_only.txt",
      },
    ],
  },
  {
    id: "neodevhost_allow",
    name: "NEO DEV HOST Official Allowlist",
    role: "allowlist",
    format: "domain_list",
    platform: "universal",
    lineage: "neodevhost",
    weight: 94,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/neodevpro/neodevhost/master/allow",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/neodevpro/neodevhost@master/allow",
      },
    ],
  },
  {
    id: "shadowwhisperer_whitelist",
    name: "ShadowWhisperer Curated Whitelist",
    role: "allowlist",
    format: "domain_list",
    platform: "universal",
    lineage: "shadowwhisperer",
    weight: 94,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Whitelists/Whitelist",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/ShadowWhisperer/BlockLists@master/Whitelists/Whitelist",
      },
    ],
  },
  {
    id: "uhb_whitelist",
    name: "Ultimate Hosts Blacklist Official Whitelist",
    role: "allowlist",
    format: "domain_list",
    platform: "universal",
    lineage: "uhb_whitelist",
    weight: 94,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/whitelist/master/domains.list",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/Ultimate-Hosts-Blacklist/whitelist@master/domains.list",
      },
    ],
  },
  {
    id: "sefinek_whitelist",
    name: "Sefinek Blocklist Collection Main Whitelist",
    role: "allowlist",
    format: "domain_list",
    platform: "universal",
    lineage: "sefinek_whitelist",
    weight: 94,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/main/whitelists/main.txt",
      },
    ],
  },
  {
    id: "cpbl_whitelist",
    name: "Combined Privacy Block Lists Official Whitelist",
    role: "allowlist",
    format: "domain_list",
    platform: "universal",
    lineage: "cpbl_whitelist",
    weight: 94,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/bongochong/CombinedPrivacyBlockLists/master/NoFormatting/WhitelistedDomains.txt",
      },
    ],
  },
  {
    id: "ut1_liste_blanche",
    name: "UT1 Toulouse University Official Allowlist (liste_blanche)",
    role: "allowlist",
    format: "domain_list",
    platform: "universal",
    lineage: "ut1_blacklists",
    weight: 94,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/liste_blanche/domains",
      },
    ],
  },
  {
    id: "acl4ssr_unban",
    name: "ACL4SSR UnBan False-Positive Allowlist",
    role: "allowlist",
    format: "surge_ruleset",
    platform: "universal",
    lineage: "acl4ssr",
    weight: 95,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/UnBan.list",
      },
    ],
  },
  {
    id: "dandelion_nordic_allowlist",
    name: "Dandelion Sprout Nordic Domains Allowlist",
    role: "allowlist",
    format: "domain_list",
    platform: "universal",
    lineage: "dandelion_adfilt",
    weight: 94,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/NorwegianExperimentalList%20alternate%20versions/NordicFiltersDomainsAllowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/DandelionSprout/adfilt@master/NorwegianExperimentalList%20alternate%20versions/NordicFiltersDomainsAllowlist.txt",
      },
    ],
  },
  {
    id: "easylist_fanboy_social_allowlist",
    name: "EasyList Fanboy Social Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "easylist_official",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/easylist/easylist@master/fanboy-addon/fanboy_social_allowlist.txt",
      },
    ],
  },
  {
    id: "easylist_fanboy_notifications_allowlist",
    name: "EasyList Fanboy Notifications Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "easylist_official",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/easylist/easylist@master/fanboy-addon/fanboy_notifications_allowlist.txt",
      },
    ],
  },
  {
    id: "easylist_fanboy_newsletter_allowlist",
    name: "EasyList Fanboy Newsletter Allowlist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "easylist_official",
    weight: 96,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_allowlist.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/easylist/easylist@master/fanboy-addon/fanboy_newsletter_allowlist.txt",
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
  {
    id: "badblock_main_whitelist",
    name: "BadBlock Combined Unbreak Whitelist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "celenityy_badblock",
    weight: 95,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/whitelist.txt",
      },
    ],
  },
  {
    id: "badblock_android_whitelist",
    name: "BadBlock Android System Services Whitelist",
    role: "allowlist",
    format: "abp_filter",
    platform: "mobile",
    lineage: "celenityy_badblock",
    weight: 95,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/android_whitelist.txt",
      },
    ],
  },
  {
    id: "badblock_linux_whitelist",
    name: "BadBlock Linux Distro & Package Mirror Whitelist",
    role: "allowlist",
    format: "abp_filter",
    platform: "desktop",
    lineage: "celenityy_badblock",
    weight: 95,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/linux_whitelist.txt",
      },
    ],
  },
  {
    id: "badblock_nintendo_whitelist",
    name: "BadBlock Nintendo Online Services Whitelist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "celenityy_badblock",
    weight: 95,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/nintendo_whitelist.txt",
      },
    ],
  },
  {
    id: "badblock_ethical_whitelist",
    name: "BadBlock Privacy-Respecting Analytics Whitelist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "celenityy_badblock",
    weight: 94,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/ethical_whitelist.txt",
      },
    ],
  },
  {
    id: "badblock_misc_whitelist",
    name: "BadBlock Miscellaneous Functional Services Whitelist",
    role: "allowlist",
    format: "abp_filter",
    platform: "universal",
    lineage: "celenityy_badblock",
    weight: 94,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/celenityy/BadBlock/pages/abp/misc_whitelist.txt",
      },
    ],
  },
];
