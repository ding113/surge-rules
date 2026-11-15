import { ADBLOCK_ALLOWLIST_SOURCES } from "./adblock-allowlists.ts";
import { ADBLOCK_COMPLEX_SOURCES } from "./adblock-complex.ts";
import { ADBLOCK_RULESET_SOURCES } from "./adblock-rulesets.ts";
import type { AdblockSourceCatalogBundle } from "./adblock-schema.ts";
import type { GeoIpSourceCatalogBundle } from "./schema.ts";
import { TIER1_GEOFEED_SOURCES } from "./tier1-geofeed.ts";
import { TIER2A_CN_SOURCES } from "./tier2a-cn.ts";
import { TIER2B_GLOBAL_SOURCES } from "./tier2b-global.ts";
import { TIER3_BGP_RIR_SOURCES } from "./tier3-bgp-rir.ts";
import { TRAIT_OVERLAY_SOURCES } from "./trait-overlays.ts";

export const GEOIP_SOURCES: GeoIpSourceCatalogBundle = {
  schemaVersion: 1,
  sources: [
    ...TIER1_GEOFEED_SOURCES,
    ...TIER2A_CN_SOURCES,
    ...TIER2B_GLOBAL_SOURCES,
    ...TIER3_BGP_RIR_SOURCES,
    ...TRAIT_OVERLAY_SOURCES,
  ],
};

export const ADBLOCK_SOURCES: AdblockSourceCatalogBundle = {
  schemaVersion: 1,
  sources: [...ADBLOCK_ALLOWLIST_SOURCES, ...ADBLOCK_COMPLEX_SOURCES, ...ADBLOCK_RULESET_SOURCES],
};

export * from "./adblock-allowlists.ts";
export * from "./adblock-complex.ts";
export * from "./adblock-rulesets.ts";
export * from "./adblock-schema.ts";
export * from "./schema.ts";
export * from "./tier1-geofeed.ts";
export * from "./tier2a-cn.ts";
export * from "./tier2b-global.ts";
export * from "./tier3-bgp-rir.ts";
export * from "./trait-overlays.ts";
