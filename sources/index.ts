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

export * from "./schema.ts";
export * from "./tier1-geofeed.ts";
export * from "./tier2a-cn.ts";
export * from "./tier2b-global.ts";
export * from "./tier3-bgp-rir.ts";
export * from "./trait-overlays.ts";
