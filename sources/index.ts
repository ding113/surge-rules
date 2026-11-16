import { ADBLOCK_ALLOWLIST_SOURCES } from "./adblock-allowlists.ts";
import { ADBLOCK_COMPLEX_SOURCES } from "./adblock-complex.ts";
import { ADBLOCK_PRIVACY_SOURCES } from "./adblock-privacy.ts";
import { ADBLOCK_RULESET_SOURCES } from "./adblock-rulesets.ts";
import type { AdblockSourceCatalogBundle } from "./adblock-schema.ts";
import { AI_ROUTING_SOURCES } from "./routing-ai.ts";
import { DIRECT_ROUTING_SOURCES } from "./routing-direct.ts";
import { PAYMENT_ROUTING_SOURCES } from "./routing-payment.ts";
import { PROXY_ROUTING_SOURCES } from "./routing-proxy.ts";
import type { RoutingSourceCatalogBundle } from "./routing-schema.ts";
import { TELEMETRY_ROUTING_SOURCES } from "./routing-telemetry.ts";
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
  sources: [
    ...ADBLOCK_ALLOWLIST_SOURCES,
    ...ADBLOCK_COMPLEX_SOURCES,
    ...ADBLOCK_RULESET_SOURCES,
    ...ADBLOCK_PRIVACY_SOURCES,
  ],
};

export const ROUTING_SOURCES: RoutingSourceCatalogBundle = {
  schemaVersion: 1,
  sources: [
    ...DIRECT_ROUTING_SOURCES,
    ...AI_ROUTING_SOURCES,
    ...PAYMENT_ROUTING_SOURCES,
    ...TELEMETRY_ROUTING_SOURCES,
    ...PROXY_ROUTING_SOURCES,
  ],
};

export * from "./adblock-allowlists.ts";
export * from "./adblock-complex.ts";
export * from "./adblock-privacy.ts";
export * from "./adblock-rulesets.ts";
export * from "./adblock-schema.ts";
export * from "./routing-ai.ts";
export * from "./routing-direct.ts";
export * from "./routing-payment.ts";
export * from "./routing-proxy.ts";
export * from "./routing-schema.ts";
export * from "./routing-telemetry.ts";
export * from "./schema.ts";
export * from "./tier1-geofeed.ts";
export * from "./tier2a-cn.ts";
export * from "./tier2b-global.ts";
export * from "./tier3-bgp-rir.ts";
export * from "./trait-overlays.ts";
