import { ALLOW_DOMAINS, PROTECTED_APEX_DOMAINS } from "./adblock-allowlist.ts";
import {
  DISABLED_URL_PATTERNS,
  MITM_ADDED_HOSTS,
  MITM_EXCLUDED_HOSTS,
  MODULE_BODY_REWRITES,
  MODULE_HEADER_REWRITES,
  MODULE_MAP_LOCALS,
  MODULE_SCRIPTS,
  MODULE_URL_REWRITES,
} from "./adblock-module.ts";
import { FORCE_RULESET_ENTRIES } from "./adblock-ruleset.ts";
import type { AdblockOverridesBundle } from "./adblock-schema.ts";
import { ASN_OVERRIDES } from "./geoip-asn.ts";
import { CN_EXCLUSIONS, COUNTRY_OVERRIDES } from "./geoip-country.ts";
import { AI_EXCLUDE_ENTRIES, AI_FORCE_ENTRIES, SHARED_INFRA_ROOTS } from "./routing-ai.ts";
import { DIRECT_EXCLUDE_ENTRIES, DIRECT_FORCE_ENTRIES } from "./routing-direct.ts";
import { PAYMENT_EXCLUDE_ENTRIES, PAYMENT_FORCE_ENTRIES } from "./routing-payment.ts";
import { PROXY_EXCLUDE_ENTRIES, PROXY_FORCE_ENTRIES } from "./routing-proxy.ts";
import type { RoutingOverridesBundle } from "./routing-schema.ts";
import { TELEMETRY_EXCLUDE_ENTRIES, TELEMETRY_FORCE_ENTRIES } from "./routing-telemetry.ts";
import type { GeoIpOverridesBundle } from "./schema.ts";
import { SPECIAL_NETWORKS } from "./special-networks.ts";

export const GEOIP_OVERRIDES: GeoIpOverridesBundle = {
  schemaVersion: 1,
  specialNetworks: SPECIAL_NETWORKS,
  countryOverrides: COUNTRY_OVERRIDES,
  cnExclusions: CN_EXCLUSIONS,
  asnOverrides: ASN_OVERRIDES,
};

export const ADBLOCK_OVERRIDES: AdblockOverridesBundle = {
  schemaVersion: 1,
  allowDomains: ALLOW_DOMAINS,
  protectedApexDomains: PROTECTED_APEX_DOMAINS,
  forceRuleSetEntries: FORCE_RULESET_ENTRIES,
  mitmExcludedHosts: MITM_EXCLUDED_HOSTS,
  mitmAddedHosts: MITM_ADDED_HOSTS,
  disabledUrlPatterns: DISABLED_URL_PATTERNS,
  urlRewrites: MODULE_URL_REWRITES,
  mapLocals: MODULE_MAP_LOCALS,
  headerRewrites: MODULE_HEADER_REWRITES,
  bodyRewrites: MODULE_BODY_REWRITES,
  scripts: MODULE_SCRIPTS,
};

export const ROUTING_OVERRIDES: RoutingOverridesBundle = {
  schemaVersion: 1,
  sharedInfraRoots: SHARED_INFRA_ROOTS,
  forceEntries: [
    ...AI_FORCE_ENTRIES,
    ...PAYMENT_FORCE_ENTRIES,
    ...TELEMETRY_FORCE_ENTRIES,
    ...DIRECT_FORCE_ENTRIES,
    ...PROXY_FORCE_ENTRIES,
  ],
  excludeEntries: [
    ...AI_EXCLUDE_ENTRIES,
    ...PAYMENT_EXCLUDE_ENTRIES,
    ...TELEMETRY_EXCLUDE_ENTRIES,
    ...DIRECT_EXCLUDE_ENTRIES,
    ...PROXY_EXCLUDE_ENTRIES,
  ],
};

export * from "./adblock-allowlist.ts";
export * from "./adblock-module.ts";
export * from "./adblock-ruleset.ts";
export * from "./adblock-schema.ts";
export * from "./geoip-asn.ts";
export * from "./geoip-country.ts";
export * from "./routing-ai.ts";
export * from "./routing-direct.ts";
export * from "./routing-payment.ts";
export * from "./routing-proxy.ts";
export * from "./routing-schema.ts";
export * from "./routing-telemetry.ts";
export * from "./schema.ts";
export * from "./special-networks.ts";
