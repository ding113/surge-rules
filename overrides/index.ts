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

export * from "./adblock-allowlist.ts";
export * from "./adblock-module.ts";
export * from "./adblock-ruleset.ts";
export * from "./adblock-schema.ts";
export * from "./geoip-asn.ts";
export * from "./geoip-country.ts";
export * from "./schema.ts";
export * from "./special-networks.ts";
