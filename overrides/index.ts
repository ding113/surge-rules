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

export * from "./geoip-asn.ts";
export * from "./geoip-country.ts";
export * from "./schema.ts";
export * from "./special-networks.ts";
