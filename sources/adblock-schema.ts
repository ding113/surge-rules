import type { SourceEndpoint } from "./schema.ts";

export type AdblockSourceRole = "allowlist" | "complex_first" | "ruleset_fallback";

export type AdblockCategory = "ad" | "privacy" | "ad_mixed" | "both";

export type AdblockSourceFormat =
  | "surge_module"
  | "qx_rewrite"
  | "surge_ruleset"
  | "surge_domainset"
  | "abp_filter"
  | "hosts"
  | "domain_list"
  | "json_domain_array"
  | "polkadot_phishing_json"
  | "metamask_config_json"
  | "tweetfeed_csv"
  | "adguard_companiesdb_json"
  | "ddg_tds_json"
  | "disconnect_services_json"
  | "ghostery_trackerdb_json"
  | "c2intel_domain_csv";

export type AdblockPlatformScope = "universal" | "mobile" | "desktop";

export interface AdblockSourceEntry {
  readonly id: string;
  readonly name?: string;
  readonly role: AdblockSourceRole;
  readonly category: AdblockCategory;
  readonly format: AdblockSourceFormat;
  readonly platform: AdblockPlatformScope;
  readonly lineage: string;
  readonly weight: number;
  readonly core?: boolean;
  readonly extractComplexNetworkRules?: boolean;
  readonly extractFallbackDomainRules?: boolean;
  readonly filterDirectCollisions?: boolean;
  readonly endpoints: readonly SourceEndpoint[];
}

export interface AdblockSourceCatalogBundle {
  readonly schemaVersion: 1;
  readonly sources: readonly AdblockSourceEntry[];
}
