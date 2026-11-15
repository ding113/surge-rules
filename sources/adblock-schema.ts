import type { SourceEndpoint } from "./schema.ts";

export type AdblockSourceRole = "allowlist" | "complex_first" | "ruleset_fallback";

export type AdblockSourceFormat =
  | "surge_module"
  | "qx_rewrite"
  | "surge_ruleset"
  | "surge_domainset"
  | "abp_filter"
  | "hosts"
  | "domain_list";

export type AdblockPlatformScope = "universal" | "mobile" | "desktop";

export interface AdblockSourceEntry {
  readonly id: string;
  readonly role: AdblockSourceRole;
  readonly format: AdblockSourceFormat;
  readonly platform: AdblockPlatformScope;
  readonly lineage: string;
  readonly weight: number;
  readonly core?: boolean;
  readonly extractComplexNetworkRules?: boolean;
  readonly extractFallbackDomainRules?: boolean;
  readonly endpoints: readonly SourceEndpoint[];
}

export interface AdblockSourceCatalogBundle {
  readonly schemaVersion: 1;
  readonly sources: readonly AdblockSourceEntry[];
}
