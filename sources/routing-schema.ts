import type { SourceEndpoint } from "./schema.ts";

export type RoutingTarget = "direct" | "ai" | "payment" | "telemetry" | "proxy";

export type RoutingSourceFormat =
  | "surge_ruleset"
  | "domain_set"
  | "domain_suffix_set"
  | "abp_filter"
  | "hosts"
  | "clash_classical"
  | "clash_yaml"
  | "geosite"
  | "dnsmasq_china"
  | "gfwlist_base64"
  | "ip_cidr"
  | "asn_list";

export type GeositeTagFilter = "all_non_ads" | "only_cn" | "exclude_cn";

export interface RoutingSourceEntry {
  readonly id: string;
  readonly name: string;
  readonly target: RoutingTarget;
  readonly lineage: string;
  readonly format: RoutingSourceFormat;
  readonly geositeFilter?: GeositeTagFilter;
  readonly weight: number;
  readonly core: boolean;
  readonly updateCadence: "6h" | "12h" | "daily" | "weekly" | "manual";
  readonly license: string;
  readonly homepage: string;
  readonly endpoints: readonly SourceEndpoint[];
  readonly notes?: string;
}

export interface RoutingSourceCatalogBundle {
  readonly schemaVersion: 1;
  readonly sources: readonly RoutingSourceEntry[];
}
