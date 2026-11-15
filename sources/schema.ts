export type SourceTier =
  | "tier1_geofeed"
  | "tier2a_cn"
  | "tier2b_global"
  | "tier3_bgp_rir"
  | "trait_overlay";

export type SourceFormat =
  | "geofeed_parquet"
  | "rfc8805_csv"
  | "aws_ip_ranges_json"
  | "gcp_cloud_json"
  | "oracle_cloud_json"
  | "xdb"
  | "qqwry_dat"
  | "ipdb"
  | "cidr_country"
  | "cidr_isp"
  | "cidr_trait"
  | "mmdb"
  | "ip2location_bin"
  | "ip2location_csv"
  | "libloc"
  | "ipscope_csv"
  | "sypex_dat"
  | "bgptools_table"
  | "bgptools_asns_csv"
  | "bgptools_tag_csv"
  | "ipverse_as_csv"
  | "iptoasn_tsv"
  | "rir_delegated"
  | "fastly_json"
  | "gcore_json"
  | "github_meta_json"
  | "onionoo_json"
  | "openproxydb_csv"
  | "sat_geoip_jsonl"
  | "sat_asns_csv"
  | "spamhaus_drop";

export type SourceEndpoint =
  | {
      readonly kind: "direct";
      readonly url: string;
    }
  | {
      readonly kind: "github_release";
      readonly repo: string;
      readonly assetPattern: string;
    }
  | {
      readonly kind: "npm_tarball";
      readonly package: string;
      readonly memberPath: string;
    };

export interface GeoIpSourceEntry {
  readonly id: string;
  readonly tier: SourceTier;
  readonly format: SourceFormat;
  readonly lineage: string;
  readonly countryWeight?: number;
  readonly cnWeight?: number;
  readonly cityWeight?: number;
  readonly ispWeight?: number;
  readonly asnWeight?: number;
  readonly registeredCountryWeight?: number;
  readonly fixedCountry?: string;
  readonly fixedIsp?: string;
  readonly isHosting?: boolean;
  readonly isCdn?: boolean;
  readonly isVpn?: boolean;
  readonly isAnycast?: boolean;
  readonly isAnonymousProxy?: boolean;
  readonly isTorExit?: boolean;
  readonly isIcloudRelay?: boolean;
  readonly isSatellite?: boolean;
  readonly isCrawler?: boolean;
  readonly isMalware?: boolean;
  readonly core?: boolean;
  readonly endpoints: readonly SourceEndpoint[];
}

export interface GeoIpSourceCatalogBundle {
  readonly schemaVersion: 1;
  readonly sources: readonly GeoIpSourceEntry[];
}
