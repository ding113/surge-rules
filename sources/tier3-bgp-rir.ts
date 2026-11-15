import type { GeoIpSourceEntry } from "./schema.ts";

/**
 * Tier 3: Live BGP Prefix-to-ASN Tables, ASN Metadata Dictionaries & RIR Delegations.
 */
export const TIER3_BGP_RIR_SOURCES: readonly GeoIpSourceEntry[] = [
  {
    id: "bgptools_table",
    tier: "tier3_bgp_rir",
    format: "bgptools_table",
    lineage: "bgptools",
    asnWeight: 96,
    core: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://bgp.tools/table.jsonl",
      },
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/Alice39s/BGP.Tools-OpenDB/auto-update/table/table-original.jsonl.gz",
      },
      {
        kind: "direct",
        url: "https://bgp.tools/table.txt",
      },
    ],
  },
  {
    id: "bgptools_asns",
    tier: "tier3_bgp_rir",
    format: "bgptools_asns_csv",
    lineage: "bgptools",
    endpoints: [
      {
        kind: "direct",
        url: "https://bgp.tools/asns.csv",
      },
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/Alice39s/BGP.Tools-OpenDB/auto-update/asns/asns.csv.gz",
      },
    ],
  },
  {
    id: "ipverse_as_metadata",
    tier: "tier3_bgp_rir",
    format: "ipverse_as_csv",
    lineage: "ipverse_as",
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/ipverse/as-metadata/master/as.csv",
      },
    ],
  },
  {
    id: "iptoasn_combined",
    tier: "tier3_bgp_rir",
    format: "iptoasn_tsv",
    lineage: "iptoasn",
    countryWeight: 35,
    asnWeight: 84,
    endpoints: [
      {
        kind: "direct",
        url: "https://iptoasn.com/data/ip2asn-combined.tsv.gz",
      },
    ],
  },
  {
    id: "sapics_origin_asn",
    tier: "tier3_bgp_rir",
    format: "mmdb",
    lineage: "sapics_bgp",
    asnWeight: 83,
    endpoints: [
      {
        kind: "direct",
        url: "https://github.com/sapics/ip-location-db/releases/download/latest/origin-asn.mmdb",
      },
    ],
  },
  {
    id: "maxmind_geolite2_asn",
    tier: "tier3_bgp_rir",
    format: "mmdb",
    lineage: "maxmind",
    asnWeight: 78,
    core: true,
    endpoints: [
      {
        kind: "github_release",
        repo: "Skiddle-ID/geoip2-mirror",
        assetPattern: "^GeoLite2-ASN\\.mmdb$",
      },
      {
        kind: "github_release",
        repo: "KoNEW/geoip2-mirror",
        assetPattern: "^GeoLite2-ASN\\.mmdb$",
      },
      {
        kind: "github_release",
        repo: "P3TERX/GeoLite.mmdb",
        assetPattern: "^GeoLite2-ASN\\.mmdb$",
      },
      {
        kind: "direct",
        url: "https://github.com/Shoyu-Dev/mmdb-latest/releases/download/maxmind-latest/GeoLite2-ASN.mmdb",
      },
    ],
  },
  {
    id: "dbip_asn_lite",
    tier: "tier3_bgp_rir",
    format: "mmdb",
    lineage: "dbip",
    asnWeight: 75,
    endpoints: [
      {
        kind: "direct",
        url: "https://github.com/Shoyu-Dev/mmdb-latest/releases/download/dbip-latest/dbip-asn-lite.mmdb",
      },
      {
        kind: "direct",
        url: "https://github.com/sapics/ip-location-db/releases/download/latest/dbip-asn.mmdb",
      },
    ],
  },
  {
    id: "iplocate_asn",
    tier: "tier3_bgp_rir",
    format: "mmdb",
    lineage: "iplocate",
    asnWeight: 70,
    endpoints: [
      {
        kind: "direct",
        url: "https://media.githubusercontent.com/media/iplocate/ip-address-databases/HEAD/ip-to-asn/ip-to-asn.mmdb",
      },
    ],
  },
  {
    id: "rir_apnic",
    tier: "tier3_bgp_rir",
    format: "rir_delegated",
    lineage: "iana_rir",
    countryWeight: 28,
    registeredCountryWeight: 100,
    endpoints: [
      {
        kind: "direct",
        url: "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
      },
      {
        kind: "direct",
        url: "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest",
      },
      {
        kind: "direct",
        url: "https://ftp.ripe.net/pub/stats/apnic/delegated-apnic-extended-latest",
      },
    ],
  },
  {
    id: "rir_arin",
    tier: "tier3_bgp_rir",
    format: "rir_delegated",
    lineage: "iana_rir",
    countryWeight: 28,
    registeredCountryWeight: 100,
    endpoints: [
      {
        kind: "direct",
        url: "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
      },
      {
        kind: "direct",
        url: "https://ftp.ripe.net/pub/stats/arin/delegated-arin-extended-latest",
      },
    ],
  },
  {
    id: "rir_ripencc",
    tier: "tier3_bgp_rir",
    format: "rir_delegated",
    lineage: "iana_rir",
    countryWeight: 28,
    registeredCountryWeight: 100,
    endpoints: [
      {
        kind: "direct",
        url: "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
      },
    ],
  },
  {
    id: "rir_lacnic",
    tier: "tier3_bgp_rir",
    format: "rir_delegated",
    lineage: "iana_rir",
    countryWeight: 28,
    registeredCountryWeight: 100,
    endpoints: [
      {
        kind: "direct",
        url: "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
      },
      {
        kind: "direct",
        url: "https://ftp.ripe.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
      },
    ],
  },
  {
    id: "rir_afrinic",
    tier: "tier3_bgp_rir",
    format: "rir_delegated",
    lineage: "iana_rir",
    countryWeight: 28,
    registeredCountryWeight: 100,
    endpoints: [
      {
        kind: "direct",
        url: "https://ftp.afrinic.net/stats/afrinic/delegated-afrinic-extended-latest",
      },
      {
        kind: "direct",
        url: "https://ftp.ripe.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
      },
    ],
  },
];
