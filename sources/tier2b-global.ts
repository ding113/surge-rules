import type { GeoIpSourceEntry } from "./schema.ts";

/**
 * Tier 2B: Global Independent & Commercial-Lite Geolocation Databases.
 */
export const TIER2B_GLOBAL_SOURCES: readonly GeoIpSourceEntry[] = [
  {
    id: "ipinfo_lite",
    tier: "tier2b_global",
    format: "mmdb",
    lineage: "ipinfo",
    countryWeight: 82,
    asnWeight: 82,
    core: true,
    endpoints: [
      {
        kind: "github_release",
        repo: "Alice39s/ipinfo-csv-lite",
        assetPattern: "^ipinfo-lite\\.mmdb$",
      },
      {
        kind: "github_release",
        repo: "NetworkCats/IPinfoLite-Download",
        assetPattern: "^ipinfo_lite\\.mmdb$",
      },
      {
        kind: "github_release",
        repo: "gen0sec/geoip-databases",
        assetPattern: "^ipinfo_lite\\.mmdb$",
      },
      {
        kind: "github_release",
        repo: "8bitsaver/ipinfo-geoip",
        assetPattern: "^country_asn\\.mmdb$",
      },
    ],
  },
  {
    id: "maxmind_geolite2_city",
    tier: "tier2b_global",
    format: "mmdb",
    lineage: "maxmind",
    countryWeight: 75,
    cityWeight: 84,
    registeredCountryWeight: 85,
    core: true,
    endpoints: [
      {
        kind: "github_release",
        repo: "Skiddle-ID/geoip2-mirror",
        assetPattern: "^GeoLite2-City\\.mmdb$",
      },
      {
        kind: "github_release",
        repo: "gen0sec/geoip-databases",
        assetPattern: "^GeoLite2-City\\.mmdb$",
      },
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/wyot1/GeoLite2-Unwalled/downloads/CITY/MMDB/GeoLite2-City.mmdb",
      },
      {
        kind: "direct",
        url: "https://github.com/jcjc-dev/mmdb-latest/releases/download/maxmind-latest/GeoLite2-City.mmdb",
      },
    ],
  },
  {
    id: "maxmind_geolite2_country",
    tier: "tier2b_global",
    format: "mmdb",
    lineage: "maxmind",
    countryWeight: 75,
    registeredCountryWeight: 85,
    endpoints: [
      {
        kind: "github_release",
        repo: "Skiddle-ID/geoip2-mirror",
        assetPattern: "^GeoLite2-Country\\.mmdb$",
      },
      {
        kind: "github_release",
        repo: "KoNEW/geoip2-mirror",
        assetPattern: "^GeoLite2-Country\\.mmdb$",
      },
      {
        kind: "github_release",
        repo: "P3TERX/GeoLite.mmdb",
        assetPattern: "^GeoLite2-Country\\.mmdb$",
      },
      {
        kind: "direct",
        url: "https://github.com/jcjc-dev/mmdb-latest/releases/download/maxmind-latest/GeoLite2-Country.mmdb",
      },
    ],
  },
  {
    id: "dbip_city_lite",
    tier: "tier2b_global",
    format: "mmdb",
    lineage: "dbip",
    countryWeight: 77,
    cityWeight: 80,
    core: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://github.com/jcjc-dev/mmdb-latest/releases/download/dbip-latest/dbip-city-lite.mmdb",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/npm/dbip-city-lite/dbip-city-lite.mmdb.gz",
      },
    ],
  },
  {
    id: "dbip_country_lite",
    tier: "tier2b_global",
    format: "mmdb",
    lineage: "dbip",
    countryWeight: 77,
    endpoints: [
      {
        kind: "direct",
        url: "https://github.com/jcjc-dev/mmdb-latest/releases/download/dbip-latest/dbip-country-lite.mmdb",
      },
      {
        kind: "direct",
        url: "https://github.com/sapics/ip-location-db/releases/download/latest/dbip-country.mmdb",
      },
    ],
  },
  {
    id: "ip2location_db11",
    tier: "tier2b_global",
    format: "ip2location_bin",
    lineage: "ip2location",
    countryWeight: 78,
    cityWeight: 82,
    core: true,
    endpoints: [
      {
        kind: "github_release",
        repo: "renfei/ip2location",
        assetPattern: "^IP2LOCATION-LITE-DB11\\.IPV6\\.BIN$",
      },
    ],
  },
  {
    id: "ip2location_db1_official",
    tier: "tier2b_global",
    format: "ip2location_csv",
    lineage: "ip2location",
    countryWeight: 78,
    endpoints: [
      {
        kind: "direct",
        url: "https://download.ip2location.com/lite/IP2LOCATION-LITE-DB1.CSV.ZIP",
      },
    ],
  },
  {
    id: "ipfire_libloc",
    tier: "tier2b_global",
    format: "libloc",
    lineage: "ipfire_libloc",
    countryWeight: 74,
    asnWeight: 86,
    endpoints: [
      {
        kind: "direct",
        url: "https://location.ipfire.org/databases/1/location.db.xz",
      },
    ],
  },
  {
    id: "sapics_user_country",
    tier: "tier2b_global",
    format: "mmdb",
    lineage: "sapics_composite",
    countryWeight: 68,
    endpoints: [
      {
        kind: "direct",
        url: "https://github.com/sapics/ip-location-db/releases/download/latest/user-country.mmdb",
      },
    ],
  },
  {
    id: "iplocate_country",
    tier: "tier2b_global",
    format: "mmdb",
    lineage: "iplocate",
    countryWeight: 66,
    endpoints: [
      {
        kind: "direct",
        url: "https://media.githubusercontent.com/media/iplocate/ip-address-databases/HEAD/ip-to-country/ip-to-country.mmdb",
      },
    ],
  },
  {
    id: "ipscope_lite",
    tier: "tier2b_global",
    format: "ipscope_csv",
    lineage: "ipscope",
    countryWeight: 65,
    asnWeight: 72,
    endpoints: [
      {
        kind: "direct",
        url: "https://api.ipscope.io/v1/lite/ipscope-lite.csv.gz",
      },
    ],
  },
  {
    id: "ip66_mmdb",
    tier: "tier2b_global",
    format: "mmdb",
    lineage: "ip66",
    countryWeight: 64,
    endpoints: [
      {
        kind: "direct",
        url: "https://downloads.ip66.dev/db/ip66.mmdb",
      },
    ],
  },
  {
    id: "sypex_geo_country",
    tier: "tier2b_global",
    format: "sypex_dat",
    lineage: "sypexgeo",
    countryWeight: 62,
    endpoints: [
      {
        kind: "direct",
        url: "https://sypexgeo.net/files/SxGeoCountry.zip",
      },
    ],
  },
];
