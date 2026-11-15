import type { MetadataUpstreamSource } from "./schema.ts";

/**
 * Upstream open repositories and canonical public datasets used to synthesize
 * `metadata/generated/geoip-metadata.json`.
 */
export const METADATA_UPSTREAMS: readonly MetadataUpstreamSource[] = [
  {
    id: "geonames_country_info",
    repoOrSite: "geonames.org",
    description: "GeoNames global country codes, continents, capitals, and geoname_ids",
    urls: ["https://download.geonames.org/export/dump/countryInfo.txt"],
  },
  {
    id: "geonames_cities5000",
    repoOrSite: "geonames.org",
    description:
      "GeoNames populated places (>= 5000 pop) with localized alternate names and WGS-84 coordinates",
    urls: ["https://download.geonames.org/export/dump/cities5000.zip"],
    archiveMember: "cities5000.txt",
  },
  {
    id: "mledoze_countries",
    repoOrSite: "mledoze/countries",
    description: "Country ISO codes, English names, alternate spellings, and zho translations",
    urls: [
      "https://raw.githubusercontent.com/mledoze/countries/master/dist/countries.json",
      "https://cdn.jsdelivr.net/gh/mledoze/countries@master/dist/countries.json",
    ],
  },
  {
    id: "cldr_country_zh_cn",
    repoOrSite: "umpirsky/country-list",
    description: "Unicode CLDR Simplified Chinese country & region display names",
    urls: [
      "https://raw.githubusercontent.com/umpirsky/country-list/master/data/zh_CN/country.json",
      "https://cdn.jsdelivr.net/gh/umpirsky/country-list@master/data/zh_CN/country.json",
    ],
  },
  {
    id: "cldr_country_en",
    repoOrSite: "umpirsky/country-list",
    description: "Unicode CLDR English country & region display names",
    urls: [
      "https://raw.githubusercontent.com/umpirsky/country-list/master/data/en/country.json",
      "https://cdn.jsdelivr.net/gh/umpirsky/country-list@master/data/en/country.json",
    ],
  },
  {
    id: "eu_membership",
    repoOrSite: "dieghernan/Country-Codes-and-International-Organizations",
    description: "European Union membership status keyed by ISO 3166-1 alpha-2",
    urls: [
      "https://raw.githubusercontent.com/dieghernan/Country-Codes-and-International-Organizations/master/outputs/Countrycodesfull.json",
      "https://raw.githubusercontent.com/OxfordEconomics/CountryLists/main/countryList-EU.csv",
    ],
  },
  {
    id: "iana_zone1970",
    repoOrSite: "eggert/tz",
    description: "IANA time zone database country-to-zone mapping table",
    urls: ["https://raw.githubusercontent.com/eggert/tz/main/zone1970.tab"],
  },
  {
    id: "modood_cn_pca",
    repoOrSite: "modood/Administrative-divisions-of-China",
    description: "GB/T 2260 Chinese province, prefecture, and county administrative hierarchy",
    urls: [
      "https://raw.githubusercontent.com/modood/Administrative-divisions-of-China/master/dist/pca-code.json",
      "https://unpkg.com/china-division@latest/dist/pca-code.json",
    ],
  },
  {
    id: "areacity_cn_level3",
    repoOrSite: "xiangyuecn/AreaCity-JsSpider-StatsGov",
    description:
      "Chinese 3-level administrative divisions with Pinyin transliterations and centroids",
    urls: [
      "https://raw.githubusercontent.com/xiangyuecn/AreaCity-JsSpider-StatsGov/master/src/%E9%87%87%E9%9B%86%E5%88%B0%E7%9A%84%E6%95%B0%E6%8D%AE/ok_data_level3.csv",
      "https://cdn.jsdelivr.net/gh/xiangyuecn/AreaCity-JsSpider-StatsGov@master/src/%E9%87%87%E9%9B%86%E5%88%B0%E7%9A%84%E6%95%B0%E6%8D%AE/ok_data_level3.csv",
    ],
  },
  {
    id: "dr5hn_states",
    repoOrSite: "dr5hn/countries-states-cities-database",
    description: "Global ISO 3166-2 subdivision codes, names, and state centroids",
    urls: [
      "github-release:dr5hn/countries-states-cities-database:^states\\.json\\.gz$",
      "https://raw.githubusercontent.com/dr5hn/countries-states-cities-database/master/json/states.json",
    ],
  },
  {
    id: "debian_iso_3166_2",
    repoOrSite: "iso-codes-team/iso-codes",
    description: "Official Debian iso-codes ISO 3166-2 subdivision registry",
    urls: ["https://salsa.debian.org/iso-codes-team/iso-codes/-/raw/main/data/iso_3166-2.json"],
  },
  {
    id: "aws_ip_ranges",
    repoOrSite: "ip-ranges.amazonaws.com",
    description: "AWS official IP prefix to region mapping",
    urls: ["https://ip-ranges.amazonaws.com/ip-ranges.json"],
  },
  {
    id: "aws_geofeed",
    repoOrSite: "ip-ranges.amazonaws.com",
    description: "AWS official RFC 8805 geofeed mapping prefixes to countries and cities",
    urls: ["https://ip-ranges.amazonaws.com/aws-ip-ranges.csv"],
  },
  {
    id: "jsonmaur_aws_regions",
    repoOrSite: "jsonmaur/aws-regions",
    description: "Structured AWS region names and availability zone catalog",
    urls: [
      "https://raw.githubusercontent.com/jsonmaur/aws-regions/master/regions.json",
      "https://cdn.jsdelivr.net/gh/jsonmaur/aws-regions@master/regions.json",
    ],
  },
  {
    id: "gcp_cloud_ranges",
    repoOrSite: "gstatic.com/ipranges",
    description: "Google Cloud official prefix-to-region scope mapping",
    urls: ["https://www.gstatic.com/ipranges/cloud.json"],
  },
  {
    id: "gcp_cloud_geofeed",
    repoOrSite: "gstatic.com/ipranges",
    description: "Google Cloud official RFC 8805 geofeed",
    urls: ["https://www.gstatic.com/ipranges/cloud_geofeed"],
  },
  {
    id: "oracle_cloud_ranges",
    repoOrSite: "docs.oracle.com",
    description: "Oracle Cloud Infrastructure official public IP ranges and region list",
    urls: ["https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"],
  },
  {
    id: "azure_regions",
    repoOrSite: "Green-Software-Foundation/carbon-aware-sdk",
    description: "Azure region identifiers and coordinates",
    urls: [
      "https://raw.githubusercontent.com/Green-Software-Foundation/carbon-aware-sdk/dev/src/data/location-sources/azure-regions.json",
      "https://cdn.jsdelivr.net/gh/Green-Software-Foundation/carbon-aware-sdk@dev/src/data/location-sources/azure-regions.json",
    ],
  },
];
