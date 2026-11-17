import type { GeoIpSourceEntry } from "./schema.ts";

/**
 * Tier 1: Aggregated Operator RFC 8805 Geofeeds & First-Party Cloud Manifests.
 */
export const TIER1_GEOFEED_SOURCES: readonly GeoIpSourceEntry[] = [
  {
    id: "geofeed_harvester",
    tier: "tier1_geofeed",
    format: "geofeed_parquet",
    lineage: "operator_geofeed",
    countryWeight: 96,
    cityWeight: 92,
    core: true,
    endpoints: [
      {
        kind: "github_release",
        repo: "ipanalytics/GeoFeed-Harvester",
        assetPattern: "^geofeed\\.parquet$",
      },
      {
        kind: "direct",
        url: "https://github.com/ipanalytics/GeoFeed-Harvester/releases/download/dataset-current/geofeed.parquet",
      },
    ],
  },
  {
    id: "opengeofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "operator_geofeed",
    countryWeight: 96,
    cityWeight: 92,
    endpoints: [
      {
        kind: "direct",
        url: "https://opengeofeed.org/feed/public.csv",
      },
    ],
  },
  {
    id: "ntt_gin_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "operator_geofeed",
    countryWeight: 96,
    cityWeight: 92,
    endpoints: [
      {
        kind: "direct",
        url: "https://geo.ip.gin.ntt.net/geofeeds/geofeeds.csv",
      },
    ],
  },
  {
    id: "lacnic_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "operator_geofeed",
    countryWeight: 96,
    cityWeight: 92,
    endpoints: [
      {
        kind: "direct",
        url: "https://milacnic.lacnic.net/lacnic/geofeeds/geofeeds.csv",
      },
    ],
  },
  {
    id: "aws_ip_ranges",
    tier: "tier1_geofeed",
    format: "aws_ip_ranges_json",
    lineage: "aws_official",
    countryWeight: 100,
    cityWeight: 98,
    isHosting: true,
    core: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://ip-ranges.amazonaws.com/ip-ranges.json",
      },
    ],
  },
  {
    id: "aws_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "aws_official",
    countryWeight: 100,
    cityWeight: 99,
    isHosting: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://ip-ranges.amazonaws.com/geo-ip-feed.csv",
      },
    ],
  },
  {
    id: "gcp_cloud_ranges",
    tier: "tier1_geofeed",
    format: "gcp_cloud_json",
    lineage: "google_official",
    countryWeight: 100,
    cityWeight: 98,
    isHosting: true,
    core: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://www.gstatic.com/ipranges/cloud.json",
      },
    ],
  },
  {
    id: "gcp_cloud_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "google_official",
    countryWeight: 100,
    cityWeight: 99,
    isHosting: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://www.gstatic.com/ipranges/cloud_geofeed",
      },
    ],
  },
  {
    id: "google_corp_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "google_official",
    countryWeight: 99,
    cityWeight: 96,
    endpoints: [
      {
        kind: "direct",
        url: "https://www.gstatic.com/geofeed/corp_external",
      },
    ],
  },
  {
    id: "google_vpn_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "google_official",
    countryWeight: 98,
    cityWeight: 95,
    isVpn: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://www.gstatic.com/vpn/geofeed",
      },
    ],
  },
  {
    id: "cloudflare_local_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "cloudflare_official",
    countryWeight: 100,
    cityWeight: 98,
    isCdn: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://api.cloudflare.com/local-ip-ranges.csv",
      },
    ],
  },
  {
    id: "cloudflare_warp_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "cloudflare_official",
    countryWeight: 100,
    cityWeight: 98,
    isVpn: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://api.cloudflare.com/warp-egress-ip-ranges.csv",
      },
    ],
  },
  {
    id: "cloudflare_jdcloud_geofeed",
    tier: "tier1_geofeed",
    format: "cloudflare_jdcloud_json",
    lineage: "cloudflare_official",
    countryWeight: 100,
    isCdn: true,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://api.cloudflare.com/client/v4/ips?networks=jdcloud",
      },
    ],
  },
  {
    id: "apple_icloud_private_relay",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "apple_official",
    countryWeight: 100,
    cityWeight: 98,
    isAnonymousProxy: true,
    isIcloudRelay: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://mask-api.icloud.com/egress-ip-ranges.csv",
      },
    ],
  },
  {
    id: "oracle_cloud_ranges",
    tier: "tier1_geofeed",
    format: "oracle_cloud_json",
    lineage: "oracle_official",
    countryWeight: 100,
    cityWeight: 98,
    isHosting: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
      },
    ],
  },
  {
    id: "digitalocean_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "digitalocean_official",
    countryWeight: 100,
    cityWeight: 98,
    isHosting: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://digitalocean.com/geo/google.csv",
      },
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/jonhadfield/cloud-ips/main/digitalocean.csv",
      },
    ],
  },
  {
    id: "akamai_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "akamai_official",
    countryWeight: 100,
    cityWeight: 97,
    isCdn: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://ipgeo.akamai.com/akamai-geofeed.csv",
      },
    ],
  },
  {
    id: "linode_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "akamai_official",
    countryWeight: 100,
    cityWeight: 98,
    isHosting: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://ipgeo.akamai.com/linode-geofeed.csv",
      },
      {
        kind: "direct",
        url: "https://geoip.linode.com/",
      },
    ],
  },
  {
    id: "hetzner_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "hetzner_official",
    countryWeight: 100,
    cityWeight: 98,
    isHosting: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://www.hetzner.com/geofeed.csv",
      },
    ],
  },
  {
    id: "vultr_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "vultr_official",
    countryWeight: 100,
    cityWeight: 98,
    isHosting: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://geofeed.constant.com/",
      },
    ],
  },
  {
    id: "starlink_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "starlink_official",
    countryWeight: 100,
    cityWeight: 97,
    isSatellite: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://geoip.starlinkisp.net/feed.csv",
      },
    ],
  },
  {
    id: "viasat_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "viasat_official",
    countryWeight: 99,
    cityWeight: 96,
    isSatellite: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/Viasat/geofeed/main/geofeed.csv",
      },
    ],
  },
  {
    id: "netflix_openconnect_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "netflix_official",
    countryWeight: 99,
    cityWeight: 96,
    isCdn: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/Netflix/nflx-geofeed/main/geofeed.csv",
      },
    ],
  },
  {
    id: "upcloud_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "upcloud_official",
    countryWeight: 99,
    cityWeight: 97,
    isHosting: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://upcloud.com/geofeed.csv",
      },
    ],
  },
  {
    id: "cherryservers_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "cherryservers_official",
    countryWeight: 99,
    cityWeight: 97,
    isHosting: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://geofeed.cherryservers.com/geofeed.csv",
      },
    ],
  },
  {
    id: "hostinger_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "hostinger_official",
    countryWeight: 99,
    cityWeight: 97,
    isHosting: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/hostinger/geofeed/main/geofeed.csv",
      },
    ],
  },
  {
    id: "exoscale_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "exoscale_official",
    countryWeight: 99,
    cityWeight: 97,
    isHosting: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://exoscale-prefixes.sos.exo.io/exoscale_geofeed",
      },
    ],
  },
  {
    id: "clouvider_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "clouvider_official",
    countryWeight: 99,
    cityWeight: 97,
    isHosting: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://clouvider.com/geoipfeed.csv",
      },
    ],
  },
  {
    id: "tmobile_us_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "tmobile_official",
    countryWeight: 99,
    cityWeight: 96,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/tmobile/tmus-geofeed/main/tmus-geo-ip.txt",
      },
    ],
  },
  {
    id: "verizon_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "verizon_official",
    countryWeight: 99,
    cityWeight: 96,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/Verizon/verizon-geofeed/main/feed_5Ghome.csv",
      },
    ],
  },
  {
    id: "microsoft_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "microsoft_official",
    countryWeight: 99,
    cityWeight: 96,
    isHosting: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://download.microsoft.com/download/0b9dc6ca-68f9-43b2-b094-da4f6d509bc3/geoloc-Microsoft.csv",
      },
    ],
  },
  {
    id: "azure_service_tags",
    tier: "tier1_geofeed",
    format: "azure_service_tags_json",
    lineage: "microsoft_official",
    countryWeight: 98,
    cityWeight: 95,
    isHosting: true,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519",
      },
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/endgor/azure-hub/main/public/data/AzureCloud.json",
      },
    ],
  },
  {
    id: "equinix_geofeed",
    tier: "tier1_geofeed",
    format: "rfc8805_csv",
    lineage: "equinix_official",
    countryWeight: 99,
    cityWeight: 97,
    isHosting: true,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/equinix/geofeed/main/geofeed.csv",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/equinix/geofeed@main/geofeed.csv",
      },
    ],
  },
];
