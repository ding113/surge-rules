import type { GeoIpSourceEntry } from "./schema.ts";

/**
 * Network Trait & Risk Overlays (Anycast, CDN, VPN, Proxy, Tor, Satellite, Crawlers, DROP).
 */
export const TRAIT_OVERLAY_SOURCES: readonly GeoIpSourceEntry[] = [
  {
    id: "bgptools_anycast_v4",
    tier: "trait_overlay",
    format: "cidr_trait",
    lineage: "bgptools_anycast",
    isAnycast: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/bgptools/anycast-prefixes/master/anycatch-v4-prefixes.txt",
      },
    ],
  },
  {
    id: "bgptools_anycast_v6",
    tier: "trait_overlay",
    format: "cidr_trait",
    lineage: "bgptools_anycast",
    isAnycast: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/bgptools/anycast-prefixes/master/anycatch-v6-prefixes.txt",
      },
    ],
  },
  {
    id: "bgptools_tags_vpsh",
    tier: "trait_overlay",
    format: "bgptools_tag_csv",
    lineage: "bgptools_tags",
    isHosting: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/Alice39s/BGP.Tools-OpenDB/auto-update/tags/vpsh/tags-vpsh.csv",
      },
      {
        kind: "github_release",
        repo: "Alice39s/BGP.Tools-OpenDB",
        assetPattern: "^tags-vpsh-.*\\.csv\\.gz$",
      },
    ],
  },
  {
    id: "bgptools_tags_cdn",
    tier: "trait_overlay",
    format: "bgptools_tag_csv",
    lineage: "bgptools_tags",
    isCdn: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/Alice39s/BGP.Tools-OpenDB/auto-update/tags/cdn/tags-cdn.csv",
      },
      {
        kind: "github_release",
        repo: "Alice39s/BGP.Tools-OpenDB",
        assetPattern: "^tags-cdn-.*\\.csv\\.gz$",
      },
    ],
  },
  {
    id: "bgptools_tags_anycast",
    tier: "trait_overlay",
    format: "bgptools_tag_csv",
    lineage: "bgptools_tags",
    isAnycast: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/Alice39s/BGP.Tools-OpenDB/auto-update/tags/anycast/tags-anycast.csv",
      },
    ],
  },
  // NOTE: bgp.tools `vpn` / `tor` tags are intentionally NOT ingested. They are ASN-wide
  // "hosts such services" labels (e.g. AS37963/AS45102 Alibaba, Hetzner, OVH), so applying
  // them to every originated prefix flags whole clouds/ISPs (incl. 223.5.5.5 AliDNS) as
  // VPN/anonymous-proxy/Tor. Per-IP feeds (x4bnet, josephrocca, Tor exits, OpenProxyDB) cover these traits.
  {
    id: "bgptools_tags_satnet",
    tier: "trait_overlay",
    format: "bgptools_tag_csv",
    lineage: "bgptools_tags",
    isSatellite: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/Alice39s/BGP.Tools-OpenDB/auto-update/tags/satnet/tags-satnet.csv",
      },
    ],
  },
  {
    id: "cloudflare_edge_v4",
    tier: "trait_overlay",
    format: "cidr_trait",
    lineage: "cloudflare_official",
    isCdn: true,
    isAnycast: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://www.cloudflare.com/ips-v4",
      },
    ],
  },
  {
    id: "cloudflare_edge_v6",
    tier: "trait_overlay",
    format: "cidr_trait",
    lineage: "cloudflare_official",
    isCdn: true,
    isAnycast: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://www.cloudflare.com/ips-v6/",
      },
    ],
  },
  {
    id: "fastly_edge",
    tier: "trait_overlay",
    format: "fastly_json",
    lineage: "fastly_official",
    isCdn: true,
    isAnycast: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://api.fastly.com/public-ip-list",
      },
    ],
  },
  {
    id: "gcore_edge",
    tier: "trait_overlay",
    format: "gcore_json",
    lineage: "gcore_official",
    isHosting: true,
    isCdn: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://api.gcore.com/cdn/public-ip-list",
      },
    ],
  },
  {
    id: "github_meta",
    tier: "trait_overlay",
    format: "github_meta_json",
    lineage: "github_official",
    isHosting: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://api.github.com/meta",
      },
    ],
  },
  {
    id: "hexydec_crawlers",
    tier: "trait_overlay",
    format: "cidr_trait",
    lineage: "hexydec_crawlers",
    isCrawler: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/hexydec/ip-ranges/main/output/crawlers.txt",
      },
    ],
  },
  {
    id: "hexydec_datacentres",
    tier: "trait_overlay",
    format: "cidr_trait",
    lineage: "hexydec_crawlers",
    isHosting: true,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/hexydec/ip-ranges/main/output/datacentres.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/hexydec/ip-ranges@main/output/datacentres.txt",
      },
    ],
  },
  {
    id: "tor_bulk_exits",
    tier: "trait_overlay",
    format: "cidr_trait",
    lineage: "tor_official",
    isAnonymousProxy: true,
    isTorExit: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://check.torproject.org/torbulkexitlist",
      },
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst",
      },
    ],
  },
  {
    id: "tor_onionoo",
    tier: "trait_overlay",
    format: "onionoo_json",
    lineage: "tor_official",
    isAnonymousProxy: true,
    isTorExit: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://onionoo.torproject.org/summary?flag=Exit&running=true",
      },
    ],
  },
  {
    id: "x4bnet_vpn_v4",
    tier: "trait_overlay",
    format: "cidr_trait",
    lineage: "x4bnet_vpn",
    isVpn: true,
    isAnonymousProxy: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
      },
    ],
  },
  {
    id: "protonvpn_exit_v4",
    tier: "trait_overlay",
    format: "cidr_trait",
    lineage: "protonvpn_official",
    isVpn: true,
    isAnonymousProxy: true,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/tn3w/ProtonVPN-IPs/master/protonvpn_ip_ranges.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/tn3w/ProtonVPN-IPs@master/protonvpn_ip_ranges.txt",
      },
    ],
  },
  {
    id: "x4bnet_datacenter_v4",
    tier: "trait_overlay",
    format: "cidr_trait",
    lineage: "x4bnet_datacenter",
    isHosting: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt",
      },
    ],
  },
  {
    id: "josephrocca_vpn_v4",
    tier: "trait_overlay",
    format: "cidr_trait",
    lineage: "josephrocca_vpn",
    isHosting: true,
    core: false,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/josephrocca/is-vpn/main/vpn-or-datacenter-ipv4-ranges.txt",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/josephrocca/is-vpn@main/vpn-or-datacenter-ipv4-ranges.txt",
      },
    ],
  },
  {
    id: "josephrocca_vpn_v6",
    tier: "trait_overlay",
    format: "cidr_trait",
    lineage: "josephrocca_vpn",
    isHosting: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/josephrocca/is-vpn/main/vpn-or-datacenter-ipv6-ranges.txt",
      },
    ],
  },
  {
    id: "openproxydb",
    tier: "trait_overlay",
    format: "openproxydb_csv",
    lineage: "openproxydb",
    endpoints: [
      {
        kind: "github_release",
        repo: "NetworkCats/OpenProxyDB",
        assetPattern: "^proxy_blocks\\.csv$",
      },
    ],
  },
  {
    id: "jhassine_datacenters",
    tier: "trait_overlay",
    format: "cidr_trait",
    lineage: "jhassine_dc",
    isHosting: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.txt",
      },
    ],
  },
  {
    id: "sat_geoip_prefixes",
    tier: "trait_overlay",
    format: "sat_geoip_jsonl",
    lineage: "sat_geoip",
    isSatellite: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/ipanalytics/Sat-geoip/main/outputs/sat-geoip-prefixes.jsonl",
      },
    ],
  },
  {
    id: "sat_geoip_asns",
    tier: "trait_overlay",
    format: "sat_asns_csv",
    lineage: "sat_geoip",
    isSatellite: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/ipanalytics/Sat-geoip/main/outputs/satellite-asns.csv",
      },
    ],
  },
  {
    id: "spamhaus_drop_v4",
    tier: "trait_overlay",
    format: "spamhaus_drop",
    lineage: "spamhaus_drop",
    isMalware: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://www.spamhaus.org/drop/drop_v4.json",
      },
      {
        kind: "direct",
        url: "https://www.spamhaus.org/drop/drop.txt",
      },
    ],
  },
  {
    id: "spamhaus_drop_v6",
    tier: "trait_overlay",
    format: "spamhaus_drop",
    lineage: "spamhaus_drop",
    isMalware: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://www.spamhaus.org/drop/drop_v6.json",
      },
    ],
  },
  {
    id: "abusech_feodo",
    tier: "trait_overlay",
    format: "cidr_trait",
    lineage: "abusech",
    isMalware: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
      },
    ],
  },
];
