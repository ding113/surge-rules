import type { GeoIpSourceEntry } from "./schema.ts";

/**
 * Tier 2A: Mainland China Specialized Geolocation, ISP & Routing Datasets.
 */
export const TIER2A_CN_SOURCES: readonly GeoIpSourceEntry[] = [
  {
    id: "ip2region_v4",
    tier: "tier2a_cn",
    format: "xdb",
    lineage: "ip2region",
    countryWeight: 70,
    cnWeight: 90,
    cityWeight: 92,
    ispWeight: 92,
    core: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/ip2region_v4.xdb",
      },
    ],
  },
  {
    id: "ip2region_v6",
    tier: "tier2a_cn",
    format: "xdb",
    lineage: "ip2region",
    countryWeight: 70,
    cnWeight: 88,
    cityWeight: 90,
    ispWeight: 90,
    core: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v6.xdb",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/ip2region_v6.xdb",
      },
    ],
  },
  {
    id: "cz88_qqwry",
    tier: "tier2a_cn",
    format: "qqwry_dat",
    lineage: "cz88_qqwry",
    countryWeight: 65,
    cnWeight: 88,
    cityWeight: 88,
    ispWeight: 90,
    core: true,
    endpoints: [
      {
        kind: "github_release",
        repo: "metowolf/qqwry.dat",
        assetPattern: "^qqwry\\.dat$",
      },
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/nmgliangwei/qqwry/main/qqwry.dat",
      },
    ],
  },
  {
    id: "openipdb",
    tier: "tier2a_cn",
    format: "ipdb",
    lineage: "openipdb",
    countryWeight: 68,
    cnWeight: 89,
    cityWeight: 91,
    ispWeight: 90,
    core: true,
    endpoints: [
      {
        kind: "npm_tarball",
        package: "openipdb.ipdb",
        memberPath: "package/openipdb.ipdb",
      },
      {
        kind: "direct",
        url: "https://unpkg.com/openipdb.ipdb/openipdb.ipdb",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/npm/openipdb.ipdb@2026.7.26/openipdb.ipdb",
      },
    ],
  },
  {
    id: "gaoyifan_china_v4",
    tier: "tier2a_cn",
    format: "cidr_country",
    lineage: "gaoyifan_bgp_rir",
    cnWeight: 90,
    fixedCountry: "CN",
    core: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt",
      },
      {
        kind: "direct",
        url: "https://gaoyifan.github.io/china-operator-ip/china.txt",
      },
    ],
  },
  {
    id: "gaoyifan_china_v6",
    tier: "tier2a_cn",
    format: "cidr_country",
    lineage: "gaoyifan_bgp_rir",
    cnWeight: 90,
    fixedCountry: "CN",
    core: true,
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china6.txt",
      },
      {
        kind: "direct",
        url: "https://gaoyifan.github.io/china-operator-ip/china6.txt",
      },
    ],
  },
  {
    id: "gaoyifan_chinanet_v4",
    tier: "tier2a_cn",
    format: "cidr_isp",
    lineage: "gaoyifan_bgp_rir",
    ispWeight: 94,
    fixedIsp: "China Telecom",
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/chinanet.txt",
      },
    ],
  },
  {
    id: "gaoyifan_chinanet_v6",
    tier: "tier2a_cn",
    format: "cidr_isp",
    lineage: "gaoyifan_bgp_rir",
    ispWeight: 94,
    fixedIsp: "China Telecom",
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/chinanet6.txt",
      },
    ],
  },
  {
    id: "gaoyifan_unicom_v4",
    tier: "tier2a_cn",
    format: "cidr_isp",
    lineage: "gaoyifan_bgp_rir",
    ispWeight: 94,
    fixedIsp: "China Unicom",
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/unicom.txt",
      },
    ],
  },
  {
    id: "gaoyifan_unicom_v6",
    tier: "tier2a_cn",
    format: "cidr_isp",
    lineage: "gaoyifan_bgp_rir",
    ispWeight: 94,
    fixedIsp: "China Unicom",
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/unicom6.txt",
      },
    ],
  },
  {
    id: "gaoyifan_cmcc_v4",
    tier: "tier2a_cn",
    format: "cidr_isp",
    lineage: "gaoyifan_bgp_rir",
    ispWeight: 94,
    fixedIsp: "China Mobile",
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cmcc.txt",
      },
    ],
  },
  {
    id: "gaoyifan_cmcc_v6",
    tier: "tier2a_cn",
    format: "cidr_isp",
    lineage: "gaoyifan_bgp_rir",
    ispWeight: 94,
    fixedIsp: "China Mobile",
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cmcc6.txt",
      },
    ],
  },
  {
    id: "gaoyifan_cernet",
    tier: "tier2a_cn",
    format: "cidr_isp",
    lineage: "gaoyifan_bgp_rir",
    ispWeight: 94,
    fixedIsp: "CERNET",
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cernet46.txt",
      },
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cernet.txt",
      },
    ],
  },
  {
    id: "gaoyifan_cstnet",
    tier: "tier2a_cn",
    format: "cidr_isp",
    lineage: "gaoyifan_bgp_rir",
    ispWeight: 94,
    fixedIsp: "CSTNET",
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cstnet46.txt",
      },
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cstnet.txt",
      },
    ],
  },
  {
    id: "gaoyifan_drpeng",
    tier: "tier2a_cn",
    format: "cidr_isp",
    lineage: "gaoyifan_bgp_rir",
    ispWeight: 94,
    fixedIsp: "Dr.Peng",
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/drpeng46.txt",
      },
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/drpeng.txt",
      },
    ],
  },
  {
    id: "metowolf_china",
    tier: "tier2a_cn",
    format: "cidr_country",
    lineage: "openipdb",
    cnWeight: 88,
    fixedCountry: "CN",
    endpoints: [
      {
        kind: "direct",
        url: "https://metowolf.github.io/iplist/data/special/china.txt",
      },
    ],
  },
  {
    id: "sukkaw_chnroutes2",
    tier: "tier2a_cn",
    format: "cidr_country",
    lineage: "chnroutes2",
    cnWeight: 88,
    fixedCountry: "CN",
    endpoints: [
      {
        kind: "direct",
        url: "https://chnroutes2.cdn.skk.moe/reversed-chnroutes.txt",
      },
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt",
      },
    ],
  },
  {
    id: "sukkaw_china_ipv6",
    tier: "tier2a_cn",
    format: "cidr_country",
    lineage: "chnroutes2",
    cnWeight: 88,
    fixedCountry: "CN",
    endpoints: [
      {
        kind: "direct",
        url: "https://ruleset.skk.moe/Clash/ip/china_ip_ipv6.txt",
      },
    ],
  },
  {
    id: "ipip_17mon_china",
    tier: "tier2a_cn",
    format: "cidr_country",
    lineage: "ipip_17mon",
    cnWeight: 86,
    fixedCountry: "CN",
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt",
      },
    ],
  },
  {
    id: "hackl0us_geoip2_cn",
    tier: "tier2a_cn",
    format: "cidr_country",
    lineage: "ipip_17mon",
    cnWeight: 85,
    fixedCountry: "CN",
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/Hackl0us/GeoIP2-CN/release/CN-ip-cidr.txt",
      },
    ],
  },
  {
    id: "chanthmiao_cn_v4",
    tier: "tier2a_cn",
    format: "cidr_country",
    lineage: "chanthmiao_cn",
    cnWeight: 84,
    fixedCountry: "CN",
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/ChanthMiao/China-IPv4-List/release/cn.txt",
      },
    ],
  },
  {
    id: "chanthmiao_cn_v6",
    tier: "tier2a_cn",
    format: "cidr_country",
    lineage: "chanthmiao_cn",
    cnWeight: 84,
    fixedCountry: "CN",
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/ChanthMiao/China-IPv6-List/release/cn6.txt",
      },
    ],
  },
];
