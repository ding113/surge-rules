import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { METADATA_UPSTREAMS } from "../metadata/sources.ts";
import type { AdblockSourceCatalogBundle, AdblockSourceEntry } from "../sources/adblock-schema.ts";
import type { RoutingSourceCatalogBundle, RoutingSourceEntry } from "../sources/routing-schema.ts";
import type {
  GeoIpSourceCatalogBundle,
  GeoIpSourceEntry,
  SourceEndpoint,
} from "../sources/schema.ts";

const START_MARKER = "<!-- sources:start -->";
const END_MARKER = "<!-- sources:end -->";

const GEOIP_AND_METADATA_TITLES: Readonly<Record<string, string>> = {
  geofeed_harvester: "Geofeed Harvester",
  opengeofeed: "Opengeofeed",
  ntt_gin_geofeed: "NTT GIN Geofeed",
  lacnic_geofeed: "LACNIC Geofeed",
  aws_ip_ranges: "AWS Official IP Ranges",
  aws_geofeed: "Aws Geofeed",
  gcp_cloud_ranges: "Gcp Cloud Ranges",
  gcp_cloud_geofeed: "Google Cloud Geofeed",
  google_corp_geofeed: "Google Corp Geofeed",
  google_vpn_geofeed: "Google VPN Geofeed",
  cloudflare_local_geofeed: "Cloudflare Local Geofeed",
  cloudflare_warp_geofeed: "Cloudflare Warp Geofeed",
  apple_icloud_private_relay: "Apple iCloud Private Relay Ranges",
  oracle_cloud_ranges: "Oracle Cloud Ranges",
  digitalocean_geofeed: "DigitalOcean Geofeed",
  akamai_geofeed: "Akamai Geofeed",
  linode_geofeed: "Akamai Linode Geofeed",
  hetzner_geofeed: "Hetzner Geofeed",
  vultr_geofeed: "Vultr Geofeed",
  starlink_geofeed: "Starlink Geofeed",
  viasat_geofeed: "Viasat Geofeed",
  netflix_openconnect_geofeed: "Netflix Openconnect Geofeed",
  upcloud_geofeed: "UpCloud Geofeed",
  cherryservers_geofeed: "Cherry Servers Geofeed",
  hostinger_geofeed: "Hostinger Geofeed",
  exoscale_geofeed: "Exoscale Geofeed",
  clouvider_geofeed: "Clouvider Geofeed",
  tmobile_us_geofeed: "T-Mobile US Geofeed",
  verizon_geofeed: "Verizon Geofeed",
  microsoft_geofeed: "Microsoft Geofeed",
  ip2region_v4: "lionsoul2014 ip2region IPv4",
  ip2region_v6: "lionsoul2014 ip2region IPv6",
  cz88_qqwry: "Cz88 Qqwry",
  openipdb: "Openipdb",
  gaoyifan_china_v4: "gaoyifan china-operator-ip China IPv4",
  gaoyifan_china_v6: "gaoyifan china-operator-ip China IPv6",
  gaoyifan_chinanet_v4: "gaoyifan china-operator-ip ChinaNet IPv4",
  gaoyifan_chinanet_v6: "gaoyifan china-operator-ip ChinaNet IPv6",
  gaoyifan_unicom_v4: "gaoyifan china-operator-ip Unicom IPv4",
  gaoyifan_unicom_v6: "gaoyifan china-operator-ip Unicom IPv6",
  gaoyifan_cmcc_v4: "gaoyifan china-operator-ip CMCC IPv4",
  gaoyifan_cmcc_v6: "gaoyifan china-operator-ip CMCC IPv6",
  gaoyifan_cernet: "gaoyifan china-operator-ip CERNET",
  gaoyifan_cstnet: "gaoyifan china-operator-ip CSTNET",
  gaoyifan_drpeng: "gaoyifan china-operator-ip Dr.Peng",
  metowolf_china: "Metowolf China",
  sukkaw_chnroutes2: "SukkaW chnroutes2",
  sukkaw_china_ipv6: "Sukkaw China Ipv6",
  heidai_china_v4: "217heidai RoutingRules China IPv4",
  hackl0us_geoip2_cn: "Hackl0us GeoIP2-CN",
  chanthmiao_cn_v4: "Chanthmiao Cn V4",
  chanthmiao_cn_v6: "Chanthmiao Cn V6",
  ipinfo_lite: "IPinfo Lite Country & ASN",
  maxmind_geolite2_city: "MaxMind GeoLite2 City / Country / ASN",
  dbip_city_lite: "DB-IP City Lite",
  dbip_country_lite: "DB-IP Country Lite",
  ip2location_db11: "Ip2Location Db11",
  ip2location_db1_official: "Ip2Location Db1 Official",
  ipfire_libloc: "IPFire Location Database",
  sapics_user_country: "Sapics User Country",
  iplocate_country: "IPLocate IP-to-Country",
  ipscope_lite: "IPScope Lite",
  ip66_mmdb: "ip66.dev GeoIP Database",
  sypex_geo_country: "Sypex Geo Country",
  bgptools_table: "bgp.tools Routing Table (with Alice39s/BGP.Tools-OpenDB mirror)",
  bgptools_asns: "bgp.tools ASN Registry (with Alice39s/BGP.Tools-OpenDB mirror)",
  ipverse_as_metadata: "ipverse AS Metadata",
  iptoasn_combined: "IPtoASN Combined Database",
  sapics_origin_asn: "Sapics Origin Asn",
  dbip_asn_lite: "DB-IP ASN Lite",
  iplocate_asn: "IPLocate IP-to-ASN",
  rir_apnic: "Rir Apnic",
  rir_arin: "Rir Arin",
  rir_ripencc: "Rir Ripencc",
  rir_lacnic: "Rir Lacnic",
  rir_afrinic: "Rir Afrinic",
  bgptools_anycast_v4: "bgp.tools Anycast Prefixes IPv4",
  bgptools_anycast_v6: "bgp.tools Anycast Prefixes IPv6",
  bgptools_tags_vpsh: "Alice39s BGP.Tools-OpenDB VPS & Hosting ASN Tags",
  bgptools_tags_cdn: "Alice39s BGP.Tools-OpenDB CDN ASN Tags",
  bgptools_tags_anycast: "Alice39s BGP.Tools-OpenDB Anycast ASN Tags",
  bgptools_tags_satnet: "Alice39s BGP.Tools-OpenDB Satellite Network ASN Tags",
  cloudflare_edge_v4: "Cloudflare Edge IPv4",
  cloudflare_edge_v6: "Cloudflare Edge IPv6",
  fastly_edge: "Fastly Public IP List",
  gcore_edge: "Gcore CDN Public IP List",
  github_meta: "GitHub Meta IP Ranges",
  hexydec_crawlers: "hexydec Verified Crawlers IP Ranges",
  tor_bulk_exits: "Tor Project Bulk Exit List",
  tor_onionoo: "Tor Project Onionoo Exit Summary",
  x4bnet_vpn_v4: "X4BNet VPN IPv4 List",
  x4bnet_datacenter_v4: "X4BNet Datacenter IPv4 List",
  josephrocca_vpn_v6: "josephrocca VPN & Datacenter IPv6",
  openproxydb: "NetworkCats OpenProxyDB",
  jhassine_datacenters: "jhassine Server & Datacenter IPs",
  sat_geoip_prefixes: "ipanalytics Sat-geoip Prefixes",
  sat_geoip_asns: "ipanalytics Sat-geoip Satellite ASNs",
  spamhaus_drop_v4: "Spamhaus DROP IPv4",
  spamhaus_drop_v6: "Spamhaus DROP IPv6",
  abusech_feodo: "abuse.ch Feodo Tracker IP Blocklist",
  geonames_country_info: "GeoNames Country Info",
  geonames_cities5000: "GeoNames Cities5000",
  mledoze_countries: "mledoze Countries",
  cldr_country_zh_cn: "CLDR Country List zh-CN (umpirsky)",
  cldr_country_en: "CLDR Country List en (umpirsky)",
  eu_membership: "dieghernan Country Codes & International Orgs",
  iana_zone1970: "IANA Time Zone Database zone1970",
  modood_cn_pca: "modood Administrative Divisions of China",
  areacity_cn_level3: "xiangyuecn AreaCity China Level-3 Divisions",
  dr5hn_states: "dr5hn Countries States Cities Database",
  debian_iso_3166_2: "Debian iso-codes ISO 3166-2",
  jsonmaur_aws_regions: "jsonmaur AWS Regions",
  azure_regions: "Green Software Foundation Azure Regions",
};

function endpointDisplayUrl(ep: SourceEndpoint | undefined, sourceId: string): string {
  if (!ep) {
    throw new Error(`[${sourceId}] Missing primary endpoint`);
  }
  switch (ep.kind) {
    case "direct":
      return ep.url;
    case "github_release":
      return `https://github.com/${ep.repo}/releases/latest`;
    case "npm_tarball":
      return `https://www.npmjs.com/package/${ep.package}`;
  }
}

function metadataDisplayUrl(rawUrl: string | undefined, sourceId: string): string {
  if (!rawUrl) {
    throw new Error(`[${sourceId}] Missing primary metadata URL`);
  }
  if (rawUrl.startsWith("github-release:")) {
    const rest = rawUrl.slice("github-release:".length);
    const sep = rest.indexOf(":");
    const repo = sep >= 0 ? rest.slice(0, sep) : rest;
    return `https://github.com/${repo}/releases/latest`;
  }
  return rawUrl;
}

function humanizeId(id: string): string {
  return id
    .split("_")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function renderDetailsBlock(titlePrefix: string, lines: readonly string[]): string {
  return [
    "<details>",
    `<summary>${titlePrefix}（共 ${lines.length} 项）</summary>`,
    "",
    "```text",
    ...lines,
    "```",
    "",
    "</details>",
  ].join("\n");
}

function formatNamedEntries(
  entries: readonly (AdblockSourceEntry | RoutingSourceEntry)[],
): string[] {
  return entries.map((src) => {
    const title = src.name ?? humanizeId(src.id);
    return `${title}, ${endpointDisplayUrl(src.endpoints[0], src.id)}`;
  });
}

function formatGeoIpAndMetadataEntries(geoSources: readonly GeoIpSourceEntry[]): string[] {
  const seenUrls = new Set<string>();
  const lines: string[] = [];

  for (const src of geoSources) {
    const url = endpointDisplayUrl(src.endpoints[0], src.id);
    if (seenUrls.has(url)) continue;
    seenUrls.add(url);
    const title = GEOIP_AND_METADATA_TITLES[src.id] ?? humanizeId(src.id);
    lines.push(`${title}, ${url}`);
  }

  for (const meta of METADATA_UPSTREAMS) {
    const url = metadataDisplayUrl(meta.urls[0], meta.id);
    if (seenUrls.has(url)) continue;
    seenUrls.add(url);
    const title = GEOIP_AND_METADATA_TITLES[meta.id] ?? humanizeId(meta.id);
    lines.push(`${title}, ${url}`);
  }

  return lines;
}

function getArgValue(flag: string): string | undefined {
  const idx = process.argv.indexOf(flag);
  if (idx >= 0) {
    return process.argv[idx + 1];
  }
  return undefined;
}

async function main(): Promise<void> {
  const scriptDir = dirname(fileURLToPath(import.meta.url));
  const repoRoot = resolve(scriptDir, "..");
  const checkMode = process.argv.includes("--check");
  const sourcesDir = resolve(
    repoRoot,
    getArgValue("--sources-dir") ?? resolve(repoRoot, "sources", "generated"),
  );
  const readmePath = resolve(repoRoot, getArgValue("--readme") ?? "README.md");

  const [adblockRaw, routingRaw, geoipRaw, currentReadme] = await Promise.all([
    readFile(resolve(sourcesDir, "adblock-sources.json"), "utf8"),
    readFile(resolve(sourcesDir, "routing-sources.json"), "utf8"),
    readFile(resolve(sourcesDir, "geoip-sources.json"), "utf8"),
    readFile(readmePath, "utf8"),
  ]);

  const adblock = JSON.parse(adblockRaw) as AdblockSourceCatalogBundle;
  const routing = JSON.parse(routingRaw) as RoutingSourceCatalogBundle;
  const geoip = JSON.parse(geoipRaw) as GeoIpSourceCatalogBundle;

  const complexLines = formatNamedEntries(
    adblock.sources.filter((s) => s.role === "complex_first"),
  );
  const adRulesetLines = formatNamedEntries(
    adblock.sources.filter(
      (s) => s.role === "ruleset_fallback" && (s.category === "ad" || s.category === "ad_mixed"),
    ),
  );
  const privacyRulesetLines = formatNamedEntries(
    adblock.sources.filter((s) => s.role === "ruleset_fallback" && s.category === "privacy"),
  );
  const allowlistLines = formatNamedEntries(adblock.sources.filter((s) => s.role === "allowlist"));
  const directLines = formatNamedEntries(routing.sources.filter((s) => s.target === "direct"));
  const aiLines = formatNamedEntries(routing.sources.filter((s) => s.target === "ai"));
  const paymentLines = formatNamedEntries(routing.sources.filter((s) => s.target === "payment"));
  const telemetryLines = formatNamedEntries(
    routing.sources.filter((s) => s.target === "telemetry"),
  );
  const proxyLines = formatNamedEntries(routing.sources.filter((s) => s.target === "proxy"));
  const geoLines = formatGeoIpAndMetadataEntries(geoip.sources);

  const renderedCatalog = [
    START_MARKER,
    renderDetailsBlock("去广告模块与高级重写数据源（Adblock.sgmodule）", complexLines),
    "",
    renderDetailsBlock("广告与安全威胁拦截数据源（Adblock.list）", adRulesetLines),
    "",
    renderDetailsBlock("隐私跟踪与遥测拦截数据源（Privacy.list）", privacyRulesetLines),
    "",
    renderDetailsBlock("去广告与隐私防误伤白名单数据源", allowlistLines),
    "",
    renderDetailsBlock("国内直连分流数据源（Direct.list）", directLines),
    "",
    renderDetailsBlock("境外 AI 应用数据源（AI.list）", aiLines),
    "",
    renderDetailsBlock("境外银行与支付数据源（Payment.list）", paymentLines),
    "",
    renderDetailsBlock("境外风控与遥测数据源（Telemetry.list）", telemetryLines),
    "",
    renderDetailsBlock("境外代理与流媒体数据源（Proxy.list）", proxyLines),
    "",
    renderDetailsBlock("GeoIP、ASN 与行政区划元数据数据源", geoLines),
    END_MARKER,
  ].join("\n");

  const startIdx = currentReadme.indexOf(START_MARKER);
  const endIdx = currentReadme.indexOf(END_MARKER);
  if (startIdx < 0 || endIdx < 0 || endIdx < startIdx) {
    throw new Error(
      `README.md is missing '${START_MARKER}' ... '${END_MARKER}' markers at ${readmePath}`,
    );
  }

  const nextReadme =
    currentReadme.slice(0, startIdx) +
    renderedCatalog +
    currentReadme.slice(endIdx + END_MARKER.length);

  const totalCount =
    complexLines.length +
    adRulesetLines.length +
    privacyRulesetLines.length +
    allowlistLines.length +
    directLines.length +
    aiLines.length +
    paymentLines.length +
    telemetryLines.length +
    proxyLines.length +
    geoLines.length;

  if (checkMode) {
    if (currentReadme !== nextReadme) {
      throw new Error(
        `Out-of-date source catalog in ${readmePath}. Run 'bun run build:readme' and commit the updated file.`,
      );
    }
    console.log(`Verified README.md source catalog in sync (${totalCount} entries).`);
    return;
  }

  if (currentReadme !== nextReadme) {
    await writeFile(readmePath, nextReadme, "utf8");
    console.log(`Updated ${readmePath} source catalog (${totalCount} entries).`);
  } else {
    console.log(`README.md source catalog already up to date (${totalCount} entries).`);
  }
}

await main();
