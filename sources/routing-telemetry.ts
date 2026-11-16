import type { RoutingSourceEntry } from "./routing-schema.ts";

/**
 * Upstream sources for dist/Telemetry.list covering general overseas risk-control,
 * human-verification CAPTCHA challenges, IP-geolocation / fraud-scoring probes,
 * and cross-platform OS & SDK telemetry endpoints.
 */
export const TELEMETRY_ROUTING_SOURCES: readonly RoutingSourceEntry[] = [
  {
    id: "metacubex_hcaptcha",
    name: "MetaCubeX hcaptcha",
    target: "telemetry",
    lineage: "v2fly_dlc",
    format: "clash_classical",
    weight: 92,
    core: true,
    updateCadence: "6h",
    license: "GPL-3.0",
    homepage: "https://github.com/MetaCubeX/meta-rules-dat",
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/hcaptcha.list",
      },
      {
        kind: "direct",
        url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/classical/hcaptcha.list",
      },
    ],
  },
  {
    id: "metacubex_ip_geo_detect",
    name: "MetaCubeX category-ip-geo-detect (IP Risk & Geo Scoring)",
    target: "telemetry",
    lineage: "v2fly_dlc",
    format: "clash_classical",
    weight: 84,
    core: false,
    updateCadence: "6h",
    license: "GPL-3.0",
    homepage: "https://github.com/MetaCubeX/meta-rules-dat",
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-ip-geo-detect.list",
      },
    ],
    notes:
      "Routes overseas IP/fraud-scoring checks via clean exit while CN IP-lookup sites yield to Direct consensus",
  },
  {
    id: "badblock_captcha_repurposed",
    name: "BadBlock CAPTCHA Verification Allowlist (Repurposed for Risk-Control)",
    target: "telemetry",
    lineage: "celenityy_badblock",
    format: "domain_suffix_set",
    weight: 91,
    core: false,
    updateCadence: "daily",
    license: "GPL-3.0",
    homepage: "https://github.com/celenityy/BadBlock",
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/celenityy/BadBlock/pages/wildcards-no-star/captcha_whitelist.txt",
      },
    ],
    notes:
      "Repurposes curated CAPTCHA allowlist so human-verification challenges match clean exit IP",
  },
  {
    id: "metacubex_category_telemetry",
    name: "MetaCubeX category-telemetry (Overseas OS & SDK Telemetry)",
    target: "telemetry",
    lineage: "v2fly_dlc",
    format: "clash_classical",
    weight: 80,
    core: false,
    updateCadence: "6h",
    license: "GPL-3.0",
    homepage: "https://github.com/MetaCubeX/meta-rules-dat",
    endpoints: [
      {
        kind: "direct",
        url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-telemetry.list",
      },
    ],
    notes: "Pure ad trackers and CN domestic telemetry are automatically stripped at compile time",
  },
];
