import { CLEAN_STREAMING_EXCLUSION_SPECS } from "./routing-ai.ts";
import type { RoutingExclusionOverride, RoutingRuleOverride } from "./routing-schema.ts";

/**
 * Curated high-confidence entries for dist/Telemetry.list covering general risk-control,
 * fraud/device-intelligence engines, CAPTCHA & bot verification (Turnstile, Arkose, hCaptcha,
 * DataDome, PerimeterX), eKYC identity verification, IP fraud/geo scoring, and OS/SDK telemetry.
 */
export const TELEMETRY_FORCE_ENTRIES: readonly RoutingRuleOverride[] = [
  // General Risk-Control, Fraud Detection, Bot/CAPTCHA, eKYC & IP-Risk Scoring
  ...(
    [
      [
        "online-metrix.net",
        "LexisNexis ThreatMetrix device risk profiling used across fintech and web portals",
      ],
      ["threatmetrix.com", "LexisNexis ThreatMetrix fraud prevention service"],
      ["iesnare.com", "TransUnion iovation device intelligence beacon"],
      ["iovation.com", "TransUnion iovation fraud detection"],
      ["kount.com", "Equifax Kount fraud prevention"],
      ["sift.com", "Sift fraud and account-takeover detection"],
      ["siftscience.com", "Sift JavaScript risk telemetry SDK"],
      ["forter.com", "Forter e-commerce fraud decisioning"],
      ["riskified.com", "Riskified risk beacon"],
      ["signifyd.com", "Signifyd fraud protection"],
      ["sardine.ai", "Sardine device intelligence and fraud API"],
      ["castle.io", "Castle account-takeover risk API"],
      ["seon.io", "SEON fraud prevention"],
      ["socure.com", "Socure KYC and identity risk verification"],
      ["fpjs.io", "FingerprintJS Pro browser risk identification API"],
      ["fingerprint.com", "Fingerprint Pro fraud detection platform"],
      ["arkoselabs.com", "Arkose Labs FunCaptcha risk challenges"],
      ["funcaptcha.com", "Arkose Labs FunCaptcha verification assets"],
      ["hcaptcha.com", "hCaptcha anti-bot human verification"],
      ["challenges.cloudflare.com", "Cloudflare Turnstile human verification"],
      ["datadome.co", "DataDome bot and fraud protection"],
      ["perimeterx.net", "HUMAN (PerimeterX) bot and risk verification"],
      ["px-cdn.net", "HUMAN (PerimeterX) sensor script CDN"],
      ["px-cloud.net", "HUMAN (PerimeterX) risk telemetry collector"],
      ["kasada.io", "Kasada anti-automation risk verification"],
      ["incapsula.com", "Imperva Incapsula WAF challenge verification"],
      ["imperva.com", "Imperva security verification"],
      ["withpersona.com", "Persona KYC identity verification"],
      ["sumsub.com", "Sumsub KYC/AML identity verification"],
      ["veriff.com", "Veriff identity verification"],
      ["veriff.me", "Veriff live KYC session endpoint"],
      ["onfido.com", "Entrust Onfido identity verification"],
      ["jumio.com", "Jumio eKYC verification"],
      ["id.me", "ID.me digital identity verification"],
      ["scamalytics.com", "Scamalytics IP fraud-risk scoring API"],
      ["ipqualityscore.com", "IPQualityScore proxy/VPN/fraud risk scoring API"],
      ["spur.us", "Spur anonymous residential/VPN intelligence API"],
      ["ipinfo.io", "IPinfo geolocation and ASN risk check endpoint"],
      ["ipregistry.co", "Ipregistry IP reputation and proxy detection API"],
      ["ipdata.co", "ipdata IP threat and proxy intelligence API"],
      ["vpnapi.io", "VPNAPI proxy/VPN risk detection service"],
      ["proxycheck.io", "proxycheck.io VPN/proxy fraud scoring service"],
    ] as const
  ).map(
    ([value, rationale]): RoutingRuleOverride => ({
      target: "telemetry",
      kind: "DOMAIN-SUFFIX",
      value,
      extendedMatching: true,
      rationale,
    }),
  ),
  {
    target: "telemetry",
    kind: "DOMAIN",
    value: "openai-api.arkoselabs.com",
    extendedMatching: true,
    rationale: "Arkose Labs verification subdomain",
  },
  {
    target: "telemetry",
    kind: "DOMAIN",
    value: "client-api.arkoselabs.com",
    extendedMatching: true,
    rationale: "Shared Arkose Labs challenge widget host",
  },

  // General Cross-Platform Web, SDK & OS Attestation / Telemetry Endpoints
  {
    target: "telemetry",
    kind: "DOMAIN-KEYWORD",
    value: "sift",
    rationale: "Sift fraud-detection keyword",
  },
  {
    target: "telemetry",
    kind: "DOMAIN-KEYWORD",
    value: "honeycomb",
    rationale: "Honeycomb observability telemetry keyword",
  },
  {
    target: "telemetry",
    kind: "DOMAIN",
    value: "static.cloudflareinsights.com",
    rationale: "Cloudflare Web Analytics beacon script",
  },
  {
    target: "telemetry",
    kind: "DOMAIN",
    value: "cdn.usefathom.com",
    rationale: "Fathom Analytics web telemetry script",
  },
  {
    target: "telemetry",
    kind: "DOMAIN",
    value: "browser-intake-us5-datadoghq.com",
    rationale: "Datadog US5 browser RUM telemetry intake",
  },
  {
    target: "telemetry",
    kind: "DOMAIN",
    value: "rum.browser-intake-datadoghq.com",
    rationale: "Datadog global browser RUM telemetry intake",
  },
  {
    target: "telemetry",
    kind: "DOMAIN",
    value: "in.appcenter.ms",
    rationale: "Microsoft App Center SDK crash and telemetry intake",
  },
  {
    target: "telemetry",
    kind: "DOMAIN",
    value: "content-firebaseappcheck.googleapis.com",
    rationale: "Google Firebase App Check device attestation API",
  },
  {
    target: "telemetry",
    kind: "DOMAIN",
    value: "firebaseappcheck.googleapis.com",
    rationale: "Google Firebase App Check bot/device verification API",
  },
  {
    target: "telemetry",
    kind: "DOMAIN",
    value: "location.microsoft.com",
    rationale: "Microsoft OS/browser geolocation verification service",
  },
];

export const TELEMETRY_EXCLUDE_ENTRIES: readonly RoutingExclusionOverride[] =
  CLEAN_STREAMING_EXCLUSION_SPECS.map(([value, rationale]) => ({
    target: "telemetry",
    kind: "DOMAIN-SUFFIX",
    value,
    rationale,
  }));
