import type { CnExclusionEntry, CountryOverrideEntry } from "./schema.ts";

/**
 * Tier-0 Human Country & Anycast Corrections.
 * Evaluated right after Priority-0 special/virtual mesh networks.
 */
export const COUNTRY_OVERRIDES: readonly CountryOverrideEntry[] = [
  // === Taiwan Chunghwa Telecom HiNet (Prevent CN administrative label conflation) ===
  {
    cidr: "114.24.0.0/14",
    isoCode: "TW",
    registeredIsoCode: "TW",
    isp: "Chunghwa Telecom",
    organization: "Chunghwa Telecom Co., Ltd.",
    rationale: "AS3462 HiNet Taiwan residential/broadband pool; separate from ISO CN",
  },
  {
    cidr: "168.95.0.0/16",
    isoCode: "TW",
    registeredIsoCode: "TW",
    isp: "Chunghwa Telecom",
    organization: "Chunghwa Telecom Co., Ltd.",
    rationale: "AS3462 HiNet DNS (168.95.1.1 / 168.95.192.1) and backbone space",
  },

  // === Mainland China Anycast Public Resolvers & HTTPDNS ===
  {
    cidr: "119.29.29.0/24",
    isoCode: "CN",
    registeredIsoCode: "CN",
    isp: "Tencent Cloud",
    organization: "DNSPod Public DNS",
    isAnycast: true,
    clearCity: true,
    rationale: "DNSPod Public DNS (119.29.29.29) mainland China anycast",
  },
  {
    cidr: "182.254.116.0/22",
    isoCode: "CN",
    registeredIsoCode: "CN",
    isp: "Tencent Cloud",
    organization: "DNSPod / Tencent HTTPDNS",
    isAnycast: true,
    clearCity: true,
    rationale: "Tencent HTTPDNS (182.254.116.116 / 182.254.118.119) mainland anycast",
  },
  {
    cidr: "223.5.5.0/24",
    isoCode: "CN",
    registeredIsoCode: "CN",
    isp: "Alibaba Cloud",
    organization: "Alibaba AliDNS",
    isAnycast: true,
    clearCity: true,
    rationale: "AliDNS primary IPv4 anycast block (223.5.5.5)",
  },
  {
    cidr: "223.6.6.0/24",
    isoCode: "CN",
    registeredIsoCode: "CN",
    isp: "Alibaba Cloud",
    organization: "Alibaba AliDNS",
    isAnycast: true,
    clearCity: true,
    rationale: "AliDNS secondary IPv4 anycast block (223.6.6.6)",
  },
  {
    cidr: "2400:3200::/32",
    isoCode: "CN",
    registeredIsoCode: "CN",
    isp: "Alibaba Cloud",
    organization: "Alibaba AliDNS IPv6",
    isAnycast: true,
    clearCity: true,
    rationale: "AliDNS IPv6 anycast block (2400:3200::1)",
  },
  {
    cidr: "114.114.114.0/24",
    isoCode: "CN",
    registeredIsoCode: "CN",
    isp: "Nanjing Xinfeng",
    organization: "114DNS Public Resolver",
    isAnycast: true,
    rationale: "114DNS mainland public resolver",
  },
  {
    cidr: "180.76.76.0/24",
    isoCode: "CN",
    registeredIsoCode: "CN",
    isp: "Baidu",
    organization: "Baidu Public DNS",
    isAnycast: true,
    clearCity: true,
    rationale: "Baidu Public DNS (180.76.76.76)",
  },
  {
    cidr: "1.12.12.0/24",
    isoCode: "CN",
    registeredIsoCode: "CN",
    isp: "Tencent Cloud",
    organization: "DNSPod Public DNS",
    isAnycast: true,
    clearCity: true,
    rationale: "DNSPod / Tencent Cloud Public DNS (1.12.12.12) mainland China anycast",
  },
  {
    cidr: "180.184.1.0/24",
    isoCode: "CN",
    registeredIsoCode: "CN",
    isp: "Volcano Engine",
    organization: "Volcengine TrafficRoute Public DNS",
    isAnycast: true,
    clearCity: true,
    rationale:
      "Volcengine / ByteDance TrafficRoute Public DNS primary block (180.184.1.1) mainland anycast",
  },
  {
    cidr: "180.184.2.0/24",
    isoCode: "CN",
    registeredIsoCode: "CN",
    isp: "Volcano Engine",
    organization: "Volcengine TrafficRoute Public DNS",
    isAnycast: true,
    clearCity: true,
    rationale:
      "Volcengine / ByteDance TrafficRoute Public DNS secondary block (180.184.2.2) mainland anycast",
  },

  // === Global Anycast Public Resolvers ===
  {
    cidr: "1.1.1.0/24",
    isoCode: "AU",
    registeredIsoCode: "AU",
    isp: "Cloudflare",
    organization: "APNIC and Cloudflare DNS Resolver project",
    isAnycast: true,
    clearCity: true,
    rationale: "Cloudflare 1.1.1.1 global anycast (APNIC research delegation)",
  },
  {
    cidr: "1.0.0.0/24",
    isoCode: "AU",
    registeredIsoCode: "AU",
    isp: "Cloudflare",
    organization: "Cloudflare, Inc.",
    isAnycast: true,
    clearCity: true,
    rationale: "Cloudflare 1.0.0.1 global anycast",
  },
  {
    cidr: "8.8.8.0/24",
    isoCode: "US",
    registeredIsoCode: "US",
    isp: "Google",
    organization: "Google Public DNS",
    isAnycast: true,
    clearCity: true,
    rationale: "Google Public DNS 8.8.8.8 global anycast",
  },
  {
    cidr: "8.8.4.0/24",
    isoCode: "US",
    registeredIsoCode: "US",
    isp: "Google",
    organization: "Google Public DNS",
    isAnycast: true,
    clearCity: true,
    rationale: "Google Public DNS 8.8.4.4 global anycast",
  },
  {
    cidr: "2001:4860:4860::/48",
    isoCode: "US",
    registeredIsoCode: "US",
    isp: "Google",
    organization: "Google Public DNS IPv6",
    isAnycast: true,
    clearCity: true,
    rationale: "Google Public DNS IPv6 global anycast",
  },
  {
    cidr: "2606:4700:4700::/48",
    isoCode: "US",
    registeredIsoCode: "US",
    isp: "Cloudflare",
    organization: "Cloudflare 1.1.1.1 IPv6",
    isAnycast: true,
    clearCity: true,
    rationale: "Cloudflare 2606:4700:4700::1111 global anycast",
  },

  // === Telegram Messenger Data Centers (Physical DC Deployment Countries) ===
  {
    cidr: "91.108.4.0/22",
    isoCode: "NL",
    organization: "Telegram Messenger Inc.",
    rationale: "Telegram DC2/DC4 Amsterdam deployment",
  },
  {
    cidr: "91.108.8.0/22",
    isoCode: "NL",
    organization: "Telegram Messenger Inc.",
    rationale: "Telegram DC4 Amsterdam deployment",
  },
  {
    cidr: "91.108.12.0/22",
    isoCode: "US",
    organization: "Telegram Messenger Inc.",
    rationale: "Telegram DC1/DC3 Miami deployment",
  },
  {
    cidr: "91.108.16.0/22",
    isoCode: "NL",
    organization: "Telegram Messenger Inc.",
    rationale: "Telegram DC2/DC4 Amsterdam deployment",
  },
  {
    cidr: "91.108.20.0/22",
    isoCode: "NL",
    organization: "Telegram Messenger Inc.",
    rationale: "Telegram Amsterdam deployment",
  },
  {
    cidr: "91.108.56.0/22",
    isoCode: "SG",
    organization: "Telegram Messenger Inc.",
    rationale: "Telegram DC5 Singapore deployment",
  },
  {
    cidr: "91.105.192.0/23",
    isoCode: "NL",
    organization: "Telegram Messenger Inc.",
    rationale: "Telegram Amsterdam deployment",
  },
  {
    cidr: "149.154.160.0/21",
    isoCode: "NL",
    organization: "Telegram Messenger Inc.",
    rationale: "Telegram DC2/DC4 Amsterdam deployment",
  },
  {
    cidr: "149.154.168.0/22",
    isoCode: "SG",
    organization: "Telegram Messenger Inc.",
    rationale: "Telegram DC5 Singapore deployment",
  },
  {
    cidr: "149.154.172.0/22",
    isoCode: "US",
    organization: "Telegram Messenger Inc.",
    rationale: "Telegram DC1/DC3 Miami deployment",
  },
  {
    cidr: "185.76.151.0/24",
    isoCode: "NL",
    organization: "Telegram Messenger Inc.",
    rationale: "Telegram Amsterdam deployment",
  },
  {
    cidr: "95.161.64.0/20",
    isoCode: "NL",
    organization: "Telegram Messenger Inc.",
    rationale: "Telegram Amsterdam deployment (AS62041 TM-SUBNETS)",
  },
  {
    cidr: "2001:b28:f23d::/48",
    isoCode: "NL",
    organization: "Telegram Messenger Inc.",
    rationale: "Telegram DC2 Amsterdam IPv6",
  },
  {
    cidr: "2001:b28:f23f::/48",
    isoCode: "US",
    organization: "Telegram Messenger Inc.",
    rationale: "Telegram DC3 Miami IPv6",
  },
  {
    cidr: "2001:67c:4e8::/48",
    isoCode: "NL",
    organization: "Telegram Messenger Inc.",
    rationale: "Telegram DC4 Amsterdam IPv6",
  },
  {
    cidr: "2001:b28:f23c::/48",
    isoCode: "SG",
    organization: "Telegram Messenger Inc.",
    rationale: "Telegram DC5 Singapore IPv6",
  },
  {
    cidr: "2a0a:f280::/32",
    isoCode: "NL",
    organization: "Telegram Messenger Inc.",
    rationale: "Telegram global IPv6 allocation",
  },
];

/**
 * Mainland China High-Recall Exclusions.
 * Prevents foreign-deployed blocks mislisted in legacy CN CIDR sets from entering `Country-cn.mmdb`.
 */
export const CN_EXCLUSIONS: readonly CnExclusionEntry[] = [
  {
    cidr: "202.165.96.0/21",
    fallbackIsoCode: "US",
    asn: 10310,
    rationale: "AS10310 Yahoo/Oath overseas block historically mislisted in legacy CN CIDR sets",
  },
  {
    cidr: "202.165.104.0/22",
    fallbackIsoCode: "US",
    asn: 10310,
    rationale: "AS10310 Yahoo/Oath overseas block historically mislisted in legacy CN CIDR sets",
  },
  {
    cidr: "202.165.110.0/23",
    fallbackIsoCode: "US",
    asn: 10310,
    rationale: "AS10310 Yahoo/Oath overseas block historically mislisted in legacy CN CIDR sets",
  },
  {
    cidr: "103.10.124.0/23",
    fallbackIsoCode: "SG",
    asn: 32590,
    rationale: "Valve Steam APAC edge block outside Mainland China",
  },
  {
    cidr: "103.28.54.0/23",
    fallbackIsoCode: "HK",
    asn: 32590,
    rationale: "Valve Steam Hong Kong edge block outside Mainland China",
  },
  {
    cidr: "223.118.0.0/15",
    fallbackIsoCode: "HK",
    asn: 58453,
    rationale:
      "AS58453 China Mobile International (CMI-INT-AS-AP) Hong Kong/international backbone block",
  },
  {
    cidr: "223.120.0.0/17",
    fallbackIsoCode: "HK",
    asn: 58453,
    rationale:
      "AS58453 China Mobile International (CMI-INT-HK) Hong Kong block (preserving 223.120.128.0/17 CMNET)",
  },
  {
    cidr: "223.121.0.0/17",
    fallbackIsoCode: "HK",
    asn: 58453,
    rationale:
      "AS58453 China Mobile International (CMI-INT-HK) Hong Kong block (preserving 223.121.128.0/17 AS9808 CMNET)",
  },
];
