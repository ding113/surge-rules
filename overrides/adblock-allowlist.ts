import type { AllowDomainEntry, ProtectedApexDomainEntry } from "./adblock-schema.ts";

/**
 * False-positive allowlist domains evaluated above all fallback host and domain rules.
 */
export const ALLOW_DOMAINS: readonly AllowDomainEntry[] = [
  // OS connectivity & push notification endpoints
  {
    matchType: "exact",
    domain: "captive.apple.com",
    rationale: "Apple captive portal connectivity probe",
  },
  { matchType: "exact", domain: "time.apple.com", rationale: "Apple NTP time synchronization" },
  {
    matchType: "exact",
    domain: "msftconnecttest.com",
    rationale: "Microsoft Windows NCSI connectivity check",
  },
  {
    matchType: "exact",
    domain: "www.msftconnecttest.com",
    rationale: "Microsoft Windows NCSI connectivity check",
  },
  {
    matchType: "exact",
    domain: "connectivitycheck.gstatic.com",
    rationale: "Chromium and Android captive portal check",
  },
  { matchType: "exact", domain: "push.apple.com", rationale: "Apple Push Notification service" },
  { matchType: "exact", domain: "xp.apple.com", rationale: "Apple system experience endpoints" },
  { matchType: "exact", domain: "itunes.apple.com", rationale: "App Store and iTunes API" },
  { matchType: "suffix", domain: "icloud.com", rationale: "iCloud Drive, Mail, and Keychain sync" },
  {
    matchType: "suffix",
    domain: "mzstatic.com",
    rationale: "App Store and Apple Media static CDN",
  },
  {
    matchType: "suffix",
    domain: "cdn-apple.com",
    rationale: "Apple system software and App Store CDN",
  },
  {
    matchType: "exact",
    domain: "login.microsoftonline.com",
    rationale: "Microsoft Entra ID authentication",
  },
  { matchType: "exact", domain: "login.live.com", rationale: "Microsoft account authentication" },
  {
    matchType: "exact",
    domain: "dl.delivery.mp.microsoft.com",
    rationale: "Windows Update and Microsoft Store content delivery",
  },

  // Payment, developer assets, DoH endpoints & functional shortlinks
  { matchType: "suffix", domain: "alipay.com", rationale: "Alipay payment gateway and checkout" },
  { matchType: "suffix", domain: "tenpay.com", rationale: "WeChat Pay settlement endpoints" },
  {
    matchType: "suffix",
    domain: "githubusercontent.com",
    rationale: "GitHub raw assets and Surge module/script hosting",
  },
  { matchType: "exact", domain: "t.co", rationale: "X / Twitter external link resolver" },
  { matchType: "exact", domain: "bit.ly", rationale: "Bitly short URL resolution" },
  { matchType: "exact", domain: "tinyurl.com", rationale: "TinyURL link resolution" },
  { matchType: "exact", domain: "dns.alidns.com", rationale: "Alibaba public DoH endpoint" },
  { matchType: "exact", domain: "doh.pub", rationale: "DNSPod public DoH endpoint" },
  { matchType: "exact", domain: "dns.google", rationale: "Google public DoH endpoint" },
  {
    matchType: "exact",
    domain: "cloudflare-dns.com",
    rationale: "Cloudflare 1.1.1.1 DoH endpoint",
  },

  // App functional APIs cleaned at URL/body/script level inside Adblock.sgmodule
  {
    matchType: "exact",
    domain: "s.youtube.com",
    rationale: "YouTube playback watch history synchronization",
  },
  {
    matchType: "exact",
    domain: "video-stats.l.google.com",
    rationale: "YouTube watch progress synchronization",
  },
  {
    matchType: "exact",
    domain: "youtubei.googleapis.com",
    rationale: "YouTube Innertube API cleaned by Surge response script",
  },
  {
    matchType: "exact",
    domain: "api.bilibili.com",
    rationale: "Bilibili core API cleaned by module rules",
  },
  {
    matchType: "exact",
    domain: "app.bilibili.com",
    rationale: "Bilibili mobile feed/splash API cleaned by module rules",
  },
  {
    matchType: "exact",
    domain: "passport.bilibili.com",
    rationale: "Bilibili authentication endpoints",
  },
  {
    matchType: "exact",
    domain: "grpc.biliapi.net",
    rationale: "Bilibili gRPC protobuf API cleaned by module script",
  },
  {
    matchType: "exact",
    domain: "m.weibo.cn",
    rationale: "Weibo H5 API cleaned by module rewrite",
  },
  {
    matchType: "exact",
    domain: "api.weibo.cn",
    rationale: "Weibo mobile API cleaned by module script",
  },
  {
    matchType: "exact",
    domain: "edith.xiaohongshu.com",
    rationale: "Xiaohongshu feed API cleaned by module script",
  },
  { matchType: "exact", domain: "www.zhihu.com", rationale: "Zhihu web and question endpoints" },
  {
    matchType: "exact",
    domain: "api.zhihu.com",
    rationale: "Zhihu mobile API cleaned by module rewrite",
  },
  {
    matchType: "exact",
    domain: "acs.m.taobao.com",
    rationale: "Taobao MTOP gateway cleaned at path level by module",
  },
  { matchType: "exact", domain: "api.m.jd.com", rationale: "JD mobile gateway API" },
  {
    matchType: "exact",
    domain: "restapi.amap.com",
    rationale: "Amap navigation and geocoding API",
  },
  {
    matchType: "exact",
    domain: "m5.amap.com",
    rationale: "Amap route API cleaned at path level by module",
  },
  {
    matchType: "exact",
    domain: "mp.weixin.qq.com",
    rationale: "WeChat Official Account article reader",
  },
  {
    matchType: "exact",
    domain: "short.weixin.qq.com",
    rationale: "WeChat core messaging short-link transport",
  },
  {
    matchType: "exact",
    domain: "long.weixin.qq.com",
    rationale: "WeChat core messaging long-link transport",
  },
  {
    matchType: "exact",
    domain: "ad.12306.cn",
    rationale: "Railway 12306 splash delay bypass requires DIRECT rather than connection hang",
  },
  {
    matchType: "exact",
    domain: "pan.baidu.com",
    rationale: "Baidu Netdisk core API cleaned at path level by module",
  },
  {
    matchType: "exact",
    domain: "tieba.baidu.com",
    rationale: "Baidu Tieba web and API endpoints cleaned by module",
  },
  {
    matchType: "exact",
    domain: "tiebac.baidu.com",
    rationale: "Baidu Tieba mobile API cleaned by module",
  },

  // AI authentication, human-verification, and feature-gate endpoints
  {
    matchType: "suffix",
    domain: "oaistatsig.com",
    rationale: "OpenAI ChatGPT dedicated Statsig feature-flag endpoint",
  },
  {
    matchType: "suffix",
    domain: "statsig.anthropic.com",
    rationale: "Anthropic Claude feature-flag gateway",
  },
  {
    matchType: "suffix",
    domain: "featuregates.org",
    rationale: "OpenAI feature-gate and experimentation service",
  },
  {
    matchType: "exact",
    domain: "cdn.growthbook.io",
    rationale: "Claude Code GrowthBook feature-flag configuration CDN",
  },
  {
    matchType: "exact",
    domain: "challenges.cloudflare.com",
    rationale: "Cloudflare Turnstile human verification required by AI web logins",
  },
  {
    matchType: "exact",
    domain: "client-api.arkoselabs.com",
    rationale: "Arkose Labs challenge client required by OpenAI login flows",
  },
  {
    matchType: "exact",
    domain: "openai-api.arkoselabs.com",
    rationale: "OpenAI dedicated Arkose Labs verification API",
  },
];

/**
 * Multi-service apex domains that must never receive a blanket DOMAIN-SUFFIX rule.
 * Dedicated ad subdomains remain eligible for fallback RULE-SET blocking unless allowlisted.
 */
export const PROTECTED_APEX_DOMAINS: readonly ProtectedApexDomainEntry[] = [
  { domain: "apple.com", rationale: "Shared apex for macOS, iOS, iCloud, and App Store" },
  { domain: "google.com", rationale: "Shared apex for Search, Maps, Auth, and Workspace" },
  { domain: "googleapis.com", rationale: "Shared apex for Google Cloud, YouTube, and SDK APIs" },
  { domain: "gstatic.com", rationale: "Static assets, fonts, and captchas" },
  { domain: "youtube.com", rationale: "Core video web and embed domain" },
  { domain: "googlevideo.com", rationale: "Core YouTube video streaming CDN" },
  { domain: "ytimg.com", rationale: "Core YouTube thumbnails and UI assets" },
  { domain: "microsoft.com", rationale: "Windows, Office, Azure, and developer services" },
  { domain: "live.com", rationale: "Outlook, OneDrive, and Microsoft Auth" },
  { domain: "office.com", rationale: "Microsoft 365 productivity apps" },
  { domain: "github.com", rationale: "Git hosting and release infrastructure" },
  { domain: "cloudflare.com", rationale: "Cloudflare dashboard and edge services" },
  { domain: "fastly.net", rationale: "Multi-tenant edge CDN" },
  { domain: "akamaihd.net", rationale: "Multi-tenant edge CDN" },
  { domain: "amazonaws.com", rationale: "Multi-tenant cloud compute and S3 buckets" },
  { domain: "spotify.com", rationale: "Core music streaming service" },
  { domain: "scdn.co", rationale: "Spotify audio and artwork CDN" },
  { domain: "qq.com", rationale: "Shared Tencent QQ, WeChat Pay, and web services" },
  { domain: "weixin.qq.com", rationale: "WeChat messaging transport and articles" },
  { domain: "myqcloud.com", rationale: "Multi-tenant Tencent Cloud COS storage" },
  { domain: "gtimg.cn", rationale: "Tencent image and static CDN" },
  { domain: "163.com", rationale: "NetEase Mail and Music apex" },
  { domain: "126.net", rationale: "NetEase static CDN" },
  { domain: "bilibili.com", rationale: "Core video platform web and API" },
  { domain: "bilivideo.com", rationale: "Core Bilibili video stream CDN" },
  { domain: "hdslb.com", rationale: "Bilibili images, covers, and static JS/CSS" },
  { domain: "weibo.com", rationale: "Weibo core web platform" },
  { domain: "weibo.cn", rationale: "Weibo mobile API apex" },
  { domain: "sinaimg.cn", rationale: "Weibo media image CDN" },
  { domain: "zhihu.com", rationale: "Zhihu core web and API platform" },
  { domain: "xiaohongshu.com", rationale: "Xiaohongshu core web and API platform" },
  { domain: "xhscdn.com", rationale: "Xiaohongshu media CDN" },
  { domain: "douyin.com", rationale: "Douyin core video platform" },
  { domain: "amemv.com", rationale: "Douyin API gateway" },
  { domain: "taobao.com", rationale: "Taobao commerce apex" },
  { domain: "tmall.com", rationale: "Tmall commerce apex" },
  { domain: "alicdn.com", rationale: "Alibaba e-commerce static CDN" },
  { domain: "jd.com", rationale: "JD commerce apex" },
  { domain: "360buyimg.com", rationale: "JD product image CDN" },
  { domain: "pinduoduo.com", rationale: "Pinduoduo commerce apex" },
  { domain: "yangkeduo.com", rationale: "Pinduoduo mobile commerce apex" },
  { domain: "meituan.com", rationale: "Meituan local services apex" },
  { domain: "dianping.com", rationale: "Dianping reviews and local services apex" },
  { domain: "baidu.com", rationale: "Baidu Search, Tieba, and Netdisk apex" },
  { domain: "bdstatic.com", rationale: "Baidu static library CDN" },
  { domain: "amap.com", rationale: "Amap navigation apex" },
  { domain: "autonavi.com", rationale: "Amap map tiles and navigation apex" },
  { domain: "12306.cn", rationale: "China Railway 12306 ticketing apex" },
  { domain: "ximalaya.com", rationale: "Ximalaya audio apex" },
  { domain: "xmcdn.com", rationale: "Ximalaya audio stream CDN" },
  { domain: "smzdm.com", rationale: "SMZDM core platform apex" },
  { domain: "coolapk.com", rationale: "Coolapk community apex" },
  { domain: "hupu.com", rationale: "Hupu community apex" },
];
