import type {
  MitmHostEntry,
  ModuleBodyRewriteOverride,
  ModuleHeaderRewriteOverride,
  ModuleMapLocalOverride,
  ModuleScriptOverride,
  ModuleUrlRewriteOverride,
} from "./adblock-schema.ts";

/**
 * Certificate-pinned, financial, password-vault, auth, and TLS-sensitive domains
 * (aligned with AdguardTeam/HttpsExclusions & CompatibilityIssues) that must always be
 * prefixed with `-` at the very front of `[MITM] hostname` in Adblock.sgmodule.
 */
export const MITM_EXCLUDED_HOSTS: readonly MitmHostEntry[] = [
  // Direct IP handshakes & Apple OS / iCloud / OCSP TLS-pinned infrastructure
  { pattern: "<ip-address>", rationale: "Avoid MITM on direct IP TLS handshakes" },
  { pattern: "*.apple.com", rationale: "Apple system services enforce TLS pinning" },
  { pattern: "apple.com", rationale: "Apple root domain enforces TLS pinning" },
  { pattern: "*.icloud.com", rationale: "iCloud sync enforces TLS pinning" },
  { pattern: "*.icloud.com.cn", rationale: "iCloud China GCBD sync enforces TLS pinning" },
  { pattern: "*.mzstatic.com", rationale: "App Store assets enforce strict cert validation" },
  { pattern: "*.cdn-apple.com", rationale: "Apple OS update CDN enforces cert pinning" },
  { pattern: "weatherkit.apple.com", rationale: "Apple WeatherKit enforces strict TLS pinning" },

  // Domestic & global payment rails, Chinese commercial banks, brokerages & crypto exchanges
  { pattern: "*.alipay.com", rationale: "Alipay payment gateway requires end-to-end TLS" },
  { pattern: "*.tenpay.com", rationale: "WeChat Pay gateway requires end-to-end TLS" },
  { pattern: "*.wechatpay.cn", rationale: "WeChat Pay API requires end-to-end TLS" },
  { pattern: "payapp.weixin.qq.com", rationale: "WeChat Pay merchant settlement endpoint" },
  { pattern: "*.unionpay.com", rationale: "UnionPay gateway requires end-to-end TLS" },
  { pattern: "*.95516.com", rationale: "UnionPay Cloud QuickPass enforces TLS pinning" },
  { pattern: "*.cmbchina.com", rationale: "China Merchants Bank enforces certificate pinning" },
  { pattern: "*.cmbimg.com", rationale: "China Merchants Bank static/app package verification" },
  { pattern: "*.icbc.com.cn", rationale: "ICBC banking portal enforces certificate pinning" },
  { pattern: "*.ccb.com", rationale: "China Construction Bank enforces certificate pinning" },
  { pattern: "*.abchina.com", rationale: "Agricultural Bank of China enforces cert pinning" },
  { pattern: "*.bankcomm.com", rationale: "Bank of Communications enforces certificate pinning" },
  {
    pattern: "*.bankcomm.cn",
    rationale: "Bank of Communications (.cn) credit card app enforces certificate pinning",
  },
  {
    pattern: "bankcomm.cn",
    rationale: "Bank of Communications (.cn) root domain enforces certificate pinning",
  },
  { pattern: "*.boc.cn", rationale: "Bank of China enforces certificate pinning" },
  { pattern: "*.psbc.com", rationale: "Postal Savings Bank enforces certificate pinning" },
  { pattern: "*.spdb.com.cn", rationale: "Shanghai Pudong Development Bank enforces TLS pinning" },
  { pattern: "*.spdbccc.com.cn", rationale: "SPDB Credit Card app enforces TLS pinning" },
  { pattern: "*.cib.com.cn", rationale: "Industrial Bank (CIB) enforces TLS pinning" },
  { pattern: "*.citicbank.com", rationale: "China CITIC Bank enforces TLS pinning" },
  { pattern: "*.ecitic.com", rationale: "CITIC financial group enforces TLS pinning" },
  { pattern: "*.pingan.com", rationale: "Ping An Bank / Insurance enforces TLS pinning" },
  { pattern: "*.pingan.com.cn", rationale: "Ping An Pocket Bank enforces TLS pinning" },
  { pattern: "*.cebbank.com", rationale: "China Everbright Bank enforces TLS pinning" },
  { pattern: "*.cmbc.com.cn", rationale: "China Minsheng Bank enforces TLS pinning" },
  { pattern: "*.cgbchina.com.cn", rationale: "China Guangfa Bank enforces TLS pinning" },
  { pattern: "*.hxb.com.cn", rationale: "Hua Xia Bank enforces TLS pinning" },
  { pattern: "*.bosc.cn", rationale: "Bank of Shanghai enforces TLS pinning" },
  { pattern: "*.mybank.cn", rationale: "MYbank enforces TLS pinning" },
  { pattern: "*.webank.com", rationale: "WeBank enforces TLS pinning" },
  { pattern: "*.futunn.com", rationale: "Futu brokerage trading enforces TLS integrity" },
  { pattern: "*.itigerup.com", rationale: "Tiger Brokers trading enforces TLS integrity" },
  { pattern: "*.paypal.com", rationale: "PayPal checkout and auth require unmodified TLS" },
  { pattern: "*.paypalobjects.com", rationale: "PayPal SDK assets require unmodified TLS" },
  { pattern: "*.stripe.com", rationale: "Stripe PCI-DSS payment API requires unmodified TLS" },
  {
    pattern: "*.braintreegateway.com",
    rationale: "Braintree tokenization requires unmodified TLS",
  },
  { pattern: "*.adyen.com", rationale: "Adyen payment gateway requires unmodified TLS" },
  { pattern: "*.wise.com", rationale: "Wise banking app enforces TLS pinning" },
  { pattern: "*.revolut.com", rationale: "Revolut banking app enforces TLS pinning" },
  { pattern: "*.hsbc.com", rationale: "HSBC banking portal enforces TLS pinning" },
  { pattern: "*.chase.com", rationale: "Chase banking portal enforces TLS pinning" },
  { pattern: "*.citibank.com", rationale: "Citibank portal enforces TLS pinning" },
  { pattern: "*.citi.com", rationale: "Citi banking portal enforces TLS pinning" },
  { pattern: "*.bankofamerica.com", rationale: "Bank of America enforces TLS pinning" },
  { pattern: "*.wellsfargo.com", rationale: "Wells Fargo enforces TLS pinning" },
  { pattern: "*.americanexpress.com", rationale: "American Express enforces TLS pinning" },
  { pattern: "*.visa.com", rationale: "Visa 3DS and payment network require unmodified TLS" },
  { pattern: "*.mastercard.com", rationale: "Mastercard network requires unmodified TLS" },
  { pattern: "*.binance.com", rationale: "Binance app enforces strict certificate pinning" },
  { pattern: "*.okx.com", rationale: "OKX app enforces strict certificate pinning" },
  { pattern: "*.coinbase.com", rationale: "Coinbase app enforces strict certificate pinning" },
  {
    pattern: "*.mexc.com",
    rationale: "MEXC crypto exchange API/app subdomains enforce TLS pinning (HttpsExclusions)",
  },
  {
    pattern: "mexc.com",
    rationale: "MEXC crypto exchange root domain enforces TLS pinning (HttpsExclusions)",
  },
  {
    pattern: "*.sberbank.ru",
    rationale:
      "Sberbank banking portal subdomains enforce TLS certificate pinning (HttpsExclusions)",
  },
  {
    pattern: "sberbank.ru",
    rationale:
      "Sberbank banking portal root domain enforces TLS certificate pinning (HttpsExclusions)",
  },
  {
    pattern: "*.tbank.ru",
    rationale: "T-Bank banking portal subdomains enforce TLS certificate pinning (HttpsExclusions)",
  },
  {
    pattern: "tbank.ru",
    rationale:
      "T-Bank banking portal root domain enforces TLS certificate pinning (HttpsExclusions)",
  },

  // Password vaults, encrypted mail & identity providers (AdGuard HttpsExclusions/sensitive.txt)
  { pattern: "*.1password.com", rationale: "1Password vault requires unmodified TLS" },
  { pattern: "*.bitwarden.com", rationale: "Bitwarden vault requires unmodified TLS" },
  { pattern: "*.dashlane.com", rationale: "Dashlane vault requires unmodified TLS" },
  { pattern: "*.lastpass.com", rationale: "LastPass vault requires unmodified TLS" },
  { pattern: "*.enpass.io", rationale: "Enpass vault requires unmodified TLS" },
  { pattern: "*.roboform.com", rationale: "RoboForm vault requires unmodified TLS" },
  { pattern: "*.proton.me", rationale: "Proton Mail/VPN enforces TLS certificate pinning" },
  { pattern: "*.protonmail.com", rationale: "Proton Mail enforces TLS certificate pinning" },
  { pattern: "*.protonvpn.com", rationale: "Proton VPN enforces TLS certificate pinning" },
  { pattern: "*.tutanota.com", rationale: "Tuta encrypted mail enforces TLS pinning" },
  { pattern: "*.fastmail.com", rationale: "Fastmail sensitive mail transport" },
  { pattern: "accounts.google.com", rationale: "Google OAuth/Passkey login (HttpsExclusions)" },
  { pattern: "console.cloud.google.com", rationale: "Google Cloud Console (HttpsExclusions)" },
  { pattern: "ssh.cloud.google.com", rationale: "Google Cloud Web SSH (HttpsExclusions)" },
  {
    pattern: "firestore.clients6.google.com",
    rationale: "Google Firestore gRPC/streaming breaks under MITM (HttpsExclusions)",
  },
  {
    pattern: "*.googleapis.com",
    rationale: "Google APIs and mobile/desktop SDKs enforce TLS certificate pinning",
  },
  {
    pattern: "googleapis.com",
    rationale: "Google APIs root domain enforces TLS certificate pinning",
  },
  { pattern: "login.microsoftonline.com", rationale: "Microsoft Entra ID OAuth/FIDO2 login" },
  { pattern: "login.live.com", rationale: "Microsoft account OAuth/Passkey login" },
  { pattern: "*.github.com", rationale: "Developer authentication and Git HTTPS endpoints" },
  { pattern: "github.com", rationale: "GitHub web Passkey/2FA authentication" },

  // AI desktop/mobile clients with TLS pinning (AdGuard HttpsExclusions/mac.txt)
  { pattern: "auth.openai.com", rationale: "OpenAI OAuth login breaks under MITM" },
  { pattern: "sentinel.openai.com", rationale: "OpenAI anti-abuse attestation breaks under MITM" },
  { pattern: "chatgpt.com", rationale: "ChatGPT macOS/iOS Atlas app TLS compatibility" },
  {
    pattern: "*.chatgpt.com",
    rationale: "ChatGPT macOS/iOS Atlas app subdomains TLS compatibility (HttpsExclusions)",
  },
  { pattern: "chat.openai.com", rationale: "ChatGPT client TLS compatibility" },
  {
    pattern: "*.chat.openai.com",
    rationale: "ChatGPT mobile/desktop client subdomains (ios.chat.openai.com) TLS compatibility",
  },
  { pattern: "oaistatic.com", rationale: "ChatGPT client static bundle integrity" },
  {
    pattern: "*.oaistatic.com",
    rationale: "ChatGPT static bundle CDN subdomains (cdn.oaistatic.com) TLS integrity",
  },
  { pattern: "*.anthropic.com", rationale: "Claude API and CLI require unmodified TLS streaming" },
  { pattern: "*.claude.ai", rationale: "Claude desktop/mobile app TLS compatibility" },

  // Encrypted messaging, DoH resolvers & pinned Chinese app endpoints
  { pattern: "web.whatsapp.com", rationale: "WhatsApp Web noise/TLS handshake" },
  { pattern: "*.whatsapp.net", rationale: "WhatsApp pinned transport" },
  { pattern: "*.signal.org", rationale: "Signal Messenger enforces strict TLS pinning" },
  { pattern: "*.telegram.org", rationale: "Telegram MTProto/HTTPS transport" },
  { pattern: "line.naver.jp", rationale: "LINE messaging transport (HttpsExclusions)" },
  {
    pattern: "*.line.naver.jp",
    rationale: "LINE gateway subdomains enforce TLS certificate pinning (HttpsExclusions)",
  },
  {
    pattern: "*.zoom.us",
    rationale: "Zoom client and subdomains enforce TLS certificate pinning (HttpsExclusions)",
  },
  {
    pattern: "zoom.us",
    rationale: "Zoom root domain enforces TLS certificate pinning (HttpsExclusions)",
  },
  {
    pattern: "*.mozilla.net",
    rationale: "Firefox add-on and update CDN subdomains enforce cert pinning (HttpsExclusions)",
  },
  {
    pattern: "mozilla.net",
    rationale: "Firefox add-on and update root domain enforces cert pinning (HttpsExclusions)",
  },
  {
    pattern: "static.tumblr.com",
    rationale: "Tumblr mobile client asset endpoint enforces TLS validation (HttpsExclusions)",
  },
  { pattern: "accounts.kakao.com", rationale: "Kakao authentication (HttpsExclusions)" },
  { pattern: "kauth.kakao.com", rationale: "Kakao OAuth (HttpsExclusions)" },
  { pattern: "pay.naver.com", rationale: "Naver Pay (HttpsExclusions)" },
  { pattern: "*.syncthing.net", rationale: "Syncthing mutual-TLS device relay (HttpsExclusions)" },
  { pattern: "dns.alidns.com", rationale: "Public DoH resolver must not be MITM'd" },
  { pattern: "doh.pub", rationale: "Public DoH resolver must not be MITM'd" },
  { pattern: "dns.google", rationale: "Public DoH resolver must not be MITM'd" },
  { pattern: "cloudflare-dns.com", rationale: "Public DoH resolver must not be MITM'd" },
  { pattern: "one.one.one.one", rationale: "Public DoH resolver must not be MITM'd" },
  { pattern: "dns.quad9.net", rationale: "Public DoH resolver must not be MITM'd" },
  {
    pattern: "*.biliapi.net",
    rationale: "Bilibili API/gRPC endpoints enforce TLS certificate pinning",
  },
  { pattern: "*.biliapi.com", rationale: "Bilibili API endpoints enforce TLS certificate pinning" },
  { pattern: "api.bilibili.com", rationale: "Bilibili REST API enforces TLS certificate pinning" },
  { pattern: "app.bilibili.com", rationale: "Bilibili app API enforces TLS certificate pinning" },
  {
    pattern: "*.xiaohongshu.com",
    rationale: "Xiaohongshu app/API endpoints (edith, rec, www) enforce TLS certificate pinning",
  },
  {
    pattern: "xiaohongshu.com",
    rationale: "Xiaohongshu root domain enforces TLS certificate pinning",
  },
  {
    pattern: "*.xhscdn.com",
    rationale: "Xiaohongshu media CDN enforces strict TLS validation",
  },
  {
    pattern: "*.beacon.qq.com",
    rationale: "Tencent Beacon telemetry SDK (otheve, mtteve) enforces TLS certificate pinning",
  },
  {
    pattern: "beacon.qq.com",
    rationale: "Tencent Beacon root domain enforces TLS certificate pinning",
  },
  {
    pattern: "*.snssdk.com",
    rationale:
      "User report: MITM on *.snssdk.com (example http://aweme.snssdk.com) prevents Douyin local services from loading",
  },
  {
    pattern: "snssdk.com",
    rationale:
      "User report: MITM on the snssdk.com root prevents Douyin local services from loading",
  },
  {
    pattern: "*.amemv.com",
    rationale:
      "Douyin (ByteDance) API endpoints enforce TLS certificate pinning; MITM breaks Douyin local services",
  },
  {
    pattern: "amemv.com",
    rationale: "Douyin (ByteDance) API root domain enforces TLS certificate pinning",
  },
  {
    pattern: "*.musical.ly",
    rationale: "ByteDance/TikTok legacy mobile API endpoints enforce TLS pinning (HttpsExclusions)",
  },
  {
    pattern: "musical.ly",
    rationale: "ByteDance/TikTok legacy root domain enforces TLS pinning (HttpsExclusions)",
  },
];

export const MITM_ADDED_HOSTS: readonly MitmHostEntry[] = [];

/**
 * Substrings identifying broken, overly broad, or banking-sensitive upstream module patterns to suppress.
 */
export const DISABLED_URL_PATTERNS: readonly string[] = [
  "^https?:\\/\\/202\\d\\.\\d{2}\\.\\d{2}",
  "/amdc/mobileDispatch",
  "/api/v\\d/movie/index_recommend",
  "/wp-json/",
  "j1\\.pupuapi\\.com/client/a朴朴",
  "朴朴超市",
  "grpc\\.biliapi\\.net",
  "app\\.biliapi\\.",
  "(?:app|api)\\.bilibili\\.com",
  "app\\.bilibili\\.com",
  "api\\.bilibili\\.com",
  // Strip Xiaohongshu / Redbook HTTPS MITM scripts & rewrites (TLS-pinned + heavy response payloads)
  "xiaohongshu\\.com",
  "xhscdn\\.com",
  "redbook",
  // Strip Google APIs and Tencent Beacon HTTPS MITM rewrites/scripts (TLS-pinned).
  // snssdk: user-reported Douyin local-service breakage. Do not assert certificate pinning.
  "youtubei\\.googleapis\\.com",
  "\\.googleapis\\.com/",
  "^https?://googleapis\\.com/",
  "beacon\\.qq\\.com",
  "gurd\\.snssdk\\.com",
  "\\.snssdk\\.com/",
  "\\.snssdk.com/",
  // Unescaped is.snssdk.com form is not covered by the escaped slash needles above.
  "^https?://is.snssdk.com/",
  // One upstream Map Local alternation; slash needles miss HTTP aweme.snssdk.com /api and /motor paths.
  "(amemv|musical|snssdk|tiktokv)\\.com/",
  "amemv\\.com",
  // Prevent Kelee broad Alibaba CDN image-dimension regexes from breaking Taobao/Alipay UI icons
  "gw\\.alicdn\\.com/mt/",
  "gw\\.alicdn\\.com/tfs/",
  "gw\\.alicdn\\.com/tps/",
  "gw\\.alicdn\\.com\\/mt\\/",
  "gw\\.alicdn\\.com\\/tfs\\/",
  "gw\\.alicdn\\.com\\/tps\\/",
  // Prevent whole-host Map-Local without URL path from breaking J&T Express parcel mini-program
  "applets\\.jtexpress\\.com\\.cn$",
  "^https?:\\/\\/applets\\.jtexpress\\.com\\.cn$",
  // Never mutate GitHub Accept-Language headers or banking/payment endpoints inside adblock module
  "githubusercontent\\.com",
  "^https?:\\/\\/github\\.com\\/",
  "cmbimg\\.com",
  "cmbchina\\.com",
  "cloud\\.ccb\\.com",
  "icbc\\.com\\.cn",
  "abchina\\.com",
  "spdb\\.com\\.cn",
  "spdbccc\\.com\\.cn",
  "pingan\\.com",
  "ecitic\\.com",
  "cib\\.com\\.cn",
  "bankcomm\\.",
  // Prevent overly broad logical AND rules from blocking Volcengine Cloud, Douyin Live WebSocket, or core QUIC APIs
  "DOMAIN-KEYWORD,volc",
  "webcast100-ws-c-",
  "api100-normal-quic-",
  "api100-core-quic-",
  "api100-quic-",
  "frontier-aweme-",
  "frontier100-aweme",
  "DOMAIN-KEYWORD,-bjlgy",
];

export const MODULE_URL_REWRITES: readonly ModuleUrlRewriteOverride[] = [];

export const MODULE_MAP_LOCALS: readonly ModuleMapLocalOverride[] = [
  {
    pattern: "^https?:\\/\\/api\\.zhihu\\.com\\/commercial_api\\/real_time_launch_v2",
    dataType: "text",
    data: '{"launch":""}',
    statusCode: 200,
    header: "Content-Type: application/json; charset=utf-8",
    rationale: "Mock empty Zhihu splash payload without upstream round-trip or JS overhead",
  },
];

export const MODULE_HEADER_REWRITES: readonly ModuleHeaderRewriteOverride[] = [];

export const MODULE_BODY_REWRITES: readonly ModuleBodyRewriteOverride[] = [];

export const MODULE_SCRIPTS: readonly ModuleScriptOverride[] = [];
