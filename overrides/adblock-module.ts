import type {
  MitmHostEntry,
  ModuleBodyRewriteOverride,
  ModuleHeaderRewriteOverride,
  ModuleMapLocalOverride,
  ModuleScriptOverride,
  ModuleUrlRewriteOverride,
} from "./adblock-schema.ts";

/**
 * Certificate-pinned and financial/system domains that must always be prefixed with `-`
 * at the very front of `[MITM] hostname` in Adblock.sgmodule.
 */
export const MITM_EXCLUDED_HOSTS: readonly MitmHostEntry[] = [
  { pattern: "<ip-address>", rationale: "Avoid MITM on direct IP TLS handshakes" },
  { pattern: "*.apple.com", rationale: "Apple system services enforce TLS pinning" },
  { pattern: "*.icloud.com", rationale: "iCloud sync enforces TLS pinning" },
  { pattern: "*.mzstatic.com", rationale: "App Store assets enforce strict cert validation" },
  { pattern: "*.cdn-apple.com", rationale: "Apple OS update CDN enforces cert pinning" },
  { pattern: "*.alipay.com", rationale: "Payment gateway requires end-to-end TLS integrity" },
  { pattern: "*.tenpay.com", rationale: "WeChat Pay gateway requires end-to-end TLS integrity" },
  { pattern: "*.wechatpay.cn", rationale: "WeChat Pay API requires end-to-end TLS integrity" },
  { pattern: "*.unionpay.com", rationale: "UnionPay gateway requires end-to-end TLS integrity" },
  { pattern: "*.cmbchina.com", rationale: "Banking portal enforces certificate pinning" },
  { pattern: "*.icbc.com.cn", rationale: "Banking portal enforces certificate pinning" },
  { pattern: "*.ccb.com", rationale: "Banking portal enforces certificate pinning" },
  { pattern: "*.abchina.com", rationale: "Banking portal enforces certificate pinning" },
  { pattern: "*.bankcomm.com", rationale: "Banking portal enforces certificate pinning" },
  { pattern: "*.boc.cn", rationale: "Banking portal enforces certificate pinning" },
  { pattern: "*.psbc.com", rationale: "Banking portal enforces certificate pinning" },
  { pattern: "*.1password.com", rationale: "Password vault requires unmodified TLS" },
  { pattern: "*.bitwarden.com", rationale: "Password vault requires unmodified TLS" },
  { pattern: "*.github.com", rationale: "Developer authentication and Git SSH/HTTPS endpoints" },
  {
    pattern: "*.biliapi.net",
    rationale: "Bilibili API/gRPC endpoints enforce TLS certificate pinning",
  },
  { pattern: "*.biliapi.com", rationale: "Bilibili API endpoints enforce TLS certificate pinning" },
  { pattern: "api.bilibili.com", rationale: "Bilibili REST API enforces TLS certificate pinning" },
  { pattern: "app.bilibili.com", rationale: "Bilibili app API enforces TLS certificate pinning" },
  { pattern: "weatherkit.apple.com", rationale: "Apple WeatherKit enforces strict TLS pinning" },
  {
    pattern: "www.xiaohongshu.com",
    rationale: "Xiaohongshu endpoints enforce TLS certificate pinning",
  },
];

export const MITM_ADDED_HOSTS: readonly MitmHostEntry[] = [];

/**
 * Regex substrings identifying broken or overly risky upstream module patterns to suppress.
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
  "www\\.xiaohongshu\\.com",
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
