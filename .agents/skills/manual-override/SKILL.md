---
name: manual-override
description: >-
  Add, update, or fix manual override rules (人工校正规则 / 手动校正规则) in surge-rules and push
  directly to main after local TypeScript validation. ALWAYS activate this skill whenever the user
  pastes Surge logs ([MITM] MITM failed, certificate pinning, [Rule], REJECT, SNI) or reports
  false-positive ad/privacy blocks (误报 / 误拦截 / 白名单 / 打不开), domains that cannot be MITM'd
  (不能 mitm / TLS pinning / 证书锁定), broken module rewrites/scripts (重写或脚本误伤), missed ad
  or tracker hosts (漏网广告 / 强制拦截), wrong routing classification (分流错误 / 直连或代理误判 /
  AI·Payment·Telemetry 归类错误), or wrong GeoIP country/ASN/bogon data (IP 归属地错误 / CN 误判).
  Do NOT use for Rust engine refactors (src/), upstream catalog changes (sources/), or Worker code.
---

# Manual Override Fast-Response Workflow (`surge-rules`)

Respond to false positives, MITM pinning failures, routing misclassifications, and GeoIP data corrections by editing the declarative TypeScript override tables under `overrides/`, validating via local TypeScript checks only, and pushing straight to `main`.

## Hard Execution Rules

1. **Touch `overrides/` only**: Edit `overrides/*.ts` and regenerate `overrides/generated/*.json`. Never edit `src/**/*.rs` or `tests/**/*.rs` for routine manual corrections.
2. **Local TS validation only**: Only `bun run format`, `bun run build:overrides`, and `bun run check` are required before pushing. **Do NOT** run `cargo test`, `cargo clippy`, `cargo build`, or `bun test` — GitHub Actions `Build & Release` handles full compilation, verification, and R2 publishing automatically on push to `main`.
3. **Direct push to `main`**: Commit directly on `main` and `git push origin main`. **Do NOT** create feature branches or Pull Requests.
4. **Stage explicit paths only**: Always `git add` the exact `overrides/<file>.ts` and `overrides/generated/<bundle>.json` files modified. **Never** run `git add -A` or `git add .`.

---

## Step 1: Diagnose Input & Map to Override Table

Before adding entries, search `overrides/` (`grep -rn "<domain-or-cidr>" overrides/`) to avoid duplicates or conflicting rules.

| Symptom / User Report | File to Edit | Exported Constant & Entry Shape |
| :--- | :--- | :--- |
| **Adblock / Privacy false positive** (legitimate site, API, CDN, shop, live stream, or login blocked) | `overrides/adblock-allowlist.ts` | `ALLOW_DOMAINS`: `{ matchType: "suffix" \| "exact", domain, rationale }` (Tier P0a — unblocks in both `Adblock.list` and `Privacy.list`). |
| **Shared multi-service root domain** (must never get blanket `DOMAIN-SUFFIX` block, while dedicated ad subdomains stay blockable) | `overrides/adblock-allowlist.ts` | `PROTECTED_APEX_DOMAINS`: `{ domain, rationale }` |
| **MITM TLS handshake failure / cert pinning** (`[MITM] MITM failed... certificate pinning`) | `overrides/adblock-module.ts` | 1. `MITM_EXCLUDED_HOSTS`: `{ pattern, rationale }` (no leading `-`).<br>2. Also add matching URL regex substrings to `DISABLED_URL_PATTERNS` if upstream modules inject `^https?://` rewrites/scripts for that domain. |
| **Upstream module URL/Header/Body/MapLocal/Script breaks app or UI** | `overrides/adblock-module.ts` | `DISABLED_URL_PATTERNS` (literal substring matched via `.contains()` against upstream rule/pattern strings), or top-weight (200) overrides in `MODULE_MAP_LOCALS`, `MODULE_URL_REWRITES`, `MODULE_HEADER_REWRITES`, `MODULE_BODY_REWRITES`, `MODULE_SCRIPTS`. |
| **Missed adware / pure-ad / tracker domain** | `overrides/adblock-ruleset.ts` | `ADBLOCK_FORCE_RULESET_ENTRIES` (`target: "ad"`) or `PRIVACY_FORCE_RULESET_ENTRIES` (`target: "privacy"`): `{ target, kind, value, rationale }` |
| **Routing misclassification** (`Direct` vs `Proxy` vs `AI` / `Payment` / `Telemetry`) | `overrides/routing-direct.ts`<br>`overrides/routing-proxy.ts`<br>`overrides/routing-ai.ts`<br>`overrides/routing-payment.ts`<br>`overrides/routing-telemetry.ts` | Add to `<TARGET>_FORCE_ENTRIES` (`{ target, kind, value, extendedMatching?, rationale }`) **and** add to `<WRONG_TARGET>_EXCLUDE_ENTRIES` (`{ target, kind, value, rationale }`) when upstream feeds pull it into the wrong list. |
| **GeoIP wrong country / Anycast / CN leak** | `overrides/geoip-country.ts` | `COUNTRY_OVERRIDES` (exact canonical CIDR, `isoCode`, optional `registeredIsoCode`, `isp`, `organization`, `isAnycast`, `clearCity`, `rationale`) or `CN_EXCLUSIONS` (remove foreign CIDR from `Country-cn.mmdb`). |
| **GeoIP ASN metadata / bogon / mesh CIDR** | `overrides/geoip-asn.ts`<br>`overrides/special-networks.ts` | `ASN_OVERRIDES` (`asn`, `organization`, `isp`, `domain`, `countryHint`, `provinceHintZhCn`, `isHosting`, `isCdn`, `isAnycast`) or `SPECIAL_NETWORKS`. |

### Key Scoping & Granularity Guidelines

#### 1. Parsing Surge `[MITM]` Logs & Choosing Exclusion Scope
Surge MITM failure logs typically show two host clues:
- `[TLS] TLS Client Hello SNI: otheve.beacon.qq.com` → concrete failing hostname.
- `[MITM] Enable MITM due to MITM hostname settings entry: *.beacon.qq.com (surge-rules Adblock & Privacy)` → the `[MITM] hostname` wildcard in `Adblock.sgmodule` that triggered interception.

How to scope `MITM_EXCLUDED_HOSTS` (`overrides/adblock-module.ts`):
- **Whole-domain / SDK pinning** (e.g., `*.googleapis.com`, `*.beacon.qq.com`, `*.snssdk.com`, `*.xiaohongshu.com`, banking/payment domains): Exclude **both** `{ pattern: "*.<domain>", rationale: "..." }` and `{ pattern: "<domain>", rationale: "..." }`. Remove any pre-existing narrower exact entries in `MITM_EXCLUDED_HOSTS` now subsumed by `*.<domain>` (e.g., removing `instantmessaging-pa.googleapis.com` when adding `*.googleapis.com`).
- **Single-endpoint pinning on a host whose siblings still need MITM** (e.g., `auth.openai.com`, `payapp.weixin.qq.com`): Exclude only the exact hostname `{ pattern: "sub.example.com", rationale: "..." }`.
- **Companion `DISABLED_URL_PATTERNS` cleanup**: Check `dist/Adblock.sgmodule` (if present locally) for upstream `[URL Rewrite]`, `[Map Local]`, `[Header Rewrite]`, `[Body Rewrite]`, or `[Script]` patterns targeting the excluded domain (`grep -n "<domain>" dist/Adblock.sgmodule`). Add concise literal substrings (noting escaped `\\.` vs unescaped `.` in upstream regexes) to `DISABLED_URL_PATTERNS` so plain-HTTP or broad `^https?://` patterns are suppressed too.

#### 2. Choosing `"suffix"` vs `"exact"` in `ALLOW_DOMAINS`
- Use `matchType: "suffix"` for dedicated service domains or tenant-specific subdomains (e.g., `pay.ldxp.cn`, `cdn.sportnanoapi.com`, `api.rc-backup.com`, `tgbot-sub.sharewithyou.dpdns.org`).
- **Never** use `matchType: "suffix"` on multi-tenant public suffixes, shared DDNS parents, or shared CDNs (e.g., `dpdns.org`, `cc.cd`, `workers.dev`, `pages.dev`, `cloudfront.net`, `googleapis.com`, `qq.com`, `snssdk.com`, `aliyuncs.com`) — only allowlist the specific subdomain or use `matchType: "exact"`.
- Follow existing file convention at the bottom of `ALLOW_DOMAINS`: include a brief Chinese comment above newly added user-reported blocks if helpful, plus a clear English `rationale` field.

---

## Step 2: Enforce Compiler & CI Invariants

Because local Rust tests are intentionally skipped, double-check these invariants so remote CI (`Build & Release`) always succeeds on the first push:

1. **No Duplicate Keys**:
   - `ALLOW_DOMAINS` forbids duplicate `matchType:domain`.
   - `FORCE_RULESET_ENTRIES`, `ROUTING_OVERRIDES`, and `GEOIP_OVERRIDES` forbid duplicate entries.
2. **Strict Mutual Disjointness (`Adblock` ∩ `Privacy` ∩ `Telemetry` = ∅)**:
   - Never place the same or overlapping domain/suffix/CIDR in both `target: "ad"` and `target: "privacy"`.
   - `Telemetry.list` (`overrides/routing-telemetry.ts`) must **never** overlap with `Adblock.list` or `Privacy.list`. If adding a host to `TELEMETRY_FORCE_ENTRIES` that upstream adlists block, also add it to `ALLOW_DOMAINS` in `overrides/adblock-allowlist.ts`. Never add a `Telemetry.list` domain to `overrides/adblock-ruleset.ts`.
3. **Routing Set Separation (`Direct` vs Clean-Egress `AI` / `Payment` / `Telemetry` vs `Proxy`)**:
   - `AI.list`, `Payment.list`, and `Telemetry.list` must be mutually disjoint (`build:overrides` rejects rules forced into more than one of `ai`, `payment`, `telemetry`), and `Proxy.list` automatically inherits 100% of them.
   - Clean-egress sets (`ai`, `payment`, `telemetry`) must **never** emit bare `DOMAIN-SUFFIX` for any domain in `SHARED_INFRA_ROOTS` (`googleapis.com`, `amazonaws.com`, `cloudflare.com`, `github.com`, `apple.com`, etc.) — use exact `DOMAIN` or composite `AND` with `PROCESS-NAME`.
   - Overseas streaming domains (`CLEAN_STREAMING_EXCLUSION_SPECS`) belong in `Proxy.list` only, never `AI` / `Payment` / `Telemetry` / `Direct`.
   - `Direct.list` and overseas `AI` / `Payment` / `Telemetry` / `Proxy` domains must not overlap; pair `<TARGET>_FORCE_ENTRIES` with `<OTHER>_EXCLUDE_ENTRIES` whenever upstream lists disagree.
4. **Canonical Syntax**:
   - Domains: lowercase ASCII/punycode, no scheme (`https://`), no path/port, no leading `.` or trailing `.`.
   - `MITM_EXCLUDED_HOSTS` / `MITM_ADDED_HOSTS`: no leading `-` (the compiler prepends `-` automatically for `MITM_EXCLUDED_HOSTS`), no `*`, `*.*`, `*:0`, bare TLDs, commas, or whitespace; `MITM_ADDED_HOSTS` additionally requires exact domains only (no wildcards `*` / `?`, `<...>`, or raw IPs).
   - CIDRs (`IP-CIDR`, `IP-CIDR6`, GeoIP overrides): strictly canonical network address with zero host bits set (e.g., `114.24.0.0/14`, never `114.24.0.1/14`).
   - Country codes: canonical uppercase ISO 3166-1 alpha-2 (`GB` instead of `UK`; `XX`, `ZZ`, `AA`, `OO` are disallowed) present in `metadata/generated/geoip-metadata.json`.
   - Every `rationale` field must be non-empty.

---

## Step 3: Regenerate & Run Local TypeScript Checks

Run these exact commands from the repository root:

```bash
bun run format
bun run build:overrides
bun run check
```

All three commands must exit `0`:
- `bun run build:overrides` validates schemas, regexes, CIDRs, deduplication, and clean-egress disjointness, then writes deterministic JSON to `overrides/generated/{geoip,adblock,routing}-overrides.json`.
- `bun run check` runs `tsc --noEmit`, `biome check`, `verify:sources`, `verify:overrides`, `verify:metadata`, and `verify:readme` in ~2–3 seconds.

---

## Step 4: Commit & Push Directly to `main`

1. Inspect `git status -sb` to verify you are on `main` and see which `overrides/` files changed.
2. Stage **only** the modified TypeScript source file(s) and regenerated JSON bundle(s):
   ```bash
   git add overrides/<edited-file>.ts overrides/generated/<updated-bundle>.json
   ```
3. Commit with a concise Conventional Commit message matching repository history:
   - `fix(adblock): ...`
   - `fix(routing): ...`
   - `fix(geoip): ...`
   Include brief bullet points in the commit body listing each domain/pattern/CIDR and why it was added.
4. Push directly to `origin/main`:
   ```bash
   git push origin main
   ```
   If `git push` fails due to a remote commit (e.g., automated README build timestamp sync), rebase cleanly and push again:
   ```bash
   git pull --rebase origin main
   bun run build:overrides && bun run check
   git push origin main
   ```
5. Report the pushed commit SHA, the modified files, and a brief summary to the user.

---

## Worked Examples

### Example A: Surge MITM Certificate-Pinning Log
**User input:**
> `21:24:01 [MITM] Enable MITM due to MITM hostname settings entry: *.googleapis.com (surge-rules Adblock & Privacy)`
> `21:24:01 [MITM] MITM failed. Client closed connection just after TLS handshake, it might because of certificate pinning.`
> `21:25:17 [TLS] TLS Client Hello SNI: otheve.beacon.qq.com`
> `21:25:17 [MITM] Enable MITM due to MITM hostname settings entry: *.beacon.qq.com`
> `21:25:52 [TLS] TLS Client Hello SNI: is.snssdk.com`
> `21:25:52 [MITM] Enable MITM due to MITM hostname settings entry: *.snssdk.com`
> 这几个域名属于不能 mitm，需要加入人工校正规则，push 到 main 分支去

**Action:**
1. Edit `overrides/adblock-module.ts`:
   - Add `*.googleapis.com` + `googleapis.com`, `*.beacon.qq.com` + `beacon.qq.com`, and `*.snssdk.com` + `snssdk.com` to `MITM_EXCLUDED_HOSTS` (replacing any narrower subsumed entry like `instantmessaging-pa.googleapis.com`).
   - Add upstream URL regex substrings (`"\\.googleapis\\.com/"`, `"beacon\\.qq\\.com"`, `"\\.snssdk\\.com/"`, etc.) to `DISABLED_URL_PATTERNS`.
2. Run `bun run format && bun run build:overrides && bun run check`.
3. Run `git add overrides/adblock-module.ts overrides/generated/adblock-overrides.json`, commit as `fix(adblock): exclude TLS-pinned googleapis.com, beacon.qq.com and snssdk.com from MITM`, and `git push origin main`.

### Example B: Adblock False-Positive Domain Report
**User input:**
> `pay.ldxp.cn` 和 `api.rc-backup.com` 被广告规则误杀导致无法下单和恢复内购，加白名单推送到 main

**Action:**
1. Edit `overrides/adblock-allowlist.ts`: append `{ matchType: "suffix", domain: "pay.ldxp.cn", rationale: "..." }` and `{ matchType: "suffix", domain: "api.rc-backup.com", rationale: "..." }` to `ALLOW_DOMAINS`.
2. Run `bun run format && bun run build:overrides && bun run check`.
3. Run `git add overrides/adblock-allowlist.ts overrides/generated/adblock-overrides.json`, commit as `fix(adblock): allowlist pay.ldxp.cn and api.rc-backup.com`, and `git push origin main`.
