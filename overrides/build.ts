import { mkdir, readFile, writeFile } from "node:fs/promises";
import { isIP, isIPv4, isIPv6 } from "node:net";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ADBLOCK_OVERRIDES, GEOIP_OVERRIDES, ROUTING_OVERRIDES } from "./index.ts";
import type { RoutingRuleKind } from "./routing-schema.ts";

const ISO_ALPHA2_RE = /^[A-Z]{2}$/;
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const ROUTING_DOMAIN_RE =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9]{2,59})$/;
const ROUTING_TLD_RE = /^(?:[a-z]{2,63}|xn--[a-z0-9]{2,59})$/;
const WILDCARD_DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9*?[\]-]+\.)+[a-z*?]{2,63}$/;
const SCRIPT_NAME_RE = /^[A-Za-z0-9_.-]+$/;
const HEADER_FIELD_RE = /^[A-Za-z0-9-]+$/;
const FORBIDDEN_HEADERS = new Set(["content-length", "transfer-encoding"]);
const DISALLOWED_ISO = new Set(["XX", "ZZ", "AA", "OO", "UK"]);

function parseIpv4ToBigInt(ip: string): bigint {
  const parts = ip.split(".");
  if (parts.length !== 4) {
    throw new Error(`Invalid IPv4 address: ${ip}`);
  }
  let acc = 0n;
  for (const part of parts) {
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255 || String(n) !== part) {
      throw new Error(`Invalid IPv4 octet in ${ip}`);
    }
    acc = (acc << 8n) | BigInt(n);
  }
  return acc;
}

function parseIpv6ToBigInt(ip: string): bigint {
  const halves = ip.split("::");
  if (halves.length > 2) {
    throw new Error(`Invalid IPv6 address: ${ip}`);
  }
  const parseGroups = (segment: string): number[] => {
    if (segment === "") return [];
    const groups = segment.split(":");
    const out: number[] = [];
    for (let i = 0; i < groups.length; i++) {
      const g = groups[i] ?? "";
      if (i === groups.length - 1 && g.includes(".")) {
        const v4 = parseIpv4ToBigInt(g);
        out.push(Number((v4 >> 16n) & 0xffffn), Number(v4 & 0xffffn));
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(g)) {
          throw new Error(`Invalid IPv6 group '${g}' in ${ip}`);
        }
        out.push(Number.parseInt(g, 16));
      }
    }
    return out;
  };

  const left = parseGroups(halves[0] ?? "");
  const right = halves.length === 2 ? parseGroups(halves[1] ?? "") : [];
  const missing = 8 - (left.length + right.length);
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) {
    throw new Error(`Invalid IPv6 group count in ${ip}`);
  }
  const full = [...left, ...Array<number>(halves.length === 2 ? missing : 0).fill(0), ...right];
  let acc = 0n;
  for (const g of full) {
    acc = (acc << 16n) | BigInt(g);
  }
  return acc;
}

function validateCanonicalCidr(cidr: string, context: string): void {
  const slashIdx = cidr.indexOf("/");
  if (slashIdx <= 0 || slashIdx !== cidr.lastIndexOf("/")) {
    throw new Error(`[${context}] Invalid CIDR syntax: ${cidr}`);
  }
  const ip = cidr.slice(0, slashIdx);
  const prefixStr = cidr.slice(slashIdx + 1);
  if (!/^\d+$/.test(prefixStr)) {
    throw new Error(`[${context}] Invalid prefix length in ${cidr}`);
  }
  const prefix = Number(prefixStr);

  if (isIPv4(ip)) {
    if (prefix < 0 || prefix > 32) {
      throw new Error(`[${context}] IPv4 prefix out of range in ${cidr}`);
    }
    const val = parseIpv4ToBigInt(ip);
    const hostBits = BigInt(32 - prefix);
    const hostMask = hostBits === 32n ? 0xffffffffn : (1n << hostBits) - 1n;
    if ((val & hostMask) !== 0n) {
      throw new Error(`[${context}] Non-canonical IPv4 CIDR (host bits set): ${cidr}`);
    }
    return;
  }

  if (isIPv6(ip)) {
    if (prefix < 0 || prefix > 128) {
      throw new Error(`[${context}] IPv6 prefix out of range in ${cidr}`);
    }
    const val = parseIpv6ToBigInt(ip);
    const hostBits = BigInt(128 - prefix);
    const hostMask = hostBits === 128n ? (1n << 128n) - 1n : (1n << hostBits) - 1n;
    if ((val & hostMask) !== 0n) {
      throw new Error(`[${context}] Non-canonical IPv6 CIDR (host bits set): ${cidr}`);
    }
    if (context === "specialNetworks" && prefix <= 96) {
      // Ensure IPv4-in-IPv6 mount trees (::/96 and ::ffff:0:0/96) are not swallowed by a broad IPv6 bogon
      const v4CompatStart = 0n;
      const v4MappedStart = 0xffffn << 32n;
      const blockSize = hostBits === 128n ? 1n << 128n : 1n << hostBits;
      const blockEnd = val + blockSize - 1n;
      if (
        (val <= v4CompatStart && blockEnd >= v4CompatStart + 0xffffffffn) ||
        (val <= v4MappedStart && blockEnd >= v4MappedStart + 0xffffffffn)
      ) {
        throw new Error(
          `[${context}] IPv6 special network ${cidr} overlaps IPv4-in-IPv6 mount subtree`,
        );
      }
    }
    return;
  }

  throw new Error(`[${context}] Unrecognized IP address in CIDR: ${cidr}`);
}

function validateIsoCode(code: string | undefined, context: string): void {
  if (code === undefined) return;
  if (!ISO_ALPHA2_RE.test(code) || DISALLOWED_ISO.has(code)) {
    throw new Error(`[${context}] Invalid or non-canonical ISO 3166-1 alpha-2 code: ${code}`);
  }
}

function validateAll(): void {
  const seenSpecial = new Set<string>();
  for (const item of GEOIP_OVERRIDES.specialNetworks) {
    validateCanonicalCidr(item.cidr, "specialNetworks");
    if (seenSpecial.has(item.cidr)) {
      throw new Error(`[specialNetworks] Duplicate CIDR: ${item.cidr}`);
    }
    seenSpecial.add(item.cidr);
  }

  const seenCountry = new Set<string>();
  for (const item of GEOIP_OVERRIDES.countryOverrides) {
    validateCanonicalCidr(item.cidr, "countryOverrides");
    validateIsoCode(item.isoCode, `countryOverrides:${item.cidr}`);
    validateIsoCode(item.registeredIsoCode, `countryOverrides:${item.cidr}`);
    if (seenCountry.has(item.cidr)) {
      throw new Error(`[countryOverrides] Duplicate CIDR: ${item.cidr}`);
    }
    seenCountry.add(item.cidr);
  }

  const seenExclusions = new Set<string>();
  for (const item of GEOIP_OVERRIDES.cnExclusions) {
    validateCanonicalCidr(item.cidr, "cnExclusions");
    validateIsoCode(item.fallbackIsoCode, `cnExclusions:${item.cidr}`);
    if (seenExclusions.has(item.cidr)) {
      throw new Error(`[cnExclusions] Duplicate CIDR: ${item.cidr}`);
    }
    seenExclusions.add(item.cidr);
  }

  const seenAsns = new Set<number>();
  for (const item of GEOIP_OVERRIDES.asnOverrides) {
    if (!Number.isInteger(item.asn) || item.asn <= 0 || item.asn > 0xffffffff) {
      throw new Error(`[asnOverrides] Invalid ASN: ${item.asn}`);
    }
    validateIsoCode(item.countryHint, `asnOverrides:AS${item.asn}`);
    if (seenAsns.has(item.asn)) {
      throw new Error(`[asnOverrides] Duplicate ASN: AS${item.asn}`);
    }
    seenAsns.add(item.asn);
  }
}

function validateAdblockRegex(pattern: string, context: string): void {
  if (pattern.trim().length === 0 || /[\r\n\s]/.test(pattern)) {
    throw new Error(`[${context}] Invalid empty or whitespace regex: '${pattern}'`);
  }
  try {
    new RegExp(pattern);
  } catch (err) {
    throw new Error(`[${context}] Invalid regex '${pattern}': ${String(err)}`);
  }
}

function validateAdblockOverrides(): void {
  const seenAllow = new Set<string>();
  for (const item of ADBLOCK_OVERRIDES.allowDomains) {
    const dom = item.domain.toLowerCase();
    if (!DOMAIN_RE.test(dom)) {
      throw new Error(`[allowDomains] Invalid domain '${item.domain}'`);
    }
    const key = `${item.matchType}:${dom}`;
    if (seenAllow.has(key)) {
      throw new Error(`[allowDomains] Duplicate entry '${key}'`);
    }
    seenAllow.add(key);
  }

  const seenApex = new Set<string>();
  for (const item of ADBLOCK_OVERRIDES.protectedApexDomains) {
    const dom = item.domain.toLowerCase();
    if (!DOMAIN_RE.test(dom)) {
      throw new Error(`[protectedApexDomains] Invalid domain '${item.domain}'`);
    }
    if (seenApex.has(dom)) {
      throw new Error(`[protectedApexDomains] Duplicate domain '${dom}'`);
    }
    seenApex.add(dom);
  }

  for (const item of ADBLOCK_OVERRIDES.forceRuleSetEntries) {
    const v = item.value.trim();
    if (v.length === 0 || /[\r\n]/.test(v)) {
      throw new Error(`[forceRuleSetEntries] Invalid value '${item.value}'`);
    }
    switch (item.kind) {
      case "DOMAIN":
      case "DOMAIN-SUFFIX": {
        if (!DOMAIN_RE.test(v.toLowerCase())) {
          throw new Error(`[forceRuleSetEntries] Invalid domain for ${item.kind}: '${v}'`);
        }
        break;
      }
      case "DOMAIN-WILDCARD": {
        if (!WILDCARD_DOMAIN_RE.test(v.toLowerCase())) {
          throw new Error(`[forceRuleSetEntries] Invalid wildcard domain: '${v}'`);
        }
        break;
      }
      case "IP-CIDR":
      case "IP-CIDR6": {
        validateCanonicalCidr(v, "forceRuleSetEntries");
        break;
      }
      case "IP-ASN": {
        const asn = Number(v);
        if (!Number.isInteger(asn) || asn <= 0 || asn > 0xffffffff) {
          throw new Error(`[forceRuleSetEntries] Invalid IP-ASN: '${v}'`);
        }
        break;
      }
      case "DOMAIN-KEYWORD":
      case "USER-AGENT":
      case "PROCESS-NAME": {
        if (v.includes(",")) {
          throw new Error(`[forceRuleSetEntries] Comma disallowed in ${item.kind}: '${v}'`);
        }
        break;
      }
    }
  }

  for (const entry of [
    ...ADBLOCK_OVERRIDES.mitmExcludedHosts,
    ...ADBLOCK_OVERRIDES.mitmAddedHosts,
  ]) {
    const p = entry.pattern.trim();
    if (p.length === 0 || p === "*" || p.includes(",") || /[\r\n\s]/.test(p)) {
      throw new Error(`[mitmHosts] Invalid MITM host pattern '${entry.pattern}'`);
    }
    if (!p.startsWith("<") && !isIP(p) && p.includes(".") && p.split(".").length < 2) {
      throw new Error(`[mitmHosts] Bare TLD pattern not allowed: '${entry.pattern}'`);
    }
  }

  for (const rule of ADBLOCK_OVERRIDES.urlRewrites) {
    validateAdblockRegex(rule.pattern, "urlRewrites");
    if (rule.mode === "reject" && rule.replacement !== "_") {
      throw new Error("[urlRewrites] reject mode replacement must be '_'");
    }
  }

  for (const rule of ADBLOCK_OVERRIDES.mapLocals) {
    validateAdblockRegex(rule.pattern, "mapLocals");
    if (rule.statusCode !== undefined && (rule.statusCode < 200 || rule.statusCode > 999)) {
      throw new Error(`[mapLocals] Invalid HTTP statusCode: ${rule.statusCode}`);
    }
    if (rule.dataType === "text" && rule.data === undefined) {
      throw new Error("[mapLocals] dataType=text requires 'data'");
    }
  }

  for (const rule of ADBLOCK_OVERRIDES.headerRewrites) {
    validateAdblockRegex(rule.pattern, "headerRewrites");
    if (!HEADER_FIELD_RE.test(rule.field)) {
      throw new Error(`[headerRewrites] Invalid header field '${rule.field}'`);
    }
    if (FORBIDDEN_HEADERS.has(rule.field.toLowerCase())) {
      throw new Error(`[headerRewrites] Surge Header Rewrite forbids mutating '${rule.field}'`);
    }
  }

  for (const rule of ADBLOCK_OVERRIDES.bodyRewrites) {
    validateAdblockRegex(rule.pattern, "bodyRewrites");
    if (rule.expression.trim().length === 0 || /[\r\n]/.test(rule.expression)) {
      throw new Error("[bodyRewrites] Body rewrite expression must be single-line non-empty");
    }
  }

  const seenScripts = new Set<string>();
  for (const s of ADBLOCK_OVERRIDES.scripts) {
    if (!SCRIPT_NAME_RE.test(s.name)) {
      throw new Error(`[scripts] Invalid script name '${s.name}'`);
    }
    if (seenScripts.has(s.name)) {
      throw new Error(`[scripts] Duplicate script name '${s.name}'`);
    }
    seenScripts.add(s.name);
    validateAdblockRegex(s.pattern, `scripts:${s.name}`);
    const parsedUrl = new URL(s.scriptPath);
    if (parsedUrl.protocol !== "https:") {
      throw new Error(`[scripts:${s.name}] scriptPath must use HTTPS`);
    }
  }
}

async function emitOrCheckBundle(
  outPath: string,
  bundle: unknown,
  summary: string,
  checkMode: boolean,
): Promise<void> {
  const serialized = `${JSON.stringify(bundle, null, 2)}\n`;
  if (checkMode) {
    let existing: string;
    try {
      existing = await readFile(outPath, "utf8");
    } catch {
      throw new Error(
        `Missing generated overrides file at ${outPath}. Run 'bun run build:overrides'.`,
      );
    }
    if (existing !== serialized) {
      throw new Error(
        `Out-of-date ${outPath}. Run 'bun run build:overrides' and commit the updated file.`,
      );
    }
    console.log(`Verified ${summary}.`);
    return;
  }

  await mkdir(dirname(outPath), { recursive: true });
  await writeFile(outPath, serialized, "utf8");
  console.log(`Wrote ${outPath} (${serialized.length} bytes).`);
}

function validateRoutingRuleValue(kind: RoutingRuleKind, value: string, context: string): void {
  const v = value.trim();
  if (v.length === 0 || /[\r\n]/.test(v)) {
    throw new Error(`[${context}] Invalid empty or multiline value '${value}'`);
  }
  switch (kind) {
    case "DOMAIN": {
      if (!ROUTING_DOMAIN_RE.test(v.toLowerCase())) {
        throw new Error(`[${context}] Invalid DOMAIN '${v}'`);
      }
      break;
    }
    case "DOMAIN-SUFFIX": {
      const low = v.toLowerCase();
      if (!ROUTING_DOMAIN_RE.test(low) && !ROUTING_TLD_RE.test(low)) {
        throw new Error(`[${context}] Invalid DOMAIN-SUFFIX '${v}'`);
      }
      break;
    }
    case "DOMAIN-WILDCARD": {
      if (!WILDCARD_DOMAIN_RE.test(v.toLowerCase())) {
        throw new Error(`[${context}] Invalid DOMAIN-WILDCARD '${v}'`);
      }
      break;
    }
    case "IP-CIDR":
    case "IP-CIDR6": {
      validateCanonicalCidr(v, context);
      break;
    }
    case "IP-ASN": {
      const asn = Number(v);
      if (!Number.isInteger(asn) || asn <= 0 || asn > 0xffffffff) {
        throw new Error(`[${context}] Invalid IP-ASN '${v}'`);
      }
      break;
    }
    case "URL-REGEX": {
      validateAdblockRegex(v, context);
      break;
    }
    case "DOMAIN-KEYWORD":
    case "USER-AGENT":
    case "PROCESS-NAME": {
      if (v.includes(",")) {
        throw new Error(`[${context}] Comma disallowed in ${kind}: '${v}'`);
      }
      break;
    }
    case "AND": {
      validateLogicalAndValue(v, context);
      break;
    }
  }
}

const LOGICAL_AND_SUB_KINDS = new Set<string>([
  "DOMAIN",
  "DOMAIN-SUFFIX",
  "DOMAIN-KEYWORD",
  "DOMAIN-WILDCARD",
  "IP-CIDR",
  "IP-CIDR6",
  "IP-ASN",
  "URL-REGEX",
  "USER-AGENT",
  "PROCESS-NAME",
]);

const LOGICAL_EXTENDED_KINDS = new Set<string>([
  "DOMAIN",
  "DOMAIN-SUFFIX",
  "DOMAIN-KEYWORD",
  "DOMAIN-WILDCARD",
  "URL-REGEX",
]);

const LOGICAL_IP_KINDS = new Set<string>(["IP-CIDR", "IP-CIDR6", "IP-ASN"]);

const FORBIDDEN_LOGICAL_TOKENS = new Set<string>([
  "DIRECT",
  "PROXY",
  "REJECT",
  "REJECT-TINYGIF",
  "REJECT-DROP",
  "REJECT-NO-DROP",
  "FINAL",
  "PRE-MATCHING",
  "FORCE-REMOTE-DNS",
]);

function splitAtZeroDepthCommas(input: string, context: string): string[] {
  const parts: string[] = [];
  let start = 0;
  let paren = 0;
  let bracket = 0;
  let brace = 0;
  let inQuotes = false;
  let escaped = false;

  for (let i = 0; i < input.length; i += 1) {
    const ch = input[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (ch === '"' && paren === 0 && bracket === 0 && brace === 0) {
      inQuotes = !inQuotes;
      continue;
    }
    if (inQuotes) {
      continue;
    }
    if (ch === "(") {
      paren += 1;
    } else if (ch === ")") {
      paren -= 1;
      if (paren < 0) {
        throw new Error(`[${context}] Unbalanced ')' in AND value '${input}'`);
      }
    } else if (ch === "[") {
      bracket += 1;
    } else if (ch === "]") {
      bracket = Math.max(0, bracket - 1);
    } else if (ch === "{") {
      brace += 1;
    } else if (ch === "}") {
      brace = Math.max(0, brace - 1);
    } else if (ch === "," && paren === 0 && bracket === 0 && brace === 0) {
      parts.push(input.slice(i === start ? i : start, i).trim());
      start = i + 1;
    }
  }

  if (paren !== 0 || inQuotes || escaped) {
    throw new Error(`[${context}] Unterminated parenthesis or quotes in AND value '${input}'`);
  }
  parts.push(input.slice(start).trim());
  return parts;
}

function validateLogicalAndValue(raw: string, context: string): void {
  if (!raw.startsWith("((") || !raw.endsWith("))")) {
    throw new Error(`[${context}] AND value must start with '((' and end with '))': '${raw}'`);
  }
  const inner = raw.slice(1, -1).trim();
  const rawClauses = splitAtZeroDepthCommas(inner, context);
  if (rawClauses.length < 2) {
    throw new Error(`[${context}] AND rule must contain at least 2 sub-rules: '${raw}'`);
  }
  for (const rawClause of rawClauses) {
    if (!rawClause.startsWith("(") || !rawClause.endsWith(")")) {
      throw new Error(`[${context}] AND sub-rule must be parenthesized: '${rawClause}'`);
    }
    const body = rawClause.slice(1, -1).trim();
    const parts = splitAtZeroDepthCommas(body, context);
    if (parts.length < 2 || parts.length > 3) {
      throw new Error(
        `[${context}] AND sub-rule must have 2 or 3 comma-separated fields: '${rawClause}'`,
      );
    }
    const subKindRaw = parts[0] ?? "";
    const subVal = (parts[1] ?? "").trim();
    const subKind = subKindRaw.trim().toUpperCase();
    if (!LOGICAL_AND_SUB_KINDS.has(subKind)) {
      throw new Error(`[${context}] Unsupported AND sub-rule kind '${subKindRaw}'`);
    }
    if (FORBIDDEN_LOGICAL_TOKENS.has(subVal.toUpperCase())) {
      throw new Error(
        `[${context}] Policy or forbidden token disallowed in AND sub-rule: '${rawClause}'`,
      );
    }
    validateRoutingRuleValue(subKind as RoutingRuleKind, subVal, `${context}:AND:${subKind}`);
    if (parts.length === 3) {
      const opt = (parts[2] ?? "").trim();
      const optLower = opt.toLowerCase();
      if (FORBIDDEN_LOGICAL_TOKENS.has(opt.toUpperCase())) {
        throw new Error(
          `[${context}] Policy or forbidden option '${opt}' in AND sub-rule '${rawClause}'`,
        );
      }
      if (LOGICAL_IP_KINDS.has(subKind)) {
        if (optLower !== "no-resolve") {
          throw new Error(`[${context}] IP sub-rule option must be 'no-resolve', got '${opt}'`);
        }
      } else if (LOGICAL_EXTENDED_KINDS.has(subKind)) {
        if (optLower !== "extended-matching") {
          throw new Error(
            `[${context}] Sub-rule '${subKind}' option must be 'extended-matching', got '${opt}'`,
          );
        }
      } else {
        throw new Error(`[${context}] Sub-rule '${subKind}' does not accept option '${opt}'`);
      }
    }
  }
}

function routingDedupKey(target: string, kind: RoutingRuleKind, value: string): string {
  const caseSensitive =
    kind === "PROCESS-NAME" || kind === "USER-AGENT" || kind === "URL-REGEX" || kind === "AND";
  const norm = caseSensitive ? value.trim() : value.trim().toLowerCase();
  return `${target}:${kind}:${norm}`;
}

function validateRoutingOverrides(): void {
  const seenInfra = new Set<string>();
  for (const item of ROUTING_OVERRIDES.sharedInfraRoots) {
    const dom = item.domain.toLowerCase();
    if (!ROUTING_DOMAIN_RE.test(dom)) {
      throw new Error(`[sharedInfraRoots] Invalid domain '${item.domain}'`);
    }
    if (seenInfra.has(dom)) {
      throw new Error(`[sharedInfraRoots] Duplicate domain '${dom}'`);
    }
    if (item.rationale.trim().length === 0) {
      throw new Error(`[sharedInfraRoots:${dom}] Rationale must not be empty`);
    }
    seenInfra.add(dom);
  }

  const seenForce = new Set<string>();
  for (const item of ROUTING_OVERRIDES.forceEntries) {
    if (item.rationale.trim().length === 0) {
      throw new Error(`[routingForce:${item.target}:${item.value}] Rationale must not be empty`);
    }
    validateRoutingRuleValue(item.kind, item.value, `routingForce:${item.target}:${item.kind}`);
    if (
      item.extendedMatching &&
      !["DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "URL-REGEX"].includes(
        item.kind,
      )
    ) {
      throw new Error(
        `[routingForce:${item.kind}] extendedMatching is unsupported on ${item.kind}`,
      );
    }
    const key = routingDedupKey(item.target, item.kind, item.value);
    if (seenForce.has(key)) {
      throw new Error(`[routingForce] Duplicate entry '${key}'`);
    }
    seenForce.add(key);
  }

  const seenExclude = new Set<string>();
  for (const item of ROUTING_OVERRIDES.excludeEntries) {
    if (item.rationale.trim().length === 0) {
      throw new Error(`[routingExclude:${item.target}:${item.value}] Rationale must not be empty`);
    }
    validateRoutingRuleValue(item.kind, item.value, `routingExclude:${item.target}:${item.kind}`);
    const key = routingDedupKey(item.target, item.kind, item.value);
    if (seenExclude.has(key)) {
      throw new Error(`[routingExclude] Duplicate entry '${key}'`);
    }
    seenExclude.add(key);
  }
}

async function main(): Promise<void> {
  validateAll();
  validateAdblockOverrides();
  validateRoutingOverrides();

  const currentDir = dirname(fileURLToPath(import.meta.url));
  const checkMode = process.argv.includes("--check");

  await emitOrCheckBundle(
    resolve(currentDir, "generated", "geoip-overrides.json"),
    GEOIP_OVERRIDES,
    `GeoIP overrides (${GEOIP_OVERRIDES.specialNetworks.length} special, ${GEOIP_OVERRIDES.countryOverrides.length} country, ${GEOIP_OVERRIDES.cnExclusions.length} CN exclusions, ${GEOIP_OVERRIDES.asnOverrides.length} ASN)`,
    checkMode,
  );
  await emitOrCheckBundle(
    resolve(currentDir, "generated", "adblock-overrides.json"),
    ADBLOCK_OVERRIDES,
    `Adblock overrides (${ADBLOCK_OVERRIDES.allowDomains.length} allow, ${ADBLOCK_OVERRIDES.protectedApexDomains.length} protected apex, ${ADBLOCK_OVERRIDES.forceRuleSetEntries.length} ruleset, ${ADBLOCK_OVERRIDES.mitmExcludedHosts.length} MITM exclusions)`,
    checkMode,
  );
  await emitOrCheckBundle(
    resolve(currentDir, "generated", "routing-overrides.json"),
    ROUTING_OVERRIDES,
    `Routing overrides (${ROUTING_OVERRIDES.sharedInfraRoots.length} shared infra roots, ${ROUTING_OVERRIDES.forceEntries.length} force, ${ROUTING_OVERRIDES.excludeEntries.length} exclude)`,
    checkMode,
  );
}

await main();
