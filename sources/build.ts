import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { AdblockSourceEntry } from "./adblock-schema.ts";
import { ADBLOCK_SOURCES, GEOIP_SOURCES, ROUTING_SOURCES } from "./index.ts";
import type { RoutingSourceEntry, RoutingTarget } from "./routing-schema.ts";
import type { GeoIpSourceEntry, SourceEndpoint } from "./schema.ts";

const ID_RE = /^[a-z0-9_]+$/;
const ISO_ALPHA2_RE = /^[A-Z]{2}$/;
const GITHUB_REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const DISALLOWED_ISO = new Set(["XX", "ZZ", "AA", "OO", "UK"]);

function validateWeight(value: number | undefined, field: string, sourceId: string): void {
  if (value === undefined) return;
  if (!Number.isInteger(value) || value < 0 || value > 100) {
    throw new Error(`[${sourceId}] Weight '${field}' must be an integer in 0..100, got ${value}`);
  }
}

function validateIsoCode(code: string | undefined, sourceId: string): void {
  if (code === undefined) return;
  if (!ISO_ALPHA2_RE.test(code) || DISALLOWED_ISO.has(code)) {
    throw new Error(`[${sourceId}] Invalid or non-canonical ISO 3166-1 alpha-2 code: ${code}`);
  }
}

function validateEndpoint(ep: SourceEndpoint, sourceId: string, idx: number): void {
  const ctx = `${sourceId}.endpoints[${idx}]`;
  switch (ep.kind) {
    case "direct": {
      let parsed: URL;
      try {
        parsed = new URL(ep.url);
      } catch {
        throw new Error(`[${ctx}] Invalid direct URL: ${ep.url}`);
      }
      if (parsed.protocol !== "https:") {
        throw new Error(`[${ctx}] Direct endpoint must use HTTPS: ${ep.url}`);
      }
      break;
    }
    case "github_release": {
      if (!GITHUB_REPO_RE.test(ep.repo)) {
        throw new Error(`[${ctx}] Invalid GitHub repository '${ep.repo}'`);
      }
      try {
        new RegExp(ep.assetPattern);
      } catch (err) {
        throw new Error(`[${ctx}] Invalid assetPattern regex '${ep.assetPattern}': ${String(err)}`);
      }
      break;
    }
    case "npm_tarball": {
      if (ep.package.trim().length === 0 || ep.memberPath.trim().length === 0) {
        throw new Error(`[${ctx}] npm_tarball requires non-empty package and memberPath`);
      }
      break;
    }
  }
}

function validateSource(src: GeoIpSourceEntry, seenIds: Set<string>): void {
  if (!ID_RE.test(src.id)) {
    throw new Error(`[${src.id}] Source id must match ${ID_RE}`);
  }
  if (seenIds.has(src.id)) {
    throw new Error(`Duplicate source id: ${src.id}`);
  }
  seenIds.add(src.id);

  if (!ID_RE.test(src.lineage)) {
    throw new Error(`[${src.id}] Lineage must match ${ID_RE}, got '${src.lineage}'`);
  }

  validateWeight(src.countryWeight, "countryWeight", src.id);
  validateWeight(src.cnWeight, "cnWeight", src.id);
  validateWeight(src.cityWeight, "cityWeight", src.id);
  validateWeight(src.ispWeight, "ispWeight", src.id);
  validateWeight(src.asnWeight, "asnWeight", src.id);
  validateWeight(src.registeredCountryWeight, "registeredCountryWeight", src.id);

  validateIsoCode(src.fixedCountry, src.id);

  if (src.format === "cidr_country" && src.fixedCountry === undefined) {
    throw new Error(`[${src.id}] Format 'cidr_country' requires 'fixedCountry'`);
  }
  if (src.format === "cidr_isp" && (src.fixedIsp === undefined || src.fixedIsp.trim() === "")) {
    throw new Error(`[${src.id}] Format 'cidr_isp' requires non-empty 'fixedIsp'`);
  }

  if (src.endpoints.length === 0) {
    throw new Error(`[${src.id}] Source must define at least one endpoint`);
  }
  for (let i = 0; i < src.endpoints.length; i++) {
    const ep = src.endpoints[i];
    if (ep !== undefined) {
      validateEndpoint(ep, src.id, i);
    }
  }
}

function validateAdblockSource(src: AdblockSourceEntry, seenIds: Set<string>): void {
  if (!ID_RE.test(src.id)) {
    throw new Error(`[${src.id}] Source id must match ${ID_RE}`);
  }
  if (seenIds.has(src.id)) {
    throw new Error(`Duplicate adblock source id: ${src.id}`);
  }
  seenIds.add(src.id);

  if (src.role === "allowlist") {
    if (src.category !== "both" && src.category !== "ad" && src.category !== "privacy") {
      throw new Error(
        `[${src.id}] Allowlist source category must be 'both' | 'ad' | 'privacy', got '${src.category}'`,
      );
    }
  } else if (src.category !== "ad" && src.category !== "privacy" && src.category !== "ad_mixed") {
    throw new Error(
      `[${src.id}] Blocklist/complex source category must be 'ad' | 'privacy' | 'ad_mixed', got '${src.category}'`,
    );
  }

  if (!ID_RE.test(src.lineage)) {
    throw new Error(`[${src.id}] Lineage must match ${ID_RE}, got '${src.lineage}'`);
  }
  if (!Number.isInteger(src.weight) || src.weight < 1 || src.weight > 100) {
    throw new Error(`[${src.id}] Weight must be an integer in 1..100, got ${src.weight}`);
  }
  if (src.endpoints.length === 0) {
    throw new Error(`[${src.id}] Source must define at least one endpoint`);
  }
  for (let i = 0; i < src.endpoints.length; i++) {
    const ep = src.endpoints[i];
    if (ep !== undefined) {
      validateEndpoint(ep, src.id, i);
    }
  }
}

function validateRoutingSource(src: RoutingSourceEntry, seenIds: Set<string>): void {
  if (!ID_RE.test(src.id)) {
    throw new Error(`[${src.id}] Source id must match ${ID_RE}`);
  }
  if (seenIds.has(src.id)) {
    throw new Error(`Duplicate routing source id: ${src.id}`);
  }
  seenIds.add(src.id);

  if (!ID_RE.test(src.lineage)) {
    throw new Error(`[${src.id}] Lineage must match ${ID_RE}, got '${src.lineage}'`);
  }
  if (!Number.isInteger(src.weight) || src.weight < 1 || src.weight > 100) {
    throw new Error(`[${src.id}] Weight must be an integer in 1..100, got ${src.weight}`);
  }
  if (src.license.trim().length === 0 || src.homepage.trim().length === 0) {
    throw new Error(`[${src.id}] Routing source requires non-empty license and homepage`);
  }
  const serialized = JSON.stringify(src).toLowerCase();
  if (serialized.includes("quixoticheart")) {
    throw new Error(`[${src.id}] Disallowed restricted-redistribution source reference`);
  }
  if (src.endpoints.length === 0) {
    throw new Error(`[${src.id}] Source must define at least one endpoint`);
  }
  for (let i = 0; i < src.endpoints.length; i++) {
    const ep = src.endpoints[i];
    if (ep !== undefined) {
      validateEndpoint(ep, src.id, i);
    }
  }
}

function validateAll(): void {
  if (GEOIP_SOURCES.sources.length === 0) {
    throw new Error("GeoIP source catalog contains zero sources");
  }
  const seenGeoIds = new Set<string>();
  for (const src of GEOIP_SOURCES.sources) {
    validateSource(src, seenGeoIds);
  }

  if (ADBLOCK_SOURCES.sources.length === 0) {
    throw new Error("Adblock source catalog contains zero sources");
  }
  const seenAdblockIds = new Set<string>();
  let coreAdRulesets = 0;
  let corePrivacyRulesets = 0;
  for (const src of ADBLOCK_SOURCES.sources) {
    validateAdblockSource(src, seenAdblockIds);
    if (src.role === "ruleset_fallback" && src.core) {
      if (src.category === "ad" || src.category === "ad_mixed") {
        coreAdRulesets += 1;
      } else if (src.category === "privacy") {
        corePrivacyRulesets += 1;
      }
    }
  }
  if (coreAdRulesets === 0) {
    throw new Error("Adblock 'ad' ruleset catalog requires at least one core: true source");
  }
  if (corePrivacyRulesets === 0) {
    throw new Error("Adblock 'privacy' ruleset catalog requires at least one core: true source");
  }

  if (ROUTING_SOURCES.sources.length === 0) {
    throw new Error("Routing source catalog contains zero sources");
  }
  const seenRoutingIds = new Set<string>();
  const coreByTarget = new Map<RoutingTarget, number>([
    ["direct", 0],
    ["ai", 0],
    ["payment", 0],
    ["telemetry", 0],
    ["proxy", 0],
  ]);
  for (const src of ROUTING_SOURCES.sources) {
    validateRoutingSource(src, seenRoutingIds);
    if (src.core) {
      coreByTarget.set(src.target, (coreByTarget.get(src.target) ?? 0) + 1);
    }
  }
  for (const [target, count] of coreByTarget.entries()) {
    if (count === 0) {
      throw new Error(`Routing target '${target}' requires at least one core: true source`);
    }
  }
}

async function emitOrCheckBundle(
  outPath: string,
  bundle: unknown,
  count: number,
  label: string,
  checkMode: boolean,
): Promise<void> {
  const serialized = `${JSON.stringify(bundle, null, 2)}\n`;
  if (checkMode) {
    let existing: string;
    try {
      existing = await readFile(outPath, "utf8");
    } catch {
      throw new Error(
        `Missing generated ${label} file at ${outPath}. Run 'bun run build:sources'.`,
      );
    }
    if (existing !== serialized) {
      throw new Error(
        `Out-of-date ${outPath}. Run 'bun run build:sources' and commit the updated file.`,
      );
    }
    console.log(`Verified ${label} sources in sync (${count} sources).`);
    return;
  }

  await mkdir(dirname(outPath), { recursive: true });
  await writeFile(outPath, serialized, "utf8");
  console.log(`Wrote ${outPath} (${count} sources, ${serialized.length} bytes).`);
}

async function main(): Promise<void> {
  validateAll();

  const currentDir = dirname(fileURLToPath(import.meta.url));
  const checkMode = process.argv.includes("--check");

  await emitOrCheckBundle(
    resolve(currentDir, "generated", "geoip-sources.json"),
    GEOIP_SOURCES,
    GEOIP_SOURCES.sources.length,
    "GeoIP",
    checkMode,
  );
  await emitOrCheckBundle(
    resolve(currentDir, "generated", "adblock-sources.json"),
    ADBLOCK_SOURCES,
    ADBLOCK_SOURCES.sources.length,
    "Adblock",
    checkMode,
  );
  await emitOrCheckBundle(
    resolve(currentDir, "generated", "routing-sources.json"),
    ROUTING_SOURCES,
    ROUTING_SOURCES.sources.length,
    "Routing",
    checkMode,
  );
}

await main();
