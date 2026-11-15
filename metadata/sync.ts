import { existsSync } from "node:fs";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync, inflateRawSync } from "node:zlib";
import type {
  CloudProviderId,
  CloudRegionMetadataEntry,
  CnDivisionMetadataEntry,
  CompiledMetadataBundle,
  ContinentCode,
  CountryMetadataEntry,
  MetadataUpstreamSource,
} from "./schema.ts";
import { METADATA_UPSTREAMS } from "./sources.ts";
import { validateMetadataBundle } from "./verify.ts";

const CONTINENT_META: Record<ContinentCode, { geonameId: number; nameEn: string; nameZh: string }> =
  {
    AF: { geonameId: 6255146, nameEn: "Africa", nameZh: "非洲" },
    AN: { geonameId: 6255152, nameEn: "Antarctica", nameZh: "南极洲" },
    AS: { geonameId: 6255147, nameEn: "Asia", nameZh: "亚洲" },
    EU: { geonameId: 6255148, nameEn: "Europe", nameZh: "欧洲" },
    NA: { geonameId: 6255149, nameEn: "North America", nameZh: "北美洲" },
    OC: { geonameId: 6255151, nameEn: "Oceania", nameZh: "大洋洲" },
    SA: { geonameId: 6255150, nameEn: "South America", nameZh: "南美洲" },
  };

const DISALLOWED_COUNTRY_CODES = new Set(["AN", "AP", "EU", "OO", "UK", "XX", "ZZ"]);
const CN_MUNICIPALITY_CODES = new Set(["110000", "120000", "310000", "500000"]);
const SYNTHETIC_CN_PARENT_NAMES = new Set([
  "市辖区",
  "县",
  "省直辖县级行政区划",
  "自治区直辖县级行政区划",
]);
const COLLOQUIAL_ALIASES: Readonly<Record<string, readonly string[]>> = {
  AE: ["阿联酋"],
  AU: ["澳洲"],
  CN: ["中国大陆", "中国内地"],
  HK: ["中国香港", "香港特别行政区", "hongkong"],
  ID: ["印尼"],
  MO: ["中国澳门", "澳门特别行政区"],
  SA: ["沙特"],
  TW: ["中国台湾", "台湾省", "中华民国"],
};
const CLOUD_REUSE_UPSTREAM_IDS = new Set([
  "aws_ip_ranges",
  "aws_geofeed",
  "gcp_cloud_ranges",
  "gcp_cloud_geofeed",
  "oracle_cloud_ranges",
]);

interface CachedFetchMeta {
  url: string;
  etag?: string | undefined;
  lastModified?: string | undefined;
  fetchedAtMs: number;
}

interface CityRecord {
  geonameId: number;
  name: string;
  asciiName: string;
  altNames: string[];
  lat: number;
  lon: number;
  featureCode: string;
  country: string;
  admin1: string;
  population: number;
  timezone: string;
}

interface Dr5hnState {
  countryCode: string;
  iso2: string;
  name: string;
  native: string;
  zhCn: string;
  lat: number;
  lon: number;
}

interface ModoodNode {
  code: string;
  name: string;
  children?: ModoodNode[];
}

interface AreaCityRow {
  adcode: string;
  deep: number;
  name: string;
  pinyin: string;
  extName: string;
}

function normalizeTextKey(input: string): string {
  return input
    .trim()
    .toLowerCase()
    .normalize("NFKD")
    .replace(/\p{M}+/gu, "")
    .replace(/[^a-z0-9\u4e00-\u9fff]+/g, "");
}

function roundCoord(val: number): number {
  return Math.round(val * 10000) / 10000;
}

function haversineKm(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const rad = Math.PI / 180;
  const dLat = (lat2 - lat1) * rad;
  const dLon = (lon2 - lon1) * rad;
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1 * rad) * Math.cos(lat2 * rad) * Math.sin(dLon / 2) * Math.sin(dLon / 2);
  return 6371 * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function extractZipMember(zipBytes: Uint8Array, memberName: string): Uint8Array {
  const view = new DataView(zipBytes.buffer, zipBytes.byteOffset, zipBytes.byteLength);
  let eocdOff = -1;
  const minOff = Math.max(0, zipBytes.length - 65557);
  for (let i = zipBytes.length - 22; i >= minOff; i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocdOff = i;
      break;
    }
  }
  if (eocdOff < 0) {
    throw new Error(`Invalid ZIP archive while locating '${memberName}'`);
  }

  const totalEntries = view.getUint16(eocdOff + 10, true);
  let cdOff = view.getUint32(eocdOff + 16, true);
  const dec = new TextDecoder();

  for (let i = 0; i < totalEntries; i++) {
    if (view.getUint32(cdOff, true) !== 0x02014b50) {
      throw new Error(`Corrupt ZIP central directory at offset ${cdOff}`);
    }
    const method = view.getUint16(cdOff + 10, true);
    const compressedSize = view.getUint32(cdOff + 20, true);
    const nameLen = view.getUint16(cdOff + 28, true);
    const extraLen = view.getUint16(cdOff + 30, true);
    const commentLen = view.getUint16(cdOff + 32, true);
    const localHeaderOff = view.getUint32(cdOff + 42, true);
    const entryName = dec.decode(zipBytes.subarray(cdOff + 46, cdOff + 46 + nameLen));

    if (entryName === memberName || entryName.endsWith(`/${memberName}`)) {
      if (view.getUint32(localHeaderOff, true) !== 0x04034b50) {
        throw new Error(`Corrupt ZIP local file header for '${memberName}'`);
      }
      const localNameLen = view.getUint16(localHeaderOff + 26, true);
      const localExtraLen = view.getUint16(localHeaderOff + 28, true);
      const dataStart = localHeaderOff + 30 + localNameLen + localExtraLen;
      const compressed = zipBytes.subarray(dataStart, dataStart + compressedSize);
      if (method === 0) return compressed;
      if (method === 8) return new Uint8Array(inflateRawSync(compressed));
      throw new Error(`Unsupported ZIP compression method ${method} for '${memberName}'`);
    }

    cdOff += 46 + nameLen + extraLen + commentLen;
  }

  throw new Error(`ZIP archive does not contain member '${memberName}'`);
}

function maybeDecompress(bytes: Uint8Array, source: MetadataUpstreamSource): Uint8Array {
  if (source.archiveMember) {
    return extractZipMember(bytes, source.archiveMember);
  }
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    return new Uint8Array(gunzipSync(bytes));
  }
  return bytes;
}

async function resolveDownloadUrl(rawUrl: string): Promise<string> {
  if (!rawUrl.startsWith("github-release:")) {
    return rawUrl;
  }
  const rest = rawUrl.slice("github-release:".length);
  const sep = rest.indexOf(":");
  if (sep < 0) {
    throw new Error(`Malformed github-release spec '${rawUrl}'`);
  }
  const repo = rest.slice(0, sep);
  const pattern = new RegExp(rest.slice(sep + 1));
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "surge-rules-metadata-sync/1.0",
  };
  const token = process.env.GITHUB_TOKEN?.trim();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const resp = await fetch(`https://api.github.com/repos/${repo}/releases/latest`, { headers });
  if (!resp.ok) {
    throw new Error(`GitHub release API ${resp.status} for ${repo}`);
  }
  const release = (await resp.json()) as {
    assets?: Array<{ name?: string; browser_download_url?: string }>;
  };
  const asset = release.assets?.find(
    (a) => a.name && a.browser_download_url && pattern.test(a.name),
  );
  if (!asset?.browser_download_url) {
    throw new Error(`No release asset matching '${pattern.source}' in ${repo}`);
  }
  return asset.browser_download_url;
}

async function fetchUpstreamText(
  source: MetadataUpstreamSource,
  repoRoot: string,
  maxCacheAgeSecs: number,
): Promise<string> {
  const upstreamReusable = resolve(repoRoot, ".cache", "upstream", `${source.id}.bin`);
  const nowMs = Date.now();
  const maxAgeMs = maxCacheAgeSecs * 1000;

  if (CLOUD_REUSE_UPSTREAM_IDS.has(source.id) && existsSync(upstreamReusable)) {
    const info = await stat(upstreamReusable);
    if (nowMs - info.mtimeMs <= maxAgeMs) {
      const bytes = maybeDecompress(await readFile(upstreamReusable), source);
      return new TextDecoder().decode(bytes);
    }
  }

  const cacheDir = resolve(repoRoot, ".cache", "metadata");
  await mkdir(cacheDir, { recursive: true });
  const binPath = resolve(cacheDir, `${source.id}.bin`);
  const metaPath = resolve(cacheDir, `${source.id}.meta.json`);

  let existingMeta: CachedFetchMeta | null = null;
  if (existsSync(metaPath) && existsSync(binPath)) {
    try {
      existingMeta = JSON.parse(await readFile(metaPath, "utf8")) as CachedFetchMeta;
      if (nowMs - existingMeta.fetchedAtMs <= maxAgeMs) {
        const bytes = maybeDecompress(await readFile(binPath), source);
        return new TextDecoder().decode(bytes);
      }
    } catch {
      existingMeta = null;
    }
  }

  let lastErr: unknown = null;
  for (const candidate of source.urls) {
    try {
      const targetUrl = await resolveDownloadUrl(candidate);
      const headers: Record<string, string> = {
        "User-Agent": "surge-rules-metadata-sync/1.0",
      };
      const token = process.env.GITHUB_TOKEN?.trim();
      if (
        token &&
        (targetUrl.includes("github.com") || targetUrl.includes("githubusercontent.com"))
      ) {
        headers.Authorization = `Bearer ${token}`;
      }
      if (existingMeta?.url === targetUrl) {
        if (existingMeta.etag) headers["If-None-Match"] = existingMeta.etag;
        if (existingMeta.lastModified) headers["If-Modified-Since"] = existingMeta.lastModified;
      }

      const resp = await fetch(targetUrl, { headers, redirect: "follow" });
      if (resp.status === 304 && existsSync(binPath)) {
        const refreshed: CachedFetchMeta = {
          url: targetUrl,
          etag: resp.headers.get("etag") ?? existingMeta?.etag,
          lastModified: resp.headers.get("last-modified") ?? existingMeta?.lastModified,
          fetchedAtMs: nowMs,
        };
        await writeFile(metaPath, JSON.stringify(refreshed), "utf8");
        const bytes = maybeDecompress(await readFile(binPath), source);
        return new TextDecoder().decode(bytes);
      }
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status} for ${targetUrl}`);
      }

      const rawBytes = new Uint8Array(await resp.arrayBuffer());
      await writeFile(binPath, rawBytes);
      const meta: CachedFetchMeta = {
        url: targetUrl,
        etag: resp.headers.get("etag") ?? undefined,
        lastModified: resp.headers.get("last-modified") ?? undefined,
        fetchedAtMs: nowMs,
      };
      await writeFile(metaPath, JSON.stringify(meta), "utf8");
      const bytes = maybeDecompress(rawBytes, source);
      return new TextDecoder().decode(bytes);
    } catch (err) {
      lastErr = err;
    }
  }

  if (existsSync(binPath)) {
    console.warn(`[${source.id}] Fetch failed (${String(lastErr)}); reusing stale cache.`);
    const bytes = maybeDecompress(await readFile(binPath), source);
    return new TextDecoder().decode(bytes);
  }

  throw new Error(`[${source.id}] All upstream URLs failed: ${String(lastErr)}`);
}

function parseCsvRow(line: string): string[] {
  const fields: string[] = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (line[i + 1] === '"') {
          cur += '"';
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        cur += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ",") {
      fields.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  fields.push(cur);
  return fields;
}

function parseEuCodes(rawEu: string): Set<string> {
  const euSet = new Set<string>();
  const trimmed = rawEu.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    const parsed = JSON.parse(trimmed) as unknown;
    const rows: unknown[] = Array.isArray(parsed)
      ? parsed
      : typeof parsed === "object" && parsed !== null
        ? ((Object.values(parsed).find((v) => Array.isArray(v)) as unknown[] | undefined) ?? [])
        : [];
    for (const item of rows) {
      if (typeof item !== "object" || item === null) continue;
      const rec = item as Record<string, unknown>;
      const iso =
        rec.ISO_3166_1_alpha2 ??
        rec.iso2c ??
        rec.ISO2 ??
        rec.ISO_3166_2 ??
        rec.iso_a2 ??
        rec.cca2 ??
        rec.alpha2;
      if (typeof iso !== "string") continue;
      const candIso = iso.trim().toUpperCase();
      if (!/^[A-Z]{2}$/.test(candIso)) continue;

      let isMember = false;
      if (Array.isArray(rec.org_id) && Array.isArray(rec.org_member)) {
        const euIdx = rec.org_id.indexOf("EU");
        if (euIdx >= 0 && typeof rec.org_member[euIdx] === "string") {
          isMember = rec.org_member[euIdx].trim().toLowerCase() === "member";
        }
      } else {
        const euVal = rec.EU ?? rec.eu;
        isMember =
          euVal === true ||
          euVal === 1 ||
          (typeof euVal === "string" &&
            ["eu", "y", "yes", "true", "1", "member"].includes(euVal.trim().toLowerCase()));
      }
      if (isMember) {
        euSet.add(candIso);
      }
    }
    return euSet;
  }

  const lines = trimmed.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]?.trim();
    if (!line || line.startsWith("#")) continue;
    const cols = parseCsvRow(line);
    if (
      i === 0 &&
      cols.some((c) => c.toLowerCase().includes("iso") || c.toLowerCase().includes("code"))
    ) {
      continue;
    }
    for (const col of cols) {
      const cand = col.trim().toUpperCase();
      if (/^[A-Z]{2}$/.test(cand) && cand !== "EU") {
        euSet.add(cand);
        break;
      }
    }
  }
  return euSet;
}

function parseIanaZoneMap(tabText: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const line of tabText.split(/\r?\n/)) {
    if (!line || line.startsWith("#")) continue;
    const cols = line.split("\t");
    const codesRaw = cols[0]?.trim();
    const tz = cols[2]?.trim();
    if (!codesRaw || !tz) continue;
    for (const code of codesRaw.split(",")) {
      const iso = code.trim().toUpperCase();
      if (/^[A-Z]{2}$/.test(iso) && !map.has(iso)) {
        map.set(iso, tz);
      }
    }
  }
  return map;
}

function parseCities5000(tsvText: string): CityRecord[] {
  const records: CityRecord[] = [];
  for (const line of tsvText.split(/\r?\n/)) {
    if (!line) continue;
    const cols = line.split("\t");
    if (cols.length < 18) continue;
    const geonameId = Number.parseInt(cols[0] ?? "", 10);
    const name = cols[1]?.trim() ?? "";
    const asciiName = (cols[2]?.trim() || name).trim();
    const altRaw = cols[3] ?? "";
    const lat = Number.parseFloat(cols[4] ?? "");
    const lon = Number.parseFloat(cols[5] ?? "");
    const featureCode = cols[7]?.trim() ?? "";
    const country = cols[8]?.trim().toUpperCase() ?? "";
    const admin1 = cols[10]?.trim() ?? "";
    const population = Number.parseInt(cols[14] ?? "0", 10) || 0;
    const timezone = cols[17]?.trim() ?? "";
    if (!Number.isFinite(geonameId) || !Number.isFinite(lat) || !Number.isFinite(lon) || !country) {
      continue;
    }
    records.push({
      geonameId,
      name,
      asciiName,
      altNames: altRaw
        ? altRaw
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean)
        : [],
      lat,
      lon,
      featureCode,
      country,
      admin1,
      population,
      timezone,
    });
  }
  return records;
}

function parseDr5hnStates(rawJson: string): Dr5hnState[] {
  const parsed = JSON.parse(rawJson) as Array<Record<string, unknown>>;
  const out: Dr5hnState[] = [];
  for (const item of parsed) {
    const cc = typeof item.country_code === "string" ? item.country_code.trim().toUpperCase() : "";
    const rawIso2 =
      typeof item.iso2 === "string"
        ? item.iso2.trim().toUpperCase()
        : typeof item.state_code === "string"
          ? item.state_code.trim().toUpperCase()
          : "";
    const iso2 = rawIso2.startsWith(`${cc}-`) ? rawIso2.slice(cc.length + 1) : rawIso2;
    const name = typeof item.name === "string" ? item.name.trim() : "";
    const native = typeof item.native === "string" ? item.native.trim() : "";
    const translations =
      typeof item.translations === "object" && item.translations !== null
        ? (item.translations as Record<string, unknown>)
        : null;
    const zhCn =
      translations && typeof translations["zh-CN"] === "string" ? translations["zh-CN"].trim() : "";
    const lat =
      typeof item.latitude === "string" || typeof item.latitude === "number"
        ? Number.parseFloat(String(item.latitude))
        : Number.NaN;
    const lon =
      typeof item.longitude === "string" || typeof item.longitude === "number"
        ? Number.parseFloat(String(item.longitude))
        : Number.NaN;
    if (!cc || !iso2 || !name) continue;
    out.push({
      countryCode: cc,
      iso2,
      name,
      native,
      zhCn,
      lat: Number.isFinite(lat) ? lat : 0,
      lon: Number.isFinite(lon) ? lon : 0,
    });
  }
  return out;
}

function parseDebianIso3166_2(rawJson: string): Map<string, string> {
  const parsed = JSON.parse(rawJson) as {
    "3166-2"?: Array<{ code?: string; name?: string }>;
  };
  const map = new Map<string, string>();
  for (const entry of parsed["3166-2"] ?? []) {
    if (entry.code && entry.name) {
      map.set(entry.code.trim().toUpperCase(), entry.name.trim());
    }
  }
  return map;
}

function cleanZhCountryName(
  cldrZh: string | undefined,
  mledozeZh: string | undefined,
  enName: string,
): string {
  const cand = cldrZh?.trim() || mledozeZh?.trim() || enName;
  if (cand.endsWith("特别行政区")) {
    return cand.replace(/^中国/, "").replace(/特别行政区$/, "");
  }
  return cand;
}

function buildCountries(
  countryInfoText: string,
  mledozeJsonText: string,
  cldrZhText: string,
  cldrEnText: string,
  euText: string,
  zoneTabText: string,
  cities: CityRecord[],
): CountryMetadataEntry[] {
  const cldrZh = JSON.parse(cldrZhText) as Record<string, string>;
  const cldrEn = JSON.parse(cldrEnText) as Record<string, string>;
  const mledozeArr = JSON.parse(mledozeJsonText) as Array<{
    cca2?: string;
    cca3?: string;
    name?: { common?: string; official?: string };
    altSpellings?: string[];
    translations?: { zho?: { common?: string; official?: string } };
  }>;
  const mledozeByIso = new Map<string, (typeof mledozeArr)[number]>();
  for (const item of mledozeArr) {
    if (item.cca2) mledozeByIso.set(item.cca2.trim().toUpperCase(), item);
  }

  const euCodes = parseEuCodes(euText);
  const zoneFallbacks = parseIanaZoneMap(zoneTabText);

  const capitalTzByIso = new Map<string, string>();
  const topPopCityByIso = new Map<string, CityRecord>();
  for (const city of cities) {
    if (!city.timezone) continue;
    if (city.featureCode === "PPLC" && !capitalTzByIso.has(city.country)) {
      capitalTzByIso.set(city.country, city.timezone);
    }
    const prev = topPopCityByIso.get(city.country);
    if (!prev || city.population > prev.population) {
      topPopCityByIso.set(city.country, city);
    }
  }

  const countries: CountryMetadataEntry[] = [];
  for (const line of countryInfoText.split(/\r?\n/)) {
    if (!line || line.startsWith("#")) continue;
    const cols = line.split("\t");
    const iso = cols[0]?.trim().toUpperCase() ?? "";
    const iso3 = cols[1]?.trim() ?? "";
    const geonamesName = cols[4]?.trim() ?? "";
    const continentRaw = (cols[8]?.trim().toUpperCase() ?? "") as ContinentCode;
    const geonameId = Number.parseInt(cols[16]?.trim() ?? "0", 10) || 0;

    if (!/^[A-Z]{2}$/.test(iso) || DISALLOWED_COUNTRY_CODES.has(iso)) continue;
    const continent = CONTINENT_META[continentRaw];
    if (!continent || geonameId <= 0) continue;

    const ml = mledozeByIso.get(iso);
    const nameEn = (ml?.name?.common?.trim() || geonamesName || cldrEn[iso] || iso).trim();
    const nameZh = cleanZhCountryName(cldrZh[iso], ml?.translations?.zho?.common, nameEn);
    const defaultTz =
      capitalTzByIso.get(iso) ??
      topPopCityByIso.get(iso)?.timezone ??
      zoneFallbacks.get(iso) ??
      "UTC";

    const aliasSet = new Set<string>();
    const pushAlias = (val: string | undefined): void => {
      if (!val) return;
      const normalized = val.trim().toLowerCase();
      if (normalized && !(iso !== "CN" && (normalized === "中国" || normalized === "china"))) {
        aliasSet.add(normalized);
      }
    };
    pushAlias(iso);
    pushAlias(iso3);
    pushAlias(geonamesName);
    pushAlias(cldrEn[iso]);
    pushAlias(cldrZh[iso]);
    pushAlias(nameEn);
    pushAlias(nameZh);
    pushAlias(ml?.name?.common);
    pushAlias(ml?.name?.official);
    pushAlias(ml?.translations?.zho?.common);
    pushAlias(ml?.translations?.zho?.official);
    for (const sp of ml?.altSpellings ?? []) {
      pushAlias(sp);
    }
    for (const extra of COLLOQUIAL_ALIASES[iso] ?? []) {
      pushAlias(extra);
    }

    countries.push({
      isoCode: iso,
      continentCode: continentRaw,
      continentGeonameId: continent.geonameId,
      continentEn: continent.nameEn,
      continentZh: continent.nameZh,
      geonameId,
      isEu: euCodes.has(iso),
      nameEn,
      nameZh,
      defaultTz,
      aliases: [...aliasSet].sort(),
    });
  }

  countries.sort((a, b) => a.isoCode.localeCompare(b.isoCode));
  return countries;
}

function parseAreaCityCsv(csvText: string): Map<string, AreaCityRow> {
  const byAdcode = new Map<string, AreaCityRow>();
  const lines = csvText.replace(/^\uFEFF/, "").split(/\r?\n/);
  if (lines.length < 2) return byAdcode;
  const header = parseCsvRow(lines[0] ?? "").map((h) => h.trim().toLowerCase());
  const idxId = header.indexOf("id");
  const idxDeep = header.indexOf("deep");
  const idxName = header.indexOf("name");
  const idxPinyin = header.indexOf("pinyin");
  const idxExt = header.indexOf("ext_name");

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i]?.trim();
    if (!line) continue;
    const cols = parseCsvRow(line);
    const rawId = cols[idxId]?.trim() ?? "";
    if (!/^\d{2,6}$/.test(rawId)) continue;
    const adcode = rawId.padEnd(6, "0");
    if (adcode.startsWith("71") || adcode.startsWith("81") || adcode.startsWith("82")) continue;

    byAdcode.set(adcode, {
      adcode,
      deep: Number.parseInt(cols[idxDeep] ?? "0", 10) || 0,
      name: (cols[idxName] ?? "").trim(),
      pinyin: (cols[idxPinyin] ?? "").trim(),
      extName: (cols[idxExt] ?? "").trim(),
    });
  }
  return byAdcode;
}

function formatPinyinEnglish(rawPinyin: string, fallbackZh: string): string {
  const tokens = rawPinyin
    .trim()
    .split(/[\s_-]+/)
    .map((t) => t.replace(/[^a-zA-Z0-9']/g, ""))
    .filter(Boolean);
  if (tokens.length === 0) return fallbackZh;
  const joined = tokens.join("").toLowerCase();
  return joined.charAt(0).toUpperCase() + joined.slice(1);
}

function cnFeatureScore(featureCode: string): number {
  switch (featureCode) {
    case "PPLC":
      return 4;
    case "PPLA":
      return 3;
    case "PPLA2":
      return 2;
    case "PPLA3":
      return 1;
    default:
      return 0;
  }
}

function findMatchingCnCity(
  names: string[],
  hintLat: number,
  hintLon: number,
  cnByAltName: Map<string, CityRecord[]>,
  hintAdmin1?: string,
  maxDistKm = 180,
): CityRecord | undefined {
  const candidates: CityRecord[] = [];
  const seenIds = new Set<number>();
  for (const name of names) {
    if (!name) continue;
    for (const c of cnByAltName.get(name) ?? []) {
      if (!seenIds.has(c.geonameId)) {
        seenIds.add(c.geonameId);
        candidates.push(c);
      }
    }
  }
  if (candidates.length === 0) return undefined;

  let filtered = candidates;
  if (hintAdmin1) {
    const sameAdmin = filtered.filter((c) => c.admin1 === hintAdmin1);
    if (sameAdmin.length > 0) {
      filtered = sameAdmin;
    } else if (maxDistKm <= 200) {
      return undefined;
    }
  }
  if (hintLat !== 0 && hintLon !== 0 && maxDistKm > 0) {
    const near = filtered.filter((c) => haversineKm(hintLat, hintLon, c.lat, c.lon) <= maxDistKm);
    if (near.length > 0) {
      filtered = near;
    } else if (!hintAdmin1) {
      return undefined;
    }
  }

  filtered.sort((a, b) => {
    const fsDiff = cnFeatureScore(b.featureCode) - cnFeatureScore(a.featureCode);
    if (fsDiff !== 0) return fsDiff;
    if (hintLat !== 0 && hintLon !== 0) {
      const distDiff =
        haversineKm(hintLat, hintLon, a.lat, a.lon) - haversineKm(hintLat, hintLon, b.lat, b.lon);
      if (Math.abs(distDiff) > 25) return distDiff;
    }
    return b.population - a.population;
  });

  return filtered[0];
}

function stripCnProvSuffix(name: string): string {
  return name
    .replace(/维吾尔自治区$/, "")
    .replace(/壮族自治区$/, "")
    .replace(/回族自治区$/, "")
    .replace(/特别行政区$/, "")
    .replace(/(自治区|省|市)$/, "");
}

function buildCnDivisions(
  pcaJsonText: string,
  areaCityCsvText: string,
  dr5hnStates: Dr5hnState[],
  debianIso3166_2: Map<string, string>,
  cities: CityRecord[],
): CnDivisionMetadataEntry[] {
  const pcaTree = JSON.parse(pcaJsonText) as ModoodNode[];
  const areaCityByAdcode = parseAreaCityCsv(areaCityCsvText);

  const cnCities = cities.filter((c) => c.country === "CN");
  const cnByAltName = new Map<string, CityRecord[]>();
  const pushCnCityKey = (raw: string, city: CityRecord): void => {
    const key = raw.trim();
    if (!key) return;
    const list = cnByAltName.get(key) ?? [];
    list.push(city);
    cnByAltName.set(key, list);
  };
  for (const c of cnCities) {
    pushCnCityKey(c.name, c);
    for (const alt of c.altNames) {
      pushCnCityKey(alt, c);
    }
  }

  const dr5hnCnStates = dr5hnStates.filter(
    (s) => s.countryCode === "CN" && !["HK", "MO", "TW"].includes(s.iso2),
  );
  const dr5hnCnByNative = new Map<string, Dr5hnState>();
  const dr5hnCnByKey = new Map<string, Dr5hnState>();
  for (const s of dr5hnCnStates) {
    if (s.native) {
      dr5hnCnByNative.set(s.native, s);
      dr5hnCnByNative.set(stripCnProvSuffix(s.native), s);
    }
    if (s.zhCn) {
      dr5hnCnByNative.set(s.zhCn, s);
      dr5hnCnByNative.set(stripCnProvSuffix(s.zhCn), s);
    }
    dr5hnCnByKey.set(normalizeTextKey(s.name), s);
  }
  const debianCnByKey = new Map<string, { iso2: string; name: string }>();
  for (const [code, name] of debianIso3166_2.entries()) {
    if (!code.startsWith("CN-")) continue;
    const iso2 = code.slice(3);
    if (["HK", "MO", "TW"].includes(iso2)) continue;
    debianCnByKey.set(normalizeTextKey(name), { iso2, name });
  }

  const usedProvIsos = new Set<string>();
  const resolveProvinceState = (
    provNameZh: string,
    areaRow: AreaCityRow | undefined,
  ): { iso2: string; en: string; lat: number; lon: number } => {
    const shortZh = stripCnProvSuffix(provNameZh);
    for (const zh of [provNameZh, shortZh, areaRow?.extName ?? "", areaRow?.name ?? ""]) {
      if (!zh) continue;
      const drNat = dr5hnCnByNative.get(zh);
      if (drNat && !usedProvIsos.has(drNat.iso2)) {
        usedProvIsos.add(drNat.iso2);
        return { iso2: drNat.iso2, en: drNat.name, lat: drNat.lat, lon: drNat.lon };
      }
    }

    const pinyinBase = normalizeTextKey(
      (areaRow?.pinyin ?? "").replace(/\b(shi|sheng|zizhiqu)\b/gi, ""),
    );
    const exactKeys = [
      pinyinBase,
      pinyinBase.replace(/zizhiqu$/, ""),
      normalizeTextKey(formatPinyinEnglish(areaRow?.pinyin ?? "", provNameZh)),
    ].filter(Boolean);

    for (const k of exactKeys) {
      const dr = dr5hnCnByKey.get(k);
      if (dr && !usedProvIsos.has(dr.iso2)) {
        usedProvIsos.add(dr.iso2);
        return { iso2: dr.iso2, en: dr.name, lat: dr.lat, lon: dr.lon };
      }
      const deb = debianCnByKey.get(k);
      if (deb && !usedProvIsos.has(deb.iso2)) {
        usedProvIsos.add(deb.iso2);
        return { iso2: deb.iso2, en: deb.name, lat: 0, lon: 0 };
      }
    }

    throw new Error(`Unable to map CN province '${provNameZh}' (${shortZh}) to ISO 3166-2 CN-xx`);
  };

  const out: CnDivisionMetadataEntry[] = [];
  const seenAdcodes = new Set<string>();
  const pushDivision = (entry: CnDivisionMetadataEntry): void => {
    if (seenAdcodes.has(entry.adcode)) return;
    seenAdcodes.add(entry.adcode);
    out.push(entry);
  };
  for (const prov of pcaTree) {
    const provAdcode = prov.code.padEnd(6, "0");
    if (provAdcode.startsWith("71") || provAdcode.startsWith("81") || provAdcode.startsWith("82")) {
      continue;
    }
    const provArea = areaCityByAdcode.get(provAdcode);
    const {
      iso2: provIso,
      en: drProvEn,
      lat: drLat,
      lon: drLon,
    } = resolveProvinceState(prov.name, provArea);
    const provGeoMatch = findMatchingCnCity(
      [prov.name, stripCnProvSuffix(prov.name)],
      drLat,
      drLon,
      cnByAltName,
      undefined,
      600,
    );
    const provAdmin1 = provGeoMatch?.admin1;
    const debProvName = debianIso3166_2.get(`CN-${provIso}`);
    const provEn = CN_MUNICIPALITY_CODES.has(provAdcode)
      ? (provGeoMatch?.asciiName ?? drProvEn.replace(/\s+Municipality$/i, ""))
      : (
          drProvEn ||
          (debProvName ?? "").replace(/\s+(Zhuangzu|Huizu|Uygur)?\s*(Sheng|Zizhiqu|Shi)$/i, "")
        ).replace(/\s+(Province|Autonomous Region|Municipality)$/i, "");
    const provLat = drLat !== 0 ? drLat : (provGeoMatch?.lat ?? 0);
    const provLon = drLon !== 0 ? drLon : (provGeoMatch?.lon ?? 0);

    pushDivision({
      adcode: provAdcode,
      level: 1,
      isoCode: provIso,
      provinceZh: prov.name,
      provinceEn: provEn,
      cityZh: "",
      cityEn: "",
      districtZh: "",
      districtEn: "",
      geonameId: provGeoMatch?.geonameId ?? 0,
      lat: roundCoord(provLat),
      lon: roundCoord(provLon),
    });

    const isMunicipality = CN_MUNICIPALITY_CODES.has(provAdcode);

    for (const city of prov.children ?? []) {
      const cityAdcode = city.code.padEnd(6, "0");
      const isSynthetic = SYNTHETIC_CN_PARENT_NAMES.has(city.name);

      let effCityZh = "";
      let effCityEn = "";
      let parentLat = provLat;
      let parentLon = provLon;
      let parentAdmin1 = provAdmin1;

      if (isMunicipality) {
        effCityZh = prov.name;
        effCityEn = provEn;
        if (city.name === "市辖区") {
          pushDivision({
            adcode: cityAdcode,
            level: 2,
            isoCode: provIso,
            provinceZh: prov.name,
            provinceEn: provEn,
            cityZh: prov.name,
            cityEn: provEn,
            districtZh: "",
            districtEn: "",
            geonameId: provGeoMatch?.geonameId ?? 0,
            lat: roundCoord(provLat),
            lon: roundCoord(provLon),
          });
        }
      } else if (!isSynthetic) {
        const cityArea = areaCityByAdcode.get(cityAdcode);
        const cityShortZh = city.name.replace(/(地区|盟|自治州|市)$/, "");
        const cityMatch = findMatchingCnCity(
          [city.name, cityShortZh, cityArea?.name ?? ""],
          provLat,
          provLon,
          cnByAltName,
          provAdmin1,
          2000,
        );
        effCityZh = city.name;
        effCityEn =
          cityMatch?.asciiName ?? formatPinyinEnglish(cityArea?.pinyin ?? "", cityShortZh);
        const cityLat = cityMatch?.lat ?? provLat;
        const cityLon = cityMatch?.lon ?? provLon;
        parentLat = cityLat;
        parentLon = cityLon;
        parentAdmin1 = cityMatch?.admin1 ?? provAdmin1;

        pushDivision({
          adcode: cityAdcode,
          level: 2,
          isoCode: provIso,
          provinceZh: prov.name,
          provinceEn: provEn,
          cityZh: effCityZh,
          cityEn: effCityEn,
          districtZh: "",
          districtEn: "",
          geonameId: cityMatch?.geonameId ?? 0,
          lat: roundCoord(cityLat),
          lon: roundCoord(cityLon),
        });
      }

      for (const dist of city.children ?? []) {
        if (!/^\d{6}$/.test(dist.code)) continue;
        const distAdcode = dist.code;
        const distArea = areaCityByAdcode.get(distAdcode);
        const distShortZh = dist.name.replace(/(新区|区|市|县|自治县|旗|自治旗|特区|林区)$/, "");
        const distMatch = findMatchingCnCity(
          [dist.name, distShortZh, distArea?.name ?? ""],
          parentLat,
          parentLon,
          cnByAltName,
          parentAdmin1,
          isSynthetic ? 1800 : 180,
        );
        const distEn =
          distMatch?.asciiName ?? formatPinyinEnglish(distArea?.pinyin ?? "", dist.name);
        const distLat = distMatch?.lat ?? parentLat;
        const distLon = distMatch?.lon ?? parentLon;

        pushDivision({
          adcode: distAdcode,
          level: 3,
          isoCode: provIso,
          provinceZh: prov.name,
          provinceEn: provEn,
          cityZh: effCityZh,
          cityEn: effCityEn,
          districtZh: dist.name,
          districtEn: distEn,
          geonameId: distMatch?.geonameId ?? 0,
          lat: roundCoord(distLat),
          lon: roundCoord(distLon),
        });
      }
    }
  }

  return out;
}

interface GeofeedGeo {
  isoCode: string;
  subdivisionIso: string;
  cityEn: string;
}

interface GeofeedCidr {
  isV6: boolean;
  network: bigint;
  prefixLen: number;
  geo: GeofeedGeo;
}

function parseCidrBigInt(
  cidr: string,
): { isV6: boolean; network: bigint; prefixLen: number } | null {
  const slash = cidr.indexOf("/");
  if (slash < 0) return null;
  const ipStr = cidr.slice(0, slash).trim();
  const prefixLen = Number.parseInt(cidr.slice(slash + 1).trim(), 10);
  if (!Number.isInteger(prefixLen) || prefixLen < 0) return null;

  if (ipStr.includes(":")) {
    if (prefixLen > 128) return null;
    const halves = ipStr.split("::");
    if (halves.length > 2) return null;
    const left = halves[0] ? halves[0].split(":").filter(Boolean) : [];
    const right = halves[1] ? halves[1].split(":").filter(Boolean) : [];
    const missing = halves.length === 2 ? 8 - (left.length + right.length) : 0;
    if (missing < 0 || (halves.length === 1 && left.length !== 8)) return null;
    const groups = [...left, ...Array<string>(missing).fill("0"), ...right];
    if (groups.length !== 8) return null;
    let val = 0n;
    for (const g of groups) {
      const n = Number.parseInt(g, 16);
      if (!Number.isInteger(n) || n < 0 || n > 0xffff) return null;
      val = (val << 16n) | BigInt(n);
    }
    const shift = BigInt(128 - prefixLen);
    return { isV6: true, network: (val >> shift) << shift, prefixLen };
  }

  if (prefixLen > 32) return null;
  const parts = ipStr.split(".");
  if (parts.length !== 4) return null;
  let val = 0n;
  for (const p of parts) {
    const n = Number.parseInt(p, 10);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    val = (val << 8n) | BigInt(n);
  }
  const shift = BigInt(32 - prefixLen);
  return { isV6: false, network: (val >> shift) << shift, prefixLen };
}

function normalizeGeofeedGeo(
  rawCountry: string,
  rawSubdiv: string,
  rawCity: string,
): GeofeedGeo | null {
  let iso = rawCountry.trim().toUpperCase();
  if (iso === "UK") iso = "GB";
  let subdiv = rawSubdiv.trim().toUpperCase();
  if (iso === "CN" && ["CN-HK", "CN-MO", "CN-TW", "HK", "MO", "TW"].includes(subdiv)) {
    iso = subdiv.replace(/^CN-/, "");
    subdiv = "";
  }
  if (!/^[A-Z]{2}$/.test(iso) || DISALLOWED_COUNTRY_CODES.has(iso)) return null;
  const subIso = subdiv.startsWith(`${iso}-`) ? subdiv.slice(iso.length + 1) : subdiv;
  return {
    isoCode: iso,
    subdivisionIso: subIso,
    cityEn: rawCity.trim(),
  };
}

function parseGeofeedTable(csvText: string): GeofeedCidr[] {
  const entries: GeofeedCidr[] = [];
  for (const line of csvText.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const cols = parseCsvRow(trimmed);
    if (cols.length < 2) continue;
    const parsed = parseCidrBigInt(cols[0] ?? "");
    const geo = normalizeGeofeedGeo(cols[1] ?? "", cols[2] ?? "", cols[3] ?? "");
    if (!parsed || !geo) continue;
    entries.push({ ...parsed, geo });
  }
  return entries;
}

function resolveGeofeedForCidr(
  cidrStr: string,
  exactMap: Map<string, GeofeedGeo>,
  list: GeofeedCidr[],
): GeofeedGeo | null {
  const direct = exactMap.get(cidrStr.trim());
  if (direct) return direct;
  const parsed = parseCidrBigInt(cidrStr);
  if (!parsed) return null;
  const totalBits = parsed.isV6 ? 128 : 32;
  let best: GeofeedCidr | null = null;
  for (const cand of list) {
    if (cand.isV6 !== parsed.isV6 || cand.prefixLen > parsed.prefixLen) continue;
    const shift = BigInt(totalBits - cand.prefixLen);
    if (parsed.network >> shift === cand.network >> shift) {
      if (!best || cand.prefixLen > best.prefixLen) {
        best = cand;
      }
    }
  }
  return best?.geo ?? null;
}

function enrichCloudRegion(
  provider: CloudProviderId,
  region: string,
  isoCode: string,
  subdivisionIso: string,
  cityEn: string,
  validIsos: Set<string>,
  countryTzByIso: Map<string, string>,
  statesByCountry: Map<string, Dr5hnState[]>,
  citiesByCountry: Map<string, CityRecord[]>,
  hintLat?: number,
  hintLon?: number,
): CloudRegionMetadataEntry | null {
  let iso = isoCode.trim().toUpperCase();
  if (iso === "UK") iso = "GB";
  if (!validIsos.has(iso)) return null;

  const states = statesByCountry.get(iso) ?? [];
  const cities = citiesByCountry.get(iso) ?? [];

  let matchedCity: CityRecord | undefined;
  const cityKey = normalizeTextKey(cityEn);
  if (cityKey) {
    matchedCity = cities
      .filter(
        (c) =>
          normalizeTextKey(c.asciiName) === cityKey ||
          normalizeTextKey(c.name) === cityKey ||
          c.altNames.some((alt) => normalizeTextKey(alt) === cityKey),
      )
      .sort((a, b) => b.population - a.population)[0];
  } else if (hintLat !== undefined && hintLon !== undefined) {
    matchedCity = [...cities].sort(
      (a, b) =>
        haversineKm(hintLat, hintLon, a.lat, a.lon) - haversineKm(hintLat, hintLon, b.lat, b.lon),
    )[0];
  }

  let subIso = subdivisionIso.trim().toUpperCase();
  if (subIso.startsWith(`${iso}-`)) subIso = subIso.slice(iso.length + 1);
  let subEn = "";

  const lat = hintLat ?? matchedCity?.lat ?? 0;
  const lon = hintLon ?? matchedCity?.lon ?? 0;

  if (subIso) {
    subEn = states.find((s) => s.iso2 === subIso)?.name ?? "";
  } else if (matchedCity && ["US"].includes(iso) && matchedCity.admin1) {
    subIso = matchedCity.admin1.toUpperCase();
    subEn = states.find((s) => s.iso2 === subIso)?.name ?? "";
  } else if (lat !== 0 && lon !== 0 && states.length > 0 && !["HK", "MO", "SG"].includes(iso)) {
    const nearestState = states
      .filter((s) => s.lat !== 0 || s.lon !== 0)
      .sort((a, b) => haversineKm(lat, lon, a.lat, a.lon) - haversineKm(lat, lon, b.lat, b.lon))[0];
    if (nearestState && haversineKm(lat, lon, nearestState.lat, nearestState.lon) <= 350) {
      subIso = nearestState.iso2;
      subEn = nearestState.name;
    }
  }

  return {
    provider,
    region,
    isoCode: iso,
    subdivisionIso: subIso,
    subdivisionEn: subEn,
    cityEn: cityEn || matchedCity?.asciiName || "",
    tz: matchedCity?.timezone || countryTzByIso.get(iso) || "UTC",
    lat: roundCoord(lat),
    lon: roundCoord(lon),
  };
}

function buildCloudRegions(
  awsIpJson: string,
  awsGeofeedCsv: string,
  awsRegionsJson: string,
  gcpCloudJson: string,
  gcpGeofeedCsv: string,
  oracleJson: string,
  azureJson: string,
  countries: CountryMetadataEntry[],
  dr5hnStates: Dr5hnState[],
  cities: CityRecord[],
): CloudRegionMetadataEntry[] {
  const validIsos = new Set(countries.map((c) => c.isoCode));
  const countryByIso = new Map(countries.map((c) => [c.isoCode, c]));
  const countryTzByIso = new Map(countries.map((c) => [c.isoCode, c.defaultTz]));

  const statesByCountry = new Map<string, Dr5hnState[]>();
  for (const s of dr5hnStates) {
    const list = statesByCountry.get(s.countryCode) ?? [];
    list.push(s);
    statesByCountry.set(s.countryCode, list);
  }

  const citiesByCountry = new Map<string, CityRecord[]>();
  for (const c of cities) {
    const list = citiesByCountry.get(c.country) ?? [];
    list.push(c);
    citiesByCountry.set(c.country, list);
  }

  const out: CloudRegionMetadataEntry[] = [];
  const seenKeys = new Set<string>();
  const pushRegion = (entry: CloudRegionMetadataEntry | null): void => {
    if (!entry) return;
    const key = `${entry.provider}/${entry.region}`;
    if (seenKeys.has(key)) return;
    seenKeys.add(key);
    out.push(entry);
  };

  // 1. AWS (join ip-ranges.json with aws-ip-ranges.csv + jsonmaur fallback)
  const awsFeedList = parseGeofeedTable(awsGeofeedCsv);
  const awsFeedExact = new Map<string, GeofeedGeo>();
  for (const line of awsGeofeedCsv.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const cols = parseCsvRow(t);
    const geo = normalizeGeofeedGeo(cols[1] ?? "", cols[2] ?? "", cols[3] ?? "");
    if (cols[0] && geo) awsFeedExact.set(cols[0].trim(), geo);
  }

  const awsParsed = JSON.parse(awsIpJson) as {
    prefixes?: Array<{ ip_prefix?: string; region?: string }>;
    ipv6_prefixes?: Array<{ ipv6_prefix?: string; region?: string }>;
  };
  const awsVotes = new Map<string, Map<string, { count: number; geo: GeofeedGeo }>>();
  const awsRegionsAll = new Set<string>();
  const awsItems: Array<{ cidr: string | undefined; region: string | undefined }> = [
    ...(awsParsed.prefixes ?? []).map((p) => ({ cidr: p.ip_prefix, region: p.region })),
    ...(awsParsed.ipv6_prefixes ?? []).map((p) => ({ cidr: p.ipv6_prefix, region: p.region })),
  ];
  for (const item of awsItems) {
    const reg = item.region?.trim();
    const cidr = item.cidr?.trim();
    if (!reg || reg === "GLOBAL") continue;
    awsRegionsAll.add(reg);
    if (!cidr) continue;
    const geo = resolveGeofeedForCidr(cidr, awsFeedExact, awsFeedList);
    if (!geo) continue;
    const regVotes = awsVotes.get(reg) ?? new Map<string, { count: number; geo: GeofeedGeo }>();
    const vk = `${geo.isoCode}|${geo.subdivisionIso}|${geo.cityEn}`;
    const prev = regVotes.get(vk);
    regVotes.set(vk, { count: (prev?.count ?? 0) + 1, geo });
    awsVotes.set(reg, regVotes);
  }

  const jsonmaurArr = JSON.parse(awsRegionsJson) as Array<{
    code?: string;
    name?: string;
  }>;
  const awsFallbackMeta = new Map<string, string>();
  for (const r of jsonmaurArr) {
    if (r.code && r.name) awsFallbackMeta.set(r.code.trim(), r.name.trim());
  }

  for (const reg of awsRegionsAll) {
    const regVotes = awsVotes.get(reg);
    if (regVotes && regVotes.size > 0) {
      const winner = [...regVotes.values()].sort((a, b) => b.count - a.count)[0];
      if (winner) {
        pushRegion(
          enrichCloudRegion(
            "aws",
            reg,
            winner.geo.isoCode,
            winner.geo.subdivisionIso,
            winner.geo.cityEn,
            validIsos,
            countryTzByIso,
            statesByCountry,
            citiesByCountry,
          ),
        );
        continue;
      }
    }
    const label = awsFallbackMeta.get(reg);
    if (label) {
      const paren = /\(([^)]+)\)/.exec(label)?.[1] ?? "";
      const firstWord = normalizeTextKey(paren.split(/[,\s]+/)[0] ?? "");
      const cityMatch = cities
        .filter((c) => normalizeTextKey(c.asciiName) === firstWord)
        .sort((a, b) => b.population - a.population)[0];
      if (cityMatch) {
        pushRegion(
          enrichCloudRegion(
            "aws",
            reg,
            cityMatch.country,
            "",
            cityMatch.asciiName,
            validIsos,
            countryTzByIso,
            statesByCountry,
            citiesByCountry,
          ),
        );
      }
    }
  }

  // 2. GCP (join cloud.json with cloud_geofeed)
  const gcpFeedList = parseGeofeedTable(gcpGeofeedCsv);
  const gcpFeedExact = new Map<string, GeofeedGeo>();
  for (const line of gcpGeofeedCsv.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const cols = parseCsvRow(t);
    const geo = normalizeGeofeedGeo(cols[1] ?? "", cols[2] ?? "", cols[3] ?? "");
    if (cols[0] && geo) gcpFeedExact.set(cols[0].trim(), geo);
  }
  const gcpParsed = JSON.parse(gcpCloudJson) as {
    prefixes?: Array<{ ipv4Prefix?: string; ipv6Prefix?: string; scope?: string }>;
  };
  const gcpVotes = new Map<string, Map<string, { count: number; geo: GeofeedGeo }>>();
  for (const item of gcpParsed.prefixes ?? []) {
    const scope = item.scope?.trim();
    const cidr = (item.ipv4Prefix ?? item.ipv6Prefix)?.trim();
    if (!scope || scope === "global" || !cidr) continue;
    const geo = resolveGeofeedForCidr(cidr, gcpFeedExact, gcpFeedList);
    if (!geo) continue;
    const regVotes = gcpVotes.get(scope) ?? new Map<string, { count: number; geo: GeofeedGeo }>();
    const vk = `${geo.isoCode}|${geo.subdivisionIso}|${geo.cityEn}`;
    const prev = regVotes.get(vk);
    regVotes.set(vk, { count: (prev?.count ?? 0) + 1, geo });
    gcpVotes.set(scope, regVotes);
  }
  for (const [scope, regVotes] of gcpVotes.entries()) {
    const winner = [...regVotes.values()].sort((a, b) => b.count - a.count)[0];
    if (winner) {
      pushRegion(
        enrichCloudRegion(
          "gcp",
          scope,
          winner.geo.isoCode,
          winner.geo.subdivisionIso,
          winner.geo.cityEn,
          validIsos,
          countryTzByIso,
          statesByCountry,
          citiesByCountry,
        ),
      );
    }
  }

  // 3. Oracle Cloud (resolve <prefix>-<city>-<n> via GeoNames cities5000)
  const cityBySlug = new Map<string, CityRecord[]>();
  for (const c of cities) {
    for (const raw of [c.asciiName, c.name]) {
      const slug = normalizeTextKey(raw);
      if (!slug) continue;
      const list = cityBySlug.get(slug) ?? [];
      list.push(c);
      cityBySlug.set(slug, list);
    }
  }
  const ociMacroContinents: Record<string, ContinentCode[]> = {
    eu: ["EU"],
    af: ["AF"],
    sa: ["SA"],
    me: ["AS"],
    ap: ["AS", "OC"],
  };
  const oracleParsed = JSON.parse(oracleJson) as {
    regions?: Array<{ region?: string }>;
  };
  for (const item of oracleParsed.regions ?? []) {
    const reg = item.region?.trim();
    if (!reg) continue;
    const cleaned = reg.replace(/-gov-/, "-").replace(/-dcc-/, "-");
    const parts = cleaned.split("-");
    if (parts.length < 3) continue;
    const prefix = (parts[0] ?? "").toLowerCase();
    const citySlug = normalizeTextKey(parts.slice(1, -1).join(""));
    const candidates = cityBySlug.get(citySlug) ?? [];
    if (candidates.length === 0) continue;

    const upperPrefix = prefix === "uk" ? "GB" : prefix.toUpperCase();
    const macroCont = ociMacroContinents[prefix];
    let pool = candidates;
    if (macroCont) {
      const byCont = candidates.filter((c) => {
        const cont = countryByIso.get(c.country)?.continentCode;
        return cont !== undefined && macroCont.includes(cont);
      });
      if (byCont.length > 0) pool = byCont;
    } else if (validIsos.has(upperPrefix)) {
      const byIso = candidates.filter((c) => c.country === upperPrefix);
      if (byIso.length > 0) pool = byIso;
    }

    const best = [...pool].sort((a, b) => b.population - a.population)[0];
    if (best) {
      pushRegion(
        enrichCloudRegion(
          "oracle",
          reg,
          best.country,
          "",
          best.asciiName,
          validIsos,
          countryTzByIso,
          statesByCountry,
          citiesByCountry,
          best.lat,
          best.lon,
        ),
      );
    }
  }

  // 4. Azure Regions (reverse geocode coordinates against GeoNames cities5000)
  const azureParsed = JSON.parse(azureJson) as Record<
    string,
    { Name?: string; Latitude?: string | number; Longitude?: string | number }
  >;
  for (const [key, item] of Object.entries(azureParsed)) {
    const regionId = (item.Name ?? key).trim().toLowerCase();
    if (!regionId) continue;
    const lat = Number.parseFloat(String(item.Latitude ?? ""));
    const lon = Number.parseFloat(String(item.Longitude ?? ""));
    if (!Number.isFinite(lat) || !Number.isFinite(lon) || (lat === 0 && lon === 0)) continue;

    let nearest: CityRecord | undefined;
    let bestDist = Number.POSITIVE_INFINITY;
    for (const c of cities) {
      if (Math.abs(c.lat - lat) > 2 || Math.abs(c.lon - lon) > 2.5) continue;
      const d = haversineKm(lat, lon, c.lat, c.lon);
      if (d < bestDist) {
        bestDist = d;
        nearest = c;
      }
    }
    if (nearest && bestDist <= 150) {
      pushRegion(
        enrichCloudRegion(
          "azure",
          regionId,
          nearest.country,
          "",
          nearest.asciiName,
          validIsos,
          countryTzByIso,
          statesByCountry,
          citiesByCountry,
          lat,
          lon,
        ),
      );
    }
  }

  out.sort((a, b) => `${a.provider}/${a.region}`.localeCompare(`${b.provider}/${b.region}`));
  return out;
}

function parseMaxCacheAgeSecs(): number {
  const idx = process.argv.indexOf("--max-cache-age-secs");
  if (idx >= 0) {
    const val = Number.parseInt(process.argv[idx + 1] ?? "", 10);
    if (Number.isFinite(val) && val >= 0) return val;
  }
  const envVal = Number.parseInt(process.env.METADATA_MAX_CACHE_AGE_SECS ?? "", 10);
  return Number.isFinite(envVal) && envVal >= 0 ? envVal : 43200;
}

async function main(): Promise<void> {
  const currentDir = dirname(fileURLToPath(import.meta.url));
  const repoRoot = resolve(currentDir, "..");
  const outPath = resolve(currentDir, "generated", "geoip-metadata.json");

  if (process.argv.includes("--check")) {
    const raw = await readFile(outPath, "utf8");
    const parsed = JSON.parse(raw) as CompiledMetadataBundle;
    validateMetadataBundle(parsed);
    console.log(
      `Verified metadata bundle (${parsed.countries.length} countries, ${parsed.cnDivisions.length} CN divisions, ${parsed.cloudRegions.length} cloud regions).`,
    );
    return;
  }

  const fallbackExisting = process.argv.includes("--fallback-existing");
  const maxAgeSecs = parseMaxCacheAgeSecs();

  try {
    const payloadEntries = await Promise.all(
      METADATA_UPSTREAMS.map(async (src) => {
        const text = await fetchUpstreamText(src, repoRoot, maxAgeSecs);
        return [src.id, text] as const;
      }),
    );
    const payloads = new Map<string, string>(payloadEntries);
    const getPayload = (id: string): string => {
      const v = payloads.get(id);
      if (v === undefined) throw new Error(`Missing fetched payload '${id}'`);
      return v;
    };

    const cities = parseCities5000(getPayload("geonames_cities5000"));
    const dr5hnStates = parseDr5hnStates(getPayload("dr5hn_states"));
    const debianIso3166_2 = parseDebianIso3166_2(getPayload("debian_iso_3166_2"));

    const countries = buildCountries(
      getPayload("geonames_country_info"),
      getPayload("mledoze_countries"),
      getPayload("cldr_country_zh_cn"),
      getPayload("cldr_country_en"),
      getPayload("eu_membership"),
      getPayload("iana_zone1970"),
      cities,
    );

    const cnDivisions = buildCnDivisions(
      getPayload("modood_cn_pca"),
      getPayload("areacity_cn_level3"),
      dr5hnStates,
      debianIso3166_2,
      cities,
    );

    const cloudRegions = buildCloudRegions(
      getPayload("aws_ip_ranges"),
      getPayload("aws_geofeed"),
      getPayload("jsonmaur_aws_regions"),
      getPayload("gcp_cloud_ranges"),
      getPayload("gcp_cloud_geofeed"),
      getPayload("oracle_cloud_ranges"),
      getPayload("azure_regions"),
      countries,
      dr5hnStates,
      cities,
    );

    const bundle: CompiledMetadataBundle = {
      schemaVersion: 1,
      upstreams: METADATA_UPSTREAMS.map((s) => `${s.id}:${s.repoOrSite}`),
      countries,
      cnDivisions,
      cloudRegions,
    };

    validateMetadataBundle(bundle);
    const serialized = `${JSON.stringify(bundle, null, 2)}\n`;
    await mkdir(dirname(outPath), { recursive: true });
    await writeFile(outPath, serialized, "utf8");

    const l1 = cnDivisions.filter((d) => d.level === 1).length;
    const l2 = cnDivisions.filter((d) => d.level === 2).length;
    const l3 = cnDivisions.filter((d) => d.level === 3).length;
    console.log(
      `Wrote ${outPath} (${countries.length} countries, CN=${l1}/${l2}/${l3} divisions, ${cloudRegions.length} cloud regions).`,
    );
  } catch (err) {
    if (fallbackExisting && existsSync(outPath)) {
      const existingRaw = await readFile(outPath, "utf8");
      const existingBundle = JSON.parse(existingRaw) as CompiledMetadataBundle;
      validateMetadataBundle(existingBundle);
      console.warn(
        `Live metadata sync failed (${String(err)}); retaining verified checked-in bundle ${outPath}.`,
      );
      return;
    }
    throw err;
  }
}

await main();
