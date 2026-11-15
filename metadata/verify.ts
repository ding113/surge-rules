import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { CompiledMetadataBundle } from "./schema.ts";

const CONTINENT_CODES = new Set(["AF", "AN", "AS", "EU", "NA", "OC", "SA"]);
const REQUIRED_COUNTRY_CODES = ["CN", "HK", "MO", "TW", "US", "GB", "JP", "DE", "SG"];
const REQUIRED_MAINLAND_CN_PROVS = [
  "BJ",
  "TJ",
  "HE",
  "SX",
  "NM",
  "LN",
  "JL",
  "HL",
  "SH",
  "JS",
  "ZJ",
  "AH",
  "FJ",
  "JX",
  "SD",
  "HA",
  "HB",
  "HN",
  "GD",
  "GX",
  "HI",
  "CQ",
  "SC",
  "GZ",
  "YN",
  "XZ",
  "SN",
  "GS",
  "QH",
  "NX",
  "XJ",
];

export function validateMetadataBundle(bundle: CompiledMetadataBundle): void {
  if (bundle.schemaVersion !== 1) {
    throw new Error(`Unsupported metadata schemaVersion: ${bundle.schemaVersion}`);
  }
  if (bundle.countries.length < 245) {
    throw new Error(`Expected >= 245 countries, got ${bundle.countries.length}`);
  }

  const countryByIso = new Map<string, (typeof bundle.countries)[number]>();
  for (const c of bundle.countries) {
    if (!/^[A-Z]{2}$/.test(c.isoCode)) {
      throw new Error(`Invalid country isoCode '${c.isoCode}'`);
    }
    if (!CONTINENT_CODES.has(c.continentCode)) {
      throw new Error(`Invalid continentCode '${c.continentCode}' on ${c.isoCode}`);
    }
    if (c.nameEn.trim() === "" || c.nameZh.trim() === "" || c.defaultTz.trim() === "") {
      throw new Error(`Incomplete country metadata on ${c.isoCode}`);
    }
    if (countryByIso.has(c.isoCode)) {
      throw new Error(`Duplicate country isoCode '${c.isoCode}'`);
    }
    countryByIso.set(c.isoCode, c);
  }
  for (const req of REQUIRED_COUNTRY_CODES) {
    if (!countryByIso.has(req)) {
      throw new Error(`Missing required country '${req}'`);
    }
  }

  const provIsos = new Set<string>();
  let l2Count = 0;
  let l3Count = 0;
  const seenAdcodes = new Set<string>();
  for (const d of bundle.cnDivisions) {
    if (!/^\d{6}$/.test(d.adcode)) {
      throw new Error(`Invalid CN division adcode '${d.adcode}'`);
    }
    if (seenAdcodes.has(d.adcode)) {
      throw new Error(`Duplicate CN division adcode '${d.adcode}'`);
    }
    seenAdcodes.add(d.adcode);

    if (d.level === 1) {
      provIsos.add(d.isoCode);
      if (d.provinceZh === "" || d.provinceEn === "") {
        throw new Error(`Missing province names for ${d.adcode}`);
      }
    } else if (d.level === 2) {
      l2Count += 1;
      if (d.cityZh === "" || d.cityEn === "") {
        throw new Error(`Missing city names for ${d.adcode} (${d.cityZh})`);
      }
    } else if (d.level === 3) {
      l3Count += 1;
      if (d.districtZh === "" || d.districtEn === "") {
        throw new Error(`Missing district names for ${d.adcode} (${d.districtZh})`);
      }
    }
    if (d.lat !== 0 && (d.lat < 3 || d.lat > 55 || d.lon < 70 || d.lon > 136)) {
      throw new Error(`Out-of-bounds CN coordinates (${d.lat}, ${d.lon}) on ${d.adcode}`);
    }
  }
  for (const prov of REQUIRED_MAINLAND_CN_PROVS) {
    if (!provIsos.has(prov)) {
      throw new Error(`Missing required Mainland China province ISO '${prov}'`);
    }
  }
  if (l2Count < 300 || l3Count < 2500) {
    throw new Error(
      `Insufficient CN divisions converted from upstream (level2=${l2Count}, level3=${l3Count})`,
    );
  }

  if (bundle.cloudRegions.length < 100) {
    throw new Error(`Expected >= 100 cloud regions, got ${bundle.cloudRegions.length}`);
  }
  const cloudKeys = new Set<string>();
  for (const r of bundle.cloudRegions) {
    const key = `${r.provider}/${r.region}`;
    if (cloudKeys.has(key)) {
      throw new Error(`Duplicate cloud region '${key}'`);
    }
    cloudKeys.add(key);
    if (!countryByIso.has(r.isoCode)) {
      throw new Error(`Cloud region ${key} references unknown country '${r.isoCode}'`);
    }
  }
  for (const requiredRegion of [
    "aws/us-east-1",
    "aws/eu-north-1",
    "aws/ap-east-1",
    "gcp/us-central1",
    "gcp/europe-west3",
    "oracle/us-ashburn-1",
  ]) {
    if (!cloudKeys.has(requiredRegion)) {
      throw new Error(`Missing expected cloud region '${requiredRegion}'`);
    }
  }
}

async function main(): Promise<void> {
  const currentDir = dirname(fileURLToPath(import.meta.url));
  const targetPath = resolve(currentDir, "generated", "geoip-metadata.json");
  const raw = await readFile(targetPath, "utf8");
  const parsed = JSON.parse(raw) as CompiledMetadataBundle;
  validateMetadataBundle(parsed);

  const l1 = parsed.cnDivisions.filter((d) => d.level === 1).length;
  const l2 = parsed.cnDivisions.filter((d) => d.level === 2).length;
  const l3 = parsed.cnDivisions.filter((d) => d.level === 3).length;
  console.log(
    `Verified metadata bundle (${parsed.countries.length} countries, CN=${l1}/${l2}/${l3} divisions, ${parsed.cloudRegions.length} cloud regions).`,
  );
}

if (import.meta.main) {
  await main();
}
