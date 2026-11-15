import { mkdir, readFile, writeFile } from "node:fs/promises";
import { isIPv4, isIPv6 } from "node:net";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { GEOIP_OVERRIDES } from "./index.ts";

const ISO_ALPHA2_RE = /^[A-Z]{2}$/;
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

async function main(): Promise<void> {
  validateAll();

  const currentDir = dirname(fileURLToPath(import.meta.url));
  const outPath = resolve(currentDir, "generated", "geoip-overrides.json");
  const serialized = `${JSON.stringify(GEOIP_OVERRIDES, null, 2)}\n`;

  const checkMode = process.argv.includes("--check");
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
    console.log(
      `Verified overrides in sync (${GEOIP_OVERRIDES.specialNetworks.length} special, ${GEOIP_OVERRIDES.countryOverrides.length} country, ${GEOIP_OVERRIDES.cnExclusions.length} CN exclusions, ${GEOIP_OVERRIDES.asnOverrides.length} ASN).`,
    );
    return;
  }

  await mkdir(dirname(outPath), { recursive: true });
  await writeFile(outPath, serialized, "utf8");
  console.log(`Wrote ${outPath} (${serialized.length} bytes).`);
}

await main();
