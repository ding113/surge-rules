import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const ARTIFACT_NAMES = [
  "Country.mmdb",
  "Country-only.mmdb",
  "Country-cn.mmdb",
  "ASN.mmdb",
  "Adblock.sgmodule",
  "Adblock.list",
  "Privacy.list",
  "Direct.list",
  "AI.list",
  "Payment.list",
  "Telemetry.list",
  "Proxy.list",
] as const;

function escapeXml(input: string): string {
  return input
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

export function renderUpdatedAtBadgeSvg(updatedAtCn: string): string {
  const badgeValue = escapeXml(`${updatedAtCn} UTC+8`);
  return `<svg xmlns="http://www.w3.org/2000/svg" width="234" height="20" role="img" aria-label="最新更新: ${badgeValue}">
  <title>最新更新: ${badgeValue}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="234" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="68" height="20" fill="#334155"/>
    <rect x="68" width="166" height="20" fill="#0a84ff"/>
    <rect width="234" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text aria-hidden="true" x="34" y="15" fill="#010101" fill-opacity=".3">最新更新</text>
    <text x="34" y="14">最新更新</text>
    <text aria-hidden="true" x="151" y="15" fill="#010101" fill-opacity=".3">${badgeValue}</text>
    <text x="151" y="14">${badgeValue}</text>
  </g>
</svg>
`;
}

function requireEnv(key: string): string {
  const val = process.env[key]?.trim();
  if (!val) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return val;
}

export interface ReleaseStageMetadataOptions {
  readonly stageDir: string;
  readonly distDir: string;
  readonly tag: string;
  readonly builtAtUtc: string;
  readonly updatedAtCn: string;
  readonly repo: string;
  readonly sourceCommit: string;
}

export async function generateReleaseStageMetadata(
  opts: ReleaseStageMetadataOptions,
): Promise<void> {
  const { stageDir, distDir, tag, builtAtUtc, updatedAtCn, repo, sourceCommit } = opts;

  const artifacts = await Promise.all(
    ARTIFACT_NAMES.map(async (name) => {
      const bytes = await readFile(resolve(distDir, name));
      const sha256 = createHash("sha256").update(bytes).digest("hex");
      return {
        name,
        sizeBytes: bytes.byteLength,
        sha256,
      };
    }),
  );

  const svg = renderUpdatedAtBadgeSvg(updatedAtCn);
  const metaJson = `${JSON.stringify(
    {
      tag,
      builtAtUtc,
      updatedAtCn,
      sourceCommit,
      artifacts,
    },
    null,
    2,
  )}\n`;

  const combinedNotes = (await readFile(resolve(distDir, "combined-notes.md"), "utf8")).trim();
  const shortSha = sourceCommit.slice(0, 7);
  const releaseReadme = [
    `# surge-rules (\`${tag}\`)`,
    "",
    `- 最新更新（北京时间）：\`${updatedAtCn}\``,
    `- 构建时间（UTC）：\`${builtAtUtc}\``,
    `- 源码提交：[\`${shortSha}\`](https://github.com/${repo}/commit/${sourceCommit})`,
    `- 最新 Release：[https://github.com/${repo}/releases/latest](https://github.com/${repo}/releases/latest)`,
    "- Cloudflare 镜像：[https://rule-set.ygxz.de](https://rule-set.ygxz.de)",
    "",
    "---",
    "",
    combinedNotes,
    "",
  ].join("\n");

  await Promise.all([
    writeFile(resolve(stageDir, "updated-at.svg"), svg, "utf8"),
    writeFile(resolve(stageDir, "build-meta.json"), metaJson, "utf8"),
    writeFile(resolve(stageDir, "README.md"), releaseReadme, "utf8"),
  ]);

  console.log(`Generated updated-at.svg, build-meta.json, and README.md in ${stageDir}.`);
}

async function main(): Promise<void> {
  await generateReleaseStageMetadata({
    stageDir: resolve(requireEnv("STAGE_DIR")),
    distDir: resolve(process.env.DIST_DIR?.trim() || "dist"),
    tag: requireEnv("RELEASE_TAG"),
    builtAtUtc: requireEnv("UTC_ISO"),
    updatedAtCn: requireEnv("UPDATED_AT"),
    repo: requireEnv("GITHUB_REPOSITORY"),
    sourceCommit: requireEnv("GITHUB_SHA"),
  });
}

if (import.meta.main) {
  await main();
}
