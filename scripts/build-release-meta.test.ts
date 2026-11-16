import { describe, expect, it } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateReleaseStageMetadata, renderUpdatedAtBadgeSvg } from "./build-release-meta.ts";

describe("build-release-meta", () => {
  it("renders valid uncached SVG timestamp badge escaping special XML chars", () => {
    const svg = renderUpdatedAtBadgeSvg("2026-11-16 12:17");
    expect(svg).toContain("<svg ");
    expect(svg).toContain("最新更新");
    expect(svg).toContain("2026-11-16 12:17 UTC+8");

    const escaped = renderUpdatedAtBadgeSvg("2026-11-16 <test>&\"'");
    expect(escaped).toContain("&lt;test&gt;&amp;&quot;&apos;");
  });

  it("writes updated-at.svg, build-meta.json, and release README.md for all 12 artifacts", async () => {
    const root = await mkdtemp(join(tmpdir(), "surge-release-meta-"));
    try {
      const distDir = join(root, "dist");
      const stageDir = join(root, "stage");
      await Promise.all([
        mkdir(distDir, { recursive: true }),
        mkdir(stageDir, { recursive: true }),
      ]);

      const names = [
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
      ];
      for (const name of names) {
        await writeFile(join(distDir, name), `payload:${name}\n`, "utf8");
      }
      await writeFile(join(distDir, "combined-notes.md"), "## Summary\n\nAll green.\n", "utf8");

      await generateReleaseStageMetadata({
        stageDir,
        distDir,
        tag: "release-20261116-0417",
        builtAtUtc: "2026-11-16T04:17:00Z",
        updatedAtCn: "2026-11-16 12:17",
        repo: "ding113/surge-rules",
        sourceCommit: "7229121260d8d4f22288298cc2771bac1228a215",
      });

      const [svg, metaRaw, readme] = await Promise.all([
        readFile(join(stageDir, "updated-at.svg"), "utf8"),
        readFile(join(stageDir, "build-meta.json"), "utf8"),
        readFile(join(stageDir, "README.md"), "utf8"),
      ]);

      expect(svg).toContain("2026-11-16 12:17 UTC+8");
      const meta = JSON.parse(metaRaw) as {
        tag: string;
        updatedAtCn: string;
        artifacts: Array<{ name: string; sizeBytes: number; sha256: string }>;
      };
      expect(meta.tag).toBe("release-20261116-0417");
      expect(meta.updatedAtCn).toBe("2026-11-16 12:17");
      expect(meta.artifacts).toHaveLength(12);
      expect(readme).toContain("# surge-rules (`release-20261116-0417`)");
      expect(readme).toContain("`7229121`");
      expect(readme).toContain("## Summary");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
