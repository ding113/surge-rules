import { describe, expect, it } from "bun:test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

interface MockR2ObjectMeta {
  readonly size: number;
  readonly httpEtag: string;
  readonly uploaded: Date;
  readonly contentType: string;
  readonly cacheControl?: string;
  writeHttpMetadata(headers: Headers): void;
}

interface MockR2ObjectBody extends MockR2ObjectMeta {
  readonly body: ReadableStream<Uint8Array>;
}

interface WorkerModule {
  default: {
    fetch(request: Request, env: MockWorkerEnv): Promise<Response>;
    scheduled(controller: { cron: string }, env: MockWorkerEnv): Promise<void>;
  };
}

interface MockWorkerEnv {
  RELEASE_BUCKET: {
    head(key: string): Promise<MockR2ObjectMeta | null>;
    get(
      key: string,
      options?: { onlyIf?: Headers },
    ): Promise<MockR2ObjectBody | MockR2ObjectMeta | null>;
  };
  ASSETS: {
    fetch(request: Request): Promise<Response>;
  };
  RELEASE_TAG?: string;
  GH_TOKEN?: string;
  GH_REPO?: string;
  GH_WORKFLOW?: string;
  GH_REF?: string;
}

function makeR2Object(
  payload: string,
  contentType: string,
  etag = '"abc123def456"',
  uploaded = new Date("2026-11-16T16:26:07Z"),
): { meta: MockR2ObjectMeta; full: MockR2ObjectBody } {
  const bytes = new TextEncoder().encode(payload);
  const meta: MockR2ObjectMeta = {
    size: bytes.byteLength,
    httpEtag: etag,
    uploaded,
    contentType,
    writeHttpMetadata(headers: Headers) {
      headers.set("Content-Type", contentType);
    },
  };
  return {
    meta,
    full: {
      ...meta,
      body: new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(bytes);
          controller.close();
        },
      }),
    },
  };
}

const workerPath = resolve(import.meta.dir, "../cloudflare/worker.js");
const wranglerPath = resolve(import.meta.dir, "../cloudflare/wrangler.jsonc");

describe("cloudflare worker & Workers Cache configuration", () => {
  it("enables per-version Workers Cache in wrangler.jsonc with up-to-date compatibility_date", async () => {
    const raw = await readFile(wranglerPath, "utf8");
    const stripped = raw.replace(/^\s*\/\/.*$/gm, "");
    const config = JSON.parse(stripped) as {
      compatibility_date: string;
      cache?: { enabled?: boolean; cross_version_cache?: boolean };
      vars?: { RELEASE_TAG?: string };
    };

    expect(config.compatibility_date >= "2026-11-16").toBe(true);
    expect(config.cache?.enabled).toBe(true);
    // Per-version keying (default) must stay enabled so every release deploy immediately
    // switches to the freshly uploaded R2 build without serving stale previous-version artifacts.
    expect(config.cache?.cross_version_cache).toBeUndefined();
    expect(config.vars?.RELEASE_TAG).toBe("dev");
  });

  it("serves rulesets, MMDBs, and badges with split client/edge cache headers and full 200 bodies", async () => {
    const mod = (await import(workerPath)) as WorkerModule;
    let getOptionsSeen: { onlyIf?: Headers } | undefined;

    const store: Record<string, ReturnType<typeof makeR2Object>> = {
      "Adblock.list": makeR2Object("DOMAIN,ads.example.com\n", "text/plain; charset=utf-8"),
      "Country.mmdb": makeR2Object("MMDB-BINARY", "application/octet-stream", '"mmdb-etag"'),
      "updated-at.svg": makeR2Object("<svg/>", "image/svg+xml; charset=utf-8", '"svg-etag"'),
    };

    const env: MockWorkerEnv = {
      RELEASE_TAG: "release-20261116-1621",
      RELEASE_BUCKET: {
        async head(key) {
          return store[key]?.meta ?? null;
        },
        async get(key, options) {
          getOptionsSeen = options;
          return store[key]?.full ?? null;
        },
      },
      ASSETS: {
        async fetch() {
          return new Response("Not Found", { status: 404 });
        },
      },
    };

    // 1. Ruleset (.list): short client TTL + ETag revalidation; 30m edge TTL + 24h SWR/SIE
    const listRes = await mod.default.fetch(
      new Request("https://rule-set.ygxz.de/Adblock.list", {
        headers: { Range: "bytes=0-5" },
      }),
      env,
    );
    expect(listRes.status).toBe(200);
    expect(await listRes.text()).toBe("DOMAIN,ads.example.com\n");
    expect(listRes.headers.get("Cache-Control")).toBe("public, max-age=60, must-revalidate");
    expect(listRes.headers.get("Cloudflare-CDN-Cache-Control")).toBe(
      "public, max-age=1800, stale-while-revalidate=86400, stale-if-error=86400",
    );
    // Edge directive must not include s-maxage / must-revalidate / proxy-revalidate (RFC 9111 §4.2.4)
    expect(listRes.headers.get("Cloudflare-CDN-Cache-Control")).not.toContain("s-maxage");
    expect(listRes.headers.get("Cloudflare-CDN-Cache-Control")).not.toContain("must-revalidate");
    expect(listRes.headers.get("Cache-Tag")).toBe("r2,r2-ruleset,artifact:Adblock.list");
    expect(listRes.headers.get("Content-Length")).toBe("23");
    expect(listRes.headers.get("ETag")).toBe('"abc123def456"');
    expect(listRes.headers.get("Accept-Ranges")).toBe("bytes");
    expect(listRes.headers.get("X-Release-Tag")).toBe("release-20261116-1621");
    expect(getOptionsSeen?.onlyIf).toBeInstanceOf(Headers);

    // 2. MMDB (.mmdb): 5m client TTL + 1h edge TTL
    const mmdbRes = await mod.default.fetch(
      new Request("https://rule-set.ygxz.de/Country.mmdb"),
      env,
    );
    expect(mmdbRes.status).toBe(200);
    expect(mmdbRes.headers.get("Cache-Control")).toBe("public, max-age=300, must-revalidate");
    expect(mmdbRes.headers.get("Cloudflare-CDN-Cache-Control")).toBe(
      "public, max-age=3600, stale-while-revalidate=86400, stale-if-error=86400",
    );
    expect(mmdbRes.headers.get("Cache-Tag")).toBe("r2,r2-mmdb,artifact:Country.mmdb");

    // 3. Metadata badge (updated-at.svg): immediate client ETag validation (no `no-store` bypass) + 60s edge cache
    const svgRes = await mod.default.fetch(
      new Request("https://rule-set.ygxz.de/updated-at.svg"),
      env,
    );
    expect(svgRes.status).toBe(200);
    expect(svgRes.headers.get("Cache-Control")).toBe("public, max-age=0, must-revalidate");
    expect(svgRes.headers.get("Cache-Control")).not.toContain("no-store");
    expect(svgRes.headers.get("Cloudflare-CDN-Cache-Control")).toBe(
      "public, max-age=60, stale-while-revalidate=300, stale-if-error=86400",
    );
    expect(svgRes.headers.get("Cache-Tag")).toBe("r2,r2-meta,artifact:updated-at.svg");
  });

  it("handles HEAD, conditional 304 revalidation, query-string canonicalization, and scanner 404s", async () => {
    const mod = (await import(workerPath)) as WorkerModule;
    const obj = makeR2Object("DOMAIN,ai.example.com\n", "text/plain; charset=utf-8", '"ai-etag"');
    let r2Calls = 0;

    const env: MockWorkerEnv = {
      RELEASE_BUCKET: {
        async head(key) {
          r2Calls += 1;
          return key === "AI.list" ? obj.meta : null;
        },
        async get(key, options) {
          r2Calls += 1;
          if (key !== "AI.list") return null;
          if (options?.onlyIf?.get("If-None-Match") === '"ai-etag"') {
            return obj.meta;
          }
          return obj.full;
        },
      },
      ASSETS: {
        async fetch() {
          return new Response("Not Found", { status: 404 });
        },
      },
    };

    // Query-string cache-busting attempt redirects to canonical path without touching R2
    const redirectRes = await mod.default.fetch(
      new Request("https://rule-set.ygxz.de/AI.list?utm_source=test&t=123"),
      env,
    );
    expect(redirectRes.status).toBe(301);
    expect(redirectRes.headers.get("Location")).toBe("https://rule-set.ygxz.de/AI.list");
    expect(r2Calls).toBe(0);

    // Scanner paths with unrelated extensions never touch R2 and get negative-cached 404
    const scannerRes = await mod.default.fetch(
      new Request("https://rule-set.ygxz.de/favicon.ico"),
      env,
    );
    expect(scannerRes.status).toBe(404);
    expect(scannerRes.headers.get("Cache-Control")).toBe("public, max-age=60");
    expect(scannerRes.headers.get("Cloudflare-CDN-Cache-Control")).toBe("public, max-age=300");
    expect(r2Calls).toBe(0);

    // Conditional GET returns 304 with cache headers preserved for RFC 9111 §4.3.4 freshening
    const notModifiedRes = await mod.default.fetch(
      new Request("https://rule-set.ygxz.de/AI.list", {
        headers: { "If-None-Match": '"ai-etag"' },
      }),
      env,
    );
    expect(notModifiedRes.status).toBe(304);
    expect(notModifiedRes.headers.get("ETag")).toBe('"ai-etag"');
    expect(notModifiedRes.headers.get("Cloudflare-CDN-Cache-Control")).toContain("max-age=1800");
    expect(notModifiedRes.headers.has("Content-Length")).toBe(false);
    expect(r2Calls).toBe(1);

    // HEAD returns metadata + Content-Length
    const headRes = await mod.default.fetch(
      new Request("https://rule-set.ygxz.de/AI.list", { method: "HEAD" }),
      env,
    );
    expect(headRes.status).toBe(200);
    expect(headRes.headers.get("Content-Length")).toBe("22");
    expect(headRes.headers.get("ETag")).toBe('"ai-etag"');
  });
});
