// Entry point of the `surge-rules` Worker (rule-set.ygxz.de).
//
// Requests are assets-first: `_redirects` and the static files in the `release` branch
// (install.html, Surge scripts) are served by the assets layer. Everything else passes
// through tiered Workers Cache (`cache.enabled = true` in wrangler.jsonc) in front of
// this Worker:
//   - Cache HIT: Cloudflare returns the cached response directly from the edge (0 Worker
//     CPU time, 0 R2 Class B reads), including automatic 206 Partial Content byte-range
//     slicing and conditional 304 Not Modified responses.
//   - Cache MISS / background revalidation: `serveFromR2` streams the full 200 OK object
//     from R2 (or answers 304 via `onlyIf`) with split client (`Cache-Control`) and edge
//     (`Cloudflare-CDN-Cache-Control`) directives so edge hit rates stay high while
//     clients revalidate promptly via ETag.
//   - Release updates: each `release.yml` run uploads fresh artifacts to R2 first and
//     then deploys a new Worker version (stamping `vars.RELEASE_TAG`). Because Workers
//     Cache includes the Worker version in its cache key by default, the new deployment
//     switches over to the fresh R2 build immediately without waiting for TTL expiry.
//   - scheduled: the hourly Cron Trigger that dispatches the GitHub `release.yml` workflow.
//
// Required secret: GH_TOKEN — fine-grained PAT scoped to the repo with Actions: read & write.

// Release artifacts and metadata live at flat root keys with known extensions;
// arbitrary scanner paths (/favicon.ico, /robots.txt, etc.) skip R2 completely.
const R2_KEY = /^[A-Za-z0-9][A-Za-z0-9._-]*\.(?:mmdb|list|sgmodule|json|svg)$/;

const CACHE_POLICIES = {
  meta: {
    tagGroup: "r2-meta",
    clientCacheControl: "public, max-age=0, must-revalidate",
    edgeCacheControl: "public, max-age=60, stale-while-revalidate=300, stale-if-error=86400",
  },
  mmdb: {
    tagGroup: "r2-mmdb",
    clientCacheControl: "public, max-age=300, must-revalidate",
    edgeCacheControl: "public, max-age=3600, stale-while-revalidate=86400, stale-if-error=86400",
  },
  ruleset: {
    tagGroup: "r2-ruleset",
    clientCacheControl: "public, max-age=60, must-revalidate",
    edgeCacheControl: "public, max-age=1800, stale-while-revalidate=86400, stale-if-error=86400",
  },
};

export default {
  async fetch(request, env) {
    const fromR2 = await serveFromR2(request, env);
    if (fromR2 !== null) return fromR2;

    const assetRes = await env.ASSETS.fetch(request);
    if (assetRes.status === 404 && !assetRes.headers.has("Cache-Control")) {
      const headers = new Headers(assetRes.headers);
      headers.set("Cache-Control", "public, max-age=60");
      headers.set("Cloudflare-CDN-Cache-Control", "public, max-age=300");
      return new Response(assetRes.body, { status: 404, headers });
    }
    return assetRes;
  },

  async scheduled(controller, env) {
    if (!env.GH_TOKEN) {
      throw new Error("GH_TOKEN secret is not configured; cannot dispatch workflow");
    }
    const url = `https://api.github.com/repos/${env.GH_REPO}/actions/workflows/${env.GH_WORKFLOW}/dispatches`;
    const res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.GH_TOKEN}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "surge-rules-worker",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ ref: env.GH_REF }),
    });
    if (!res.ok) {
      throw new Error(`workflow_dispatch failed: HTTP ${res.status} ${await res.text()}`);
    }
    console.log(
      `dispatched ${env.GH_REPO} ${env.GH_WORKFLOW}@${env.GH_REF} (cron "${controller.cron}")`,
    );
  },
};

/** Returns a Response for an R2-hosted artifact, or null to fall through to static assets. */
async function serveFromR2(request, env) {
  if (request.method !== "GET" && request.method !== "HEAD") return null;

  const url = new URL(request.url);
  const key = url.pathname.slice(1);
  if (!R2_KEY.test(key)) return null;

  // Canonicalize away random query strings (?t=..., ?utm_source=...) so cache-busting
  // parameters cannot partition Workers Cache keys or trigger repeated R2 reads.
  if (url.search !== "") {
    return new Response(null, {
      status: 301,
      headers: {
        Location: `${url.origin}${url.pathname}`,
        "Cache-Control": "public, max-age=300",
        "Cloudflare-CDN-Cache-Control": "public, max-age=3600",
      },
    });
  }

  if (request.method === "HEAD") {
    const meta = await env.RELEASE_BUCKET.head(key);
    if (meta === null) return null;
    const headers = objectHeaders(key, meta, env, true);
    return new Response(null, { status: 200, headers });
  }

  // Always request the full object (no `range`): Workers Cache strips inbound `Range`,
  // caches the complete 200 OK body, and performs byte-range slicing (206 / 416) at the
  // edge. Passing `onlyIf` lets edge revalidations short-circuit with 304 Not Modified.
  const object = await env.RELEASE_BUCKET.get(key, {
    onlyIf: request.headers,
  });
  if (object === null) return null;

  if (!("body" in object) || !object.body) {
    const status =
      request.headers.has("If-Match") || request.headers.has("If-Unmodified-Since") ? 412 : 304;
    const headers = objectHeaders(key, object, env, false);
    return new Response(null, { status, headers });
  }

  const headers = objectHeaders(key, object, env, true);
  return new Response(object.body, { status: 200, headers });
}

function cachePolicyForKey(key) {
  if (key === "build-meta.json" || key === "updated-at.svg") {
    return CACHE_POLICIES.meta;
  }
  if (key.endsWith(".mmdb")) {
    return CACHE_POLICIES.mmdb;
  }
  return CACHE_POLICIES.ruleset;
}

function objectHeaders(key, object, env, includeContentLength) {
  const headers = new Headers();
  object.writeHttpMetadata(headers);

  const policy = cachePolicyForKey(key);
  // Client directive: short freshness + mandatory ETag validation for prompt updates.
  headers.set("Cache-Control", policy.clientCacheControl);
  // Edge directive (consumed & stripped by Cloudflare): long tiered-cache TTL + SWR/SIE.
  headers.set("Cloudflare-CDN-Cache-Control", policy.edgeCacheControl);
  headers.set("Cache-Tag", `r2,${policy.tagGroup},artifact:${key}`);

  headers.set("ETag", object.httpEtag);
  headers.set("Last-Modified", object.uploaded.toUTCString());
  headers.set("Accept-Ranges", "bytes");
  if (includeContentLength) {
    headers.set("Content-Length", String(object.size));
  }
  if (env.RELEASE_TAG) {
    headers.set("X-Release-Tag", env.RELEASE_TAG);
  }
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set(
    "Access-Control-Expose-Headers",
    "ETag, Last-Modified, Content-Length, Content-Range, Cf-Cache-Status, X-Release-Tag",
  );
  headers.set("X-Content-Type-Options", "nosniff");
  return headers;
}
