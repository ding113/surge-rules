// Entry point of the `surge-rules` Worker (rule-set.ygxz.de).
//
// Requests are assets-first: `_redirects` and the static files in the `release` branch
// (install.html, Surge scripts) are served by the assets layer and never reach this script.
// It only handles:
//   - fetch: every build artifact (rule sets, modules, MMDBs, updated-at.svg,
//     build-meta.json) is served from the `surge-rules` R2 bucket, which the release workflow
//     overwrites with the latest build on each run. R2 misses fall back to the assets binding
//     so 404 behaviour is unchanged.
//   - scheduled: the hourly Cron Trigger that dispatches the GitHub `release.yml` workflow.
//     GitHub's own `schedule` event is best-effort and silently drops runs under load;
//     Cloudflare Cron Triggers fire reliably.
//
// Required secret: GH_TOKEN — fine-grained PAT scoped to the repo with Actions: read & write.

// Release artifacts are flat, plain file names; anything else never touches R2.
const R2_KEY = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

export default {
  async fetch(request, env) {
    const fromR2 = await serveFromR2(request, env);
    return fromR2 ?? env.ASSETS.fetch(request);
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
  const key = new URL(request.url).pathname.slice(1);
  if (!R2_KEY.test(key)) return null;

  if (request.method === "HEAD") {
    const meta = await env.RELEASE_BUCKET.head(key);
    if (meta === null) return null;
    const headers = objectHeaders(meta);
    headers.set("Content-Length", String(meta.size));
    return new Response(null, { headers });
  }

  let object;
  try {
    object = await env.RELEASE_BUCKET.get(key, {
      onlyIf: request.headers,
      range: request.headers,
    });
  } catch (err) {
    if (!request.headers.has("Range")) throw err;
    // Unsatisfiable or malformed Range header.
    const meta = await env.RELEASE_BUCKET.head(key);
    if (meta === null) return null;
    return new Response(null, {
      status: 416,
      headers: { "Content-Range": `bytes */${meta.size}` },
    });
  }
  if (object === null) return null;

  const headers = objectHeaders(object);
  if (!("body" in object)) {
    // A conditional header failed: If-None-Match / If-Modified-Since → 304, otherwise 412.
    const status =
      request.headers.has("If-Match") || request.headers.has("If-Unmodified-Since") ? 412 : 304;
    return new Response(null, { status, headers });
  }
  if (request.headers.has("Range") && object.range) {
    const { offset, length } = resolveRange(object.range, object.size);
    // A range covering the whole object (or one R2 ignored) is just a normal 200.
    if (offset > 0 || length < object.size) {
      headers.set("Content-Range", `bytes ${offset}-${offset + length - 1}/${object.size}`);
      return new Response(object.body, { status: 206, headers });
    }
  }
  return new Response(object.body, { headers });
}

function objectHeaders(object) {
  const headers = new Headers();
  // Content-Type and Cache-Control are stored on the object by the release upload step.
  object.writeHttpMetadata(headers);
  headers.set("ETag", object.httpEtag);
  headers.set("Last-Modified", object.uploaded.toUTCString());
  headers.set("Accept-Ranges", "bytes");
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("X-Content-Type-Options", "nosniff");
  return headers;
}

function resolveRange(range, size) {
  // R2 always returns the `suffix` key (possibly undefined), so test its value, not its presence.
  if (typeof range.suffix === "number") {
    const length = Math.min(range.suffix, size);
    return { offset: size - length, length };
  }
  const offset = range.offset ?? 0;
  return { offset, length: range.length ?? size - offset };
}
