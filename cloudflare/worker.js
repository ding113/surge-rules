// Entry point of the `surge-rules` Worker (rule-set.ygxz.de).
//
// Static rule-set assets are served directly by the assets layer and never reach this
// script. It only handles:
//   - fetch: requests that match no asset, delegated back to the assets binding so
//     `_redirects`, `_headers` and 404 behaviour stay identical to an assets-only Worker.
//   - scheduled: the hourly Cron Trigger that dispatches the GitHub `release.yml`
//     workflow. GitHub's own `schedule` event is best-effort and silently drops runs
//     under load; Cloudflare Cron Triggers fire reliably.
//
// Required secret: GH_TOKEN — fine-grained PAT scoped to the repo with Actions: read & write.

export default {
  fetch(request, env) {
    return env.ASSETS.fetch(request);
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
