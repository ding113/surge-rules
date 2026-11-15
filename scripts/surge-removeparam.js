/**
 * Surge http-request query parameter cleaner for $removeparam rules.
 * Argument format: semicolon-separated `scope=param1|param2|...` rules,
 * where `scope` is `*` for global parameters or a domain/suffix host match.
 */
(() => {
  if (typeof $request === "undefined" || typeof $done !== "function") {
    return;
  }

  const rawUrl = $request.url;
  if (typeof rawUrl !== "string") {
    $done({});
    return;
  }

  const qIdx = rawUrl.indexOf("?");
  if (qIdx < 0) {
    $done({});
    return;
  }

  const argStr = typeof $argument === "string" ? $argument.trim() : "";
  if (argStr.length === 0) {
    $done({});
    return;
  }

  const host = extractHostname(rawUrl, qIdx);
  if (host.length === 0) {
    $done({});
    return;
  }

  const stripSet = collectMatchedParams(argStr, host);
  if (stripSet.size === 0) {
    $done({});
    return;
  }

  const hashIdx = rawUrl.indexOf("#", qIdx + 1);
  const queryEnd = hashIdx >= 0 ? hashIdx : rawUrl.length;
  const querySlice = rawUrl.slice(qIdx + 1, queryEnd);
  if (querySlice.length === 0) {
    $done({});
    return;
  }

  const kept = [];
  let changed = false;
  const pairs = querySlice.split("&");

  for (let i = 0; i < pairs.length; i++) {
    const part = pairs[i];
    if (part === undefined || part.length === 0) {
      if (part === "") {
        changed = true;
      }
      continue;
    }
    const eqIdx = part.indexOf("=");
    const rawKey = eqIdx >= 0 ? part.slice(0, eqIdx) : part;
    let decodedKey = rawKey;
    try {
      decodedKey = decodeURIComponent(rawKey);
    } catch {
      decodedKey = rawKey;
    }
    if (stripSet.has(rawKey.toLowerCase()) || stripSet.has(decodedKey.toLowerCase())) {
      changed = true;
    } else {
      kept.push(part);
    }
  }

  if (!changed) {
    $done({});
    return;
  }

  const prefix = rawUrl.slice(0, qIdx);
  const fragment = hashIdx >= 0 ? rawUrl.slice(hashIdx) : "";
  const nextQuery = kept.length > 0 ? `?${kept.join("&")}` : "";
  $done({ url: `${prefix}${nextQuery}${fragment}` });

  function extractHostname(url, queryIndex) {
    const schemeSep = url.indexOf("://");
    if (schemeSep < 0 || schemeSep + 3 >= queryIndex) {
      return "";
    }
    const authStart = schemeSep + 3;
    const slashIdx = url.indexOf("/", authStart);
    const authEnd = slashIdx >= 0 && slashIdx < queryIndex ? slashIdx : queryIndex;
    let authority = url.slice(authStart, authEnd);
    const atIdx = authority.lastIndexOf("@");
    if (atIdx >= 0) {
      authority = authority.slice(atIdx + 1);
    }
    if (authority.startsWith("[")) {
      const closeBracket = authority.indexOf("]");
      return closeBracket >= 0 ? authority.slice(1, closeBracket).toLowerCase() : "";
    }
    const colonIdx = authority.indexOf(":");
    const bare = colonIdx >= 0 ? authority.slice(0, colonIdx) : authority;
    return bare.replace(/\.+$/, "").toLowerCase();
  }

  function hostMatches(domain, scope) {
    if (scope === "*") {
      return true;
    }
    if (domain === scope) {
      return true;
    }
    return domain.endsWith(`.${scope}`);
  }

  function collectMatchedParams(arg, hostname) {
    const out = new Set();
    const entries = arg.split(";");
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      if (!entry) continue;
      const eq = entry.indexOf("=");
      if (eq <= 0 || eq >= entry.length - 1) continue;
      const scope = entry.slice(0, eq).trim().toLowerCase();
      if (!hostMatches(hostname, scope)) continue;
      const params = entry.slice(eq + 1).split("|");
      for (let j = 0; j < params.length; j++) {
        const p = params[j];
        if (p) {
          out.add(p.trim().toLowerCase());
        }
      }
    }
    return out;
  }
})();
