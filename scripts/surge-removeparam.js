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

  const config = getParsedConfig(argStr);
  const scopedSets = collectMatchedScopeSets(config.scopedMap, host);
  if (config.globalSet.size === 0 && scopedSets.length === 0) {
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
    const rawLower = rawKey.toLowerCase();
    let matched = matchesAnyParam(rawLower, config.globalSet, scopedSets);
    if (!matched && rawKey.includes("%")) {
      try {
        const decodedLower = decodeURIComponent(rawKey).toLowerCase();
        if (decodedLower !== rawLower) {
          matched = matchesAnyParam(decodedLower, config.globalSet, scopedSets);
        }
      } catch {
        // Malformed percent encoding keeps original parameter
      }
    }
    if (matched) {
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

  function addParamList(targetSet, rawList) {
    const params = rawList.split("|");
    for (let j = 0; j < params.length; j++) {
      const item = params[j];
      if (!item) continue;
      const trimmed = item.trim().toLowerCase();
      if (trimmed) {
        targetSet.add(trimmed);
      }
    }
  }

  function getParsedConfig(rawArg) {
    const cached = globalThis.__surgeRemoveParamCache;
    if (cached && cached.arg === rawArg) {
      return cached;
    }

    const globalSet = new Set();
    const scopedMap = new Map();
    const entries = rawArg.split(";");
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      if (!entry) continue;
      const eq = entry.indexOf("=");
      if (eq <= 0 || eq >= entry.length - 1) continue;
      const scope = entry.slice(0, eq).trim().toLowerCase();
      if (!scope) continue;
      const paramSpec = entry.slice(eq + 1);
      if (scope === "*") {
        addParamList(globalSet, paramSpec);
      } else {
        let scopeSet = scopedMap.get(scope);
        if (!scopeSet) {
          scopeSet = new Set();
          scopedMap.set(scope, scopeSet);
        }
        addParamList(scopeSet, paramSpec);
      }
    }

    const nextCache = { arg: rawArg, globalSet, scopedMap };
    globalThis.__surgeRemoveParamCache = nextCache;
    return nextCache;
  }

  function collectMatchedScopeSets(scopedMap, hostname) {
    if (scopedMap.size === 0) {
      return [];
    }
    const sets = [];
    let cursor = 0;
    while (cursor < hostname.length) {
      const suffix = cursor === 0 ? hostname : hostname.slice(cursor);
      const hit = scopedMap.get(suffix);
      if (hit) {
        sets.push(hit);
      }
      const dotIdx = hostname.indexOf(".", cursor);
      if (dotIdx < 0) {
        break;
      }
      cursor = dotIdx + 1;
    }
    return sets;
  }

  function matchesAnyParam(paramLower, globalSet, scopedSets) {
    if (globalSet.has(paramLower)) {
      return true;
    }
    for (let i = 0; i < scopedSets.length; i++) {
      if (scopedSets[i].has(paramLower)) {
        return true;
      }
    }
    return false;
  }
})();
