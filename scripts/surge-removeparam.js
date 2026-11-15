/**
 * Surge http-request query parameter cleaner for $removeparam rules.
 * Argument format: semicolon-separated `scope=token1|token2|...` rules:
 * - `scope` is `*` for global parameters, `<domain>` for domain/suffix match,
 *   or `-<domain>` for `@@||domain^$removeparam` host exemptions.
 * - Each token is an exact case-insensitive parameter name, `*` (strip/exempt all on host),
 *   or `~<flags>:<urlEncodedRegex>` for AdGuard/uBO regex $removeparam rules.
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
  const exemptSets = collectMatchedScopeItems(config.exemptMap, host);
  for (let i = 0; i < exemptSets.length; i++) {
    if (exemptSets[i].has("*")) {
      $done({});
      return;
    }
  }

  const scopedSets = collectMatchedScopeItems(config.scopedMap, host);
  const scopedRegexes = collectMatchedScopeArrays(config.scopedRegexMap, host);
  if (
    config.globalSet.size === 0 &&
    config.globalRegexes.length === 0 &&
    scopedSets.length === 0 &&
    scopedRegexes.length === 0
  ) {
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

    if (isExemptParam(rawLower, exemptSets)) {
      kept.push(part);
      continue;
    }

    let matched = matchesCandidate(
      rawKey,
      rawLower,
      part,
      config.globalSet,
      config.globalRegexes,
      scopedSets,
      scopedRegexes,
    );
    if (!matched && rawKey.includes("%")) {
      try {
        const decodedKey = decodeURIComponent(rawKey);
        const decodedLower = decodedKey.toLowerCase();
        if (decodedKey !== rawKey) {
          if (isExemptParam(decodedLower, exemptSets)) {
            kept.push(part);
            continue;
          }
          const decodedPart = eqIdx >= 0 ? `${decodedKey}${part.slice(eqIdx)}` : decodedKey;
          matched = matchesCandidate(
            decodedKey,
            decodedLower,
            decodedPart,
            config.globalSet,
            config.globalRegexes,
            scopedSets,
            scopedRegexes,
          );
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

  function normalizeScope(rawScope) {
    let s = rawScope.trim().toLowerCase();
    if (s.startsWith("*.")) {
      s = s.slice(2);
    }
    return s.replace(/\.+$/, "");
  }

  function parseRegexToken(token) {
    if (!token.startsWith("~")) {
      return null;
    }
    const colon = token.indexOf(":", 1);
    if (colon < 0) {
      return null;
    }
    const rawFlags = token.slice(1, colon);
    let cleanFlags = "";
    for (let i = 0; i < rawFlags.length; i++) {
      const ch = rawFlags[i];
      if ((ch === "i" || ch === "m" || ch === "s" || ch === "u") && !cleanFlags.includes(ch)) {
        cleanFlags += ch;
      }
    }
    try {
      const pattern = decodeURIComponent(token.slice(colon + 1));
      if (!pattern) {
        return null;
      }
      const re = new RegExp(pattern, cleanFlags);
      return { re, matchPair: pattern.includes("=") && pattern.startsWith("^") };
    } catch {
      return null;
    }
  }

  function addParamList(targetSet, targetRegexes, rawList, allowWildcard) {
    const params = rawList.split("|");
    for (let j = 0; j < params.length; j++) {
      const item = params[j];
      if (!item) continue;
      const trimmed = item.trim();
      if (!trimmed) continue;
      if (trimmed.startsWith("~") && targetRegexes) {
        const compiled = parseRegexToken(trimmed);
        if (compiled) {
          targetRegexes.push(compiled);
        }
        continue;
      }
      const lower = trimmed.toLowerCase();
      if (lower === "*" && !allowWildcard) {
        continue;
      }
      targetSet.add(lower);
    }
  }

  function getParsedConfig(rawArg) {
    const cached = globalThis.__surgeRemoveParamCache;
    if (cached && cached.arg === rawArg) {
      return cached;
    }

    const globalSet = new Set();
    const globalRegexes = [];
    const scopedMap = new Map();
    const scopedRegexMap = new Map();
    const exemptMap = new Map();

    const entries = rawArg.split(";");
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      if (!entry) continue;
      const eq = entry.indexOf("=");
      if (eq <= 0 || eq >= entry.length - 1) continue;
      const rawScope = entry.slice(0, eq).trim();
      if (!rawScope) continue;
      const paramSpec = entry.slice(eq + 1);

      if (rawScope.startsWith("-")) {
        const exScope = normalizeScope(rawScope.slice(1));
        if (!exScope) continue;
        let exSet = exemptMap.get(exScope);
        if (!exSet) {
          exSet = new Set();
          exemptMap.set(exScope, exSet);
        }
        addParamList(exSet, null, paramSpec, true);
        continue;
      }

      const scope = rawScope === "*" ? "*" : normalizeScope(rawScope);
      if (!scope) continue;
      if (scope === "*") {
        addParamList(globalSet, globalRegexes, paramSpec, false);
      } else {
        let scopeSet = scopedMap.get(scope);
        if (!scopeSet) {
          scopeSet = new Set();
          scopedMap.set(scope, scopeSet);
        }
        let scopeReList = scopedRegexMap.get(scope);
        if (!scopeReList) {
          scopeReList = [];
          scopedRegexMap.set(scope, scopeReList);
        }
        addParamList(scopeSet, scopeReList, paramSpec, true);
        if (scopeSet.size === 0) {
          scopedMap.delete(scope);
        }
        if (scopeReList.length === 0) {
          scopedRegexMap.delete(scope);
        }
      }
    }

    const nextCache = {
      arg: rawArg,
      globalSet,
      globalRegexes,
      scopedMap,
      scopedRegexMap,
      exemptMap,
    };
    globalThis.__surgeRemoveParamCache = nextCache;
    return nextCache;
  }

  function collectMatchedScopeItems(map, hostname) {
    if (map.size === 0) {
      return [];
    }
    const sets = [];
    let cursor = 0;
    while (cursor < hostname.length) {
      const suffix = cursor === 0 ? hostname : hostname.slice(cursor);
      const hit = map.get(suffix);
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

  function collectMatchedScopeArrays(map, hostname) {
    if (map.size === 0) {
      return [];
    }
    const out = [];
    let cursor = 0;
    while (cursor < hostname.length) {
      const suffix = cursor === 0 ? hostname : hostname.slice(cursor);
      const hit = map.get(suffix);
      if (hit) {
        for (let i = 0; i < hit.length; i++) {
          out.push(hit[i]);
        }
      }
      const dotIdx = hostname.indexOf(".", cursor);
      if (dotIdx < 0) {
        break;
      }
      cursor = dotIdx + 1;
    }
    return out;
  }

  function isExemptParam(paramLower, exemptSets) {
    for (let i = 0; i < exemptSets.length; i++) {
      if (exemptSets[i].has(paramLower)) {
        return true;
      }
    }
    return false;
  }

  function matchesRegexList(rawKey, rawPair, regexList) {
    for (let i = 0; i < regexList.length; i++) {
      const item = regexList[i];
      if (item.matchPair ? item.re.test(rawPair) : item.re.test(rawKey)) {
        return true;
      }
    }
    return false;
  }

  function matchesCandidate(
    rawKey,
    paramLower,
    rawPair,
    globalSet,
    globalRegexes,
    scopedSets,
    scopedRegexes,
  ) {
    if (globalSet.has(paramLower)) {
      return true;
    }
    for (let i = 0; i < scopedSets.length; i++) {
      if (scopedSets[i].has("*") || scopedSets[i].has(paramLower)) {
        return true;
      }
    }
    if (globalRegexes.length > 0 && matchesRegexList(rawKey, rawPair, globalRegexes)) {
      return true;
    }
    if (scopedRegexes.length > 0 && matchesRegexList(rawKey, rawPair, scopedRegexes)) {
      return true;
    }
    return false;
  }
})();
