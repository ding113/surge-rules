/**
 * Surge http-response transformer for AdGuard CoreLibs advanced modifiers:
 * - $replace   ({ op: "replace", pat, rep, flags? })
 * - $hls       ({ op: "hls", pat, flags? })
 * - $xmlprune  ({ op: "xmlprune", expr })
 * - $jsonprune ({ op: "jsonprune", expr })
 *
 * Argument format: either `u:<encodeURIComponent(JSON)>` or raw JSON array of ops.
 * Strictly fail-open: calls `$done({})` whenever nothing changes or input is non-matching/malformed.
 */
(() => {
  if (typeof $response === "undefined" || typeof $done !== "function") {
    return;
  }

  const origBody = $response.body;
  if (typeof origBody !== "string" || origBody.length === 0) {
    $done({});
    return;
  }

  const rawArg = typeof $argument === "string" ? $argument.trim() : "";
  if (rawArg.length === 0) {
    $done({});
    return;
  }

  const ops = getParsedOps(rawArg);
  if (ops.length === 0) {
    $done({});
    return;
  }

  let body = origBody;
  let jsonState = null; // { parsed: unknown, dirty: boolean } | "invalid"

  function flushJsonIfDirty() {
    if (jsonState && jsonState !== "invalid") {
      if (jsonState.dirty) {
        body = JSON.stringify(jsonState.parsed);
      }
      jsonState = null;
    }
  }

  for (let i = 0; i < ops.length; i++) {
    const item = ops[i];
    if (item.kind === "jsonprune") {
      if (jsonState === null) {
        const trimmed = body.trim();
        if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
          jsonState = "invalid";
          continue;
        }
        try {
          jsonState = { parsed: JSON.parse(body), dirty: false };
        } catch {
          jsonState = "invalid";
          continue;
        }
      }
      if (jsonState !== "invalid") {
        if (applyJsonPruneSteps(jsonState.parsed, item.steps, 0)) {
          jsonState.dirty = true;
        }
      }
      continue;
    }

    flushJsonIfDirty();

    if (item.kind === "replace") {
      const next = body.replace(item.re, item.rep);
      if (next !== body) {
        body = next;
      }
    } else if (item.kind === "hls") {
      if (body.includes("#EXTM3U")) {
        body = pruneHlsPlaylist(body, item.re);
      }
    } else if (item.kind === "xmlprune") {
      if (body.includes("<")) {
        body = pruneXmlDocument(body, item.branches);
      }
    }
  }

  flushJsonIfDirty();

  if (body === origBody) {
    $done({});
    return;
  }
  $done({ body });

  function sanitizeFlags(rawFlags, ensureGlobal) {
    let out = ensureGlobal ? "g" : "";
    if (typeof rawFlags === "string") {
      for (let i = 0; i < rawFlags.length; i++) {
        const ch = rawFlags[i];
        if (
          (ch === "g" || ch === "i" || ch === "m" || ch === "s" || ch === "u") &&
          !out.includes(ch)
        ) {
          out += ch;
        }
      }
    }
    return out;
  }

  function getParsedOps(argStr) {
    const cached = globalThis.__surgeAdguardCache;
    if (cached && cached.arg === argStr) {
      return cached.ops;
    }

    let rawList = null;
    try {
      const jsonText = argStr.startsWith("u:") ? decodeURIComponent(argStr.slice(2)) : argStr;
      const parsed = JSON.parse(jsonText);
      rawList = Array.isArray(parsed) ? parsed : [parsed];
    } catch {
      rawList = [];
    }

    const compiled = [];
    for (let i = 0; i < rawList.length; i++) {
      const entry = rawList[i];
      if (!entry || typeof entry !== "object") continue;
      if (
        entry.op === "replace" &&
        typeof entry.pat === "string" &&
        typeof entry.rep === "string"
      ) {
        try {
          const re = new RegExp(entry.pat, sanitizeFlags(entry.flags, true));
          compiled.push({ kind: "replace", re, rep: entry.rep });
        } catch {
          // Skip invalid upstream regex
        }
      } else if (entry.op === "hls" && typeof entry.pat === "string") {
        try {
          const re = new RegExp(entry.pat, sanitizeFlags(entry.flags, false));
          compiled.push({ kind: "hls", re });
        } catch {
          // Skip invalid upstream regex
        }
      } else if (entry.op === "xmlprune" && typeof entry.expr === "string") {
        const branches = parseXmlPruneExpr(entry.expr);
        if (branches.length > 0) {
          compiled.push({ kind: "xmlprune", branches });
        }
      } else if (entry.op === "jsonprune" && typeof entry.expr === "string") {
        const steps = parseJsonPrunePath(entry.expr);
        if (steps.length > 0) {
          compiled.push({ kind: "jsonprune", steps });
        }
      }
    }

    globalThis.__surgeAdguardCache = { arg: argStr, ops: compiled };
    return compiled;
  }

  // ============================================================================
  // 1. HLS (.m3u8) Segment Pruner
  // ============================================================================
  function isPlaylistHeaderTag(trimmed) {
    return (
      trimmed === "#EXTM3U" ||
      trimmed === "#EXT-X-INDEPENDENT-SEGMENTS" ||
      trimmed === "#EXT-X-ENDLIST" ||
      trimmed.startsWith("#EXT-X-VERSION:") ||
      trimmed.startsWith("#EXT-X-TARGETDURATION:") ||
      trimmed.startsWith("#EXT-X-MEDIA-SEQUENCE:") ||
      trimmed.startsWith("#EXT-X-DISCONTINUITY-SEQUENCE:") ||
      trimmed.startsWith("#EXT-X-PLAYLIST-TYPE:") ||
      trimmed.startsWith("#EXT-X-STREAM-INF:") ||
      trimmed.startsWith("#EXT-X-I-FRAME-STREAM-INF:") ||
      trimmed.startsWith("#EXT-X-MEDIA:") ||
      trimmed.startsWith("#EXT-X-SESSION-")
    );
  }

  function pruneHlsPlaylist(m3u8, re) {
    const crlf = m3u8.includes("\r\n");
    const lines = m3u8.split(/\r?\n/);
    const out = [];
    let segBuf = [];
    let mutated = false;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      if (trimmed.length === 0) {
        if (segBuf.length > 0) {
          for (let j = 0; j < segBuf.length; j++) out.push(segBuf[j]);
          segBuf = [];
        }
        out.push(line);
        continue;
      }

      if (trimmed.startsWith("#")) {
        if (isPlaylistHeaderTag(trimmed)) {
          if (segBuf.length > 0) {
            for (let j = 0; j < segBuf.length; j++) out.push(segBuf[j]);
            segBuf = [];
          }
          out.push(line);
        } else if (trimmed.startsWith("#EXT-X-DATERANGE:") && re.test(trimmed)) {
          mutated = true;
        } else {
          segBuf.push(line);
        }
        continue;
      }

      // Segment URI line: test accumulated segment tags + URI line as a block
      segBuf.push(line);
      const blockText = segBuf.join("\n");
      if (re.test(blockText)) {
        mutated = true;
      } else {
        for (let j = 0; j < segBuf.length; j++) {
          out.push(segBuf[j]);
        }
      }
      segBuf = [];
    }

    if (segBuf.length > 0) {
      const tailText = segBuf.join("\n");
      if (re.test(tailText)) {
        mutated = true;
      } else {
        for (let j = 0; j < segBuf.length; j++) out.push(segBuf[j]);
      }
    }

    if (!mutated) {
      return m3u8;
    }
    return out.join(crlf ? "\r\n" : "\n");
  }

  // ============================================================================
  // 2. XML / VAST / MPEG-DASH Pruner ($xmlprune)
  // ============================================================================
  function splitTopLevelPipe(expr) {
    const parts = [];
    let start = 0;
    let bracket = 0;
    let paren = 0;
    let quote = "";
    for (let i = 0; i < expr.length; i++) {
      const ch = expr[i];
      if (quote) {
        if (ch === quote) quote = "";
        continue;
      }
      if (ch === '"' || ch === "'") {
        quote = ch;
      } else if (ch === "[") {
        bracket++;
      } else if (ch === "]") {
        bracket = Math.max(0, bracket - 1);
      } else if (ch === "(") {
        paren++;
      } else if (ch === ")") {
        paren = Math.max(0, paren - 1);
      } else if (ch === "|" && bracket === 0 && paren === 0) {
        const piece = expr.slice(start, i).trim();
        if (piece) parts.push(piece);
        start = i + 1;
      }
    }
    const tail = expr.slice(start).trim();
    if (tail) parts.push(tail);
    return parts;
  }

  function parseXmlPruneExpr(expr) {
    const rawParts = splitTopLevelPipe(expr);
    const branches = [];

    for (let i = 0; i < rawParts.length; i++) {
      const part = rawParts[i];

      // Attribute removal form: `//*[name()="Period"]/@start[boolean(//*[@value="Ad"])]` or `//Period/@start`
      const attrMatch = part.match(
        /(?:name\(\)\s*=\s*["']([A-Za-z0-9_:-]+)["']\s*\]|\/([A-Za-z0-9_:-]+))\/@([A-Za-z0-9_:-]+)(?:\[(.*)\])?$/,
      );
      if (attrMatch) {
        const tag = attrMatch[1] || attrMatch[2];
        const attrName = attrMatch[3];
        const condRaw = attrMatch[4] || "";
        let docAttrCheck = null;
        const boolAttr = condRaw.match(/@([A-Za-z0-9_:-]+)\s*=\s*["']([^"']*)["']/);
        if (boolAttr) {
          docAttrCheck = { attr: boolAttr[1], val: boolAttr[2] };
        }
        branches.push({
          type: "remove-attr",
          tag,
          attrName,
          docAttrCheck,
        });
        continue;
      }

      // Element removal form: `/MPD/Period[contains(@id,'ad-')]`, `//*[name()="Period"][.//*[@value="Ad"]]`, `//Ad`
      let tag = null;
      const nameFnMatch = part.match(/(?:local-name|name)\(\)\s*=\s*["']([A-Za-z0-9_:-]+)["']/);
      if (nameFnMatch) {
        tag = nameFnMatch[1];
      } else {
        const stripped = part.replace(/\[[^\]]*\]/g, "");
        const segs = stripped.split("/").filter(Boolean);
        const last = segs[segs.length - 1];
        if (last && last !== "*" && /^[A-Za-z0-9_:-]+$/.test(last)) {
          tag = last;
        }
      }
      if (!tag) continue;

      let pred = null;
      const containsMatch = part.match(
        /contains\(\s*@([A-Za-z0-9_:-]+)\s*,\s*["']([^"']+)["']\s*\)/,
      );
      const descendantEqMatch = part.match(
        /\.\s*\/\/\*\[\s*@([A-Za-z0-9_:-]+)\s*=\s*["']([^"']*)["']\s*\]/,
      );
      const selfEqMatch = !descendantEqMatch
        ? part.match(/\[\s*@([A-Za-z0-9_:-]+)\s*=\s*["']([^"']*)["']\s*\]/)
        : null;

      if (containsMatch) {
        pred = { kind: "attr-contains", attr: containsMatch[1], sub: containsMatch[2] };
      } else if (descendantEqMatch) {
        pred = {
          kind: "descendant-attr-eq",
          attr: descendantEqMatch[1],
          val: descendantEqMatch[2],
        };
      } else if (selfEqMatch) {
        pred = { kind: "attr-eq", attr: selfEqMatch[1], val: selfEqMatch[2] };
      }

      branches.push({ type: "remove-elem", tag, pred });
    }

    return branches;
  }

  function xmlHasAttrEq(xmlFragment, attr, val) {
    const escapedAttr = attr.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const escapedVal = val.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(`\\b${escapedAttr}\\s*=\\s*["']${escapedVal}["']`);
    return re.test(xmlFragment);
  }

  function xmlTagAttrValue(openTag, attr) {
    const escapedAttr = attr.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(`\\b${escapedAttr}\\s*=\\s*(?:"([^"]*)"|'([^']*)')`);
    const m = openTag.match(re);
    if (!m) return null;
    return m[1] !== undefined ? m[1] : m[2];
  }

  function removeMatchingXmlElements(xml, tag, pred) {
    const escapedTag = tag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const tokenRe = new RegExp(
      `<(?:[A-Za-z0-9_]+:)?${escapedTag}\\b[^>]*>|<(?:\\/)?(?:[A-Za-z0-9_]+:)?${escapedTag}\\s*>`,
      "g",
    );
    const tokens = [];
    let m = tokenRe.exec(xml);
    while (m !== null) {
      const text = m[0];
      const isClose = text.startsWith("</");
      const isSelfClose = !isClose && text.endsWith("/>");
      tokens.push({
        start: m.index,
        end: m.index + text.length,
        text,
        isClose,
        isSelfClose,
      });
      m = tokenRe.exec(xml);
    }
    if (tokens.length === 0) return xml;

    const stack = [];
    const candidateSpans = [];
    for (let i = 0; i < tokens.length; i++) {
      const tok = tokens[i];
      if (tok.isSelfClose) {
        candidateSpans.push({ start: tok.start, end: tok.end, openTag: tok.text });
      } else if (!tok.isClose) {
        stack.push(tok);
      } else if (stack.length > 0) {
        const openTok = stack.pop();
        if (stack.length === 0) {
          candidateSpans.push({
            start: openTok.start,
            end: tok.end,
            openTag: openTok.text,
          });
        }
      }
    }

    const toDelete = [];
    for (let i = 0; i < candidateSpans.length; i++) {
      const span = candidateSpans[i];
      const fullElem = xml.slice(span.start, span.end);
      let hit = false;
      if (!pred) {
        hit = true;
      } else if (pred.kind === "attr-contains") {
        const val = xmlTagAttrValue(span.openTag, pred.attr);
        hit = typeof val === "string" && val.includes(pred.sub);
      } else if (pred.kind === "attr-eq") {
        const val = xmlTagAttrValue(span.openTag, pred.attr);
        hit = val === pred.val;
      } else if (pred.kind === "descendant-attr-eq") {
        hit = xmlHasAttrEq(fullElem, pred.attr, pred.val);
      }
      if (hit) {
        toDelete.push(span);
      }
    }

    if (toDelete.length === 0) return xml;
    toDelete.sort((a, b) => a.start - b.start);
    let out = "";
    let cursor = 0;
    for (let i = 0; i < toDelete.length; i++) {
      const sp = toDelete[i];
      if (sp.start < cursor) continue;
      out += xml.slice(cursor, sp.start);
      cursor = sp.end;
    }
    out += xml.slice(cursor);
    return out;
  }

  function removeXmlAttributeFromTag(xml, tag, attrName) {
    const escapedTag = tag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const escapedAttr = attrName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const openTagRe = new RegExp(`<(?:[A-Za-z0-9_]+:)?${escapedTag}\\b[^>]*>`, "g");
    const attrRe = new RegExp(`\\s+\\b${escapedAttr}\\s*=\\s*(?:"[^"]*"|'[^']*')`, "g");
    return xml.replace(openTagRe, (openTag) => openTag.replace(attrRe, ""));
  }

  function pruneXmlDocument(origXml, branches) {
    // Evaluate document-level conditions against the original XML snapshot (XPath union semantics)
    const activeBranches = [];
    for (let i = 0; i < branches.length; i++) {
      const b = branches[i];
      if (b.type === "remove-attr" && b.docAttrCheck) {
        if (!xmlHasAttrEq(origXml, b.docAttrCheck.attr, b.docAttrCheck.val)) {
          continue;
        }
      }
      activeBranches.push(b);
    }

    let xml = origXml;
    for (let i = 0; i < activeBranches.length; i++) {
      const b = activeBranches[i];
      if (b.type === "remove-elem") {
        xml = removeMatchingXmlElements(xml, b.tag, b.pred);
      }
    }
    for (let i = 0; i < activeBranches.length; i++) {
      const b = activeBranches[i];
      if (b.type === "remove-attr") {
        xml = removeXmlAttributeFromTag(xml, b.tag, b.attrName);
      }
    }
    return xml;
  }

  // ============================================================================
  // 3. AdGuard Extended JSONPrune Evaluator ($jsonprune)
  // ============================================================================
  function parseJsonPrunePath(rawExpr) {
    let s = rawExpr.trim();
    if (s.startsWith("$")) {
      s = s.slice(1);
    }
    const steps = [];
    let i = 0;

    while (i < s.length) {
      let recursive = false;
      if (s[i] === "." && s[i + 1] === ".") {
        recursive = true;
        i += 2;
      } else if (s[i] === ".") {
        i += 1;
      }

      if (i >= s.length) break;

      if (s[i] === "*") {
        steps.push({ type: "wildcard", recursive });
        i += 1;
        continue;
      }

      if (s[i] === "[") {
        const closeIdx = findMatchingBracket(s, i);
        if (closeIdx < 0) return [];
        const inner = s.slice(i + 1, closeIdx).trim();
        i = closeIdx + 1;

        if (inner === "*") {
          steps.push({ type: "wildcard", recursive });
        } else if (inner.startsWith("?")) {
          const pred = parseFilterPredicate(inner.slice(1).trim());
          if (!pred) return [];
          steps.push({ type: "filter", recursive, pred });
        } else if (
          (inner.startsWith('"') && inner.endsWith('"') && !inner.slice(1, -1).includes('"')) ||
          (inner.startsWith("'") && inner.endsWith("'") && !inner.slice(1, -1).includes("'"))
        ) {
          steps.push({ type: "keys", recursive, keys: [inner.slice(1, -1)] });
        } else if (/^\d+$/.test(inner)) {
          steps.push({ type: "index", recursive, index: Number(inner) });
        } else {
          const keys = splitBracketKeys(inner);
          if (keys.length === 0) return [];
          steps.push({ type: "keys", recursive, keys });
        }
        continue;
      }

      let end = i;
      while (end < s.length && s[end] !== "." && s[end] !== "[") {
        end++;
      }
      const key = s.slice(i, end).trim();
      if (!key) return [];
      steps.push({ type: "keys", recursive, keys: [key] });
      i = end;
    }

    return steps;
  }

  function findMatchingBracket(str, openPos) {
    let depth = 0;
    let quote = "";
    for (let i = openPos; i < str.length; i++) {
      const ch = str[i];
      if (quote) {
        if (ch === "\\" && i + 1 < str.length) {
          i++;
          continue;
        }
        if (ch === quote) quote = "";
        continue;
      }
      if (ch === '"' || ch === "'") {
        quote = ch;
      } else if (ch === "[") {
        depth++;
      } else if (ch === "]") {
        depth--;
        if (depth === 0) return i;
      }
    }
    return -1;
  }

  function splitBracketKeys(inner) {
    const out = [];
    const parts = inner.split(",");
    for (let i = 0; i < parts.length; i++) {
      let tok = parts[i].trim();
      if (
        (tok.startsWith('"') && tok.endsWith('"')) ||
        (tok.startsWith("'") && tok.endsWith("'"))
      ) {
        tok = tok.slice(1, -1);
      }
      if (tok) out.push(tok);
    }
    return out;
  }

  function tokenizeSExpr(body) {
    let s = body.trim();
    if (s.startsWith("(") && s.endsWith(")")) {
      s = s.slice(1, -1).trim();
    }
    const tokens = [];
    let i = 0;
    while (i < s.length) {
      while (i < s.length && /\s/.test(s[i])) i++;
      if (i >= s.length) break;
      const q = s[i];
      if (q === '"' || q === "'") {
        let val = "";
        i++;
        while (i < s.length && s[i] !== q) {
          if (s[i] === "\\" && i + 1 < s.length) {
            i++;
          }
          val += s[i];
          i++;
        }
        i++; // skip closing quote
        tokens.push({ quoted: true, value: val });
      } else {
        const start = i;
        while (i < s.length && !/\s/.test(s[i])) i++;
        tokens.push({ quoted: false, value: s.slice(start, i) });
      }
    }
    return tokens;
  }

  function parseLiteralToken(tok) {
    if (tok.quoted) return tok.value;
    if (tok.value === "true") return true;
    if (tok.value === "false") return false;
    if (tok.value === "null") return null;
    if (/^-?\d+(?:\.\d+)?$/.test(tok.value)) return Number(tok.value);
    return tok.value;
  }

  function parseFilterPredicate(rawPred) {
    const tokens = tokenizeSExpr(rawPred);
    if (tokens.length < 2) return null;
    const op = tokens[0].value;
    const subSteps = parseJsonPrunePath(tokens[1].value);
    if (subSteps.length === 0) return null;

    if (op === "has") {
      return { op: "has", subSteps };
    }
    if (op === "key-substr" && tokens.length >= 3) {
      return { op: "key-substr", subSteps, needle: String(tokens[2].value) };
    }
    if (op === "key-eq" && tokens.length >= 3) {
      return { op: "key-eq", subSteps, expected: parseLiteralToken(tokens[2]) };
    }
    return null;
  }

  function collectSubPathValues(node, steps, stepIdx, out, depth) {
    if (depth > 48 || node === null || typeof node !== "object") {
      return;
    }
    if (stepIdx >= steps.length) {
      out.push(node);
      return;
    }

    const step = steps[stepIdx];
    const isLast = stepIdx === steps.length - 1;

    if (step.type === "keys") {
      if (!Array.isArray(node)) {
        for (let i = 0; i < step.keys.length; i++) {
          const k = step.keys[i];
          if (Object.hasOwn(node, k)) {
            const child = node[k];
            if (isLast) {
              if (child !== undefined) out.push(child);
            } else {
              collectSubPathValues(child, steps, stepIdx + 1, out, depth + 1);
            }
          }
        }
      } else {
        for (let i = 0; i < node.length; i++) {
          collectSubPathValues(node[i], steps, stepIdx, out, depth + 1);
        }
      }
    } else if (step.type === "wildcard") {
      const vals = Array.isArray(node) ? node : Object.values(node);
      for (let i = 0; i < vals.length; i++) {
        if (isLast) {
          if (vals[i] !== undefined) out.push(vals[i]);
        } else {
          collectSubPathValues(vals[i], steps, stepIdx + 1, out, depth + 1);
        }
      }
    }

    if (step.recursive) {
      const vals = Array.isArray(node) ? node : Object.values(node);
      for (let i = 0; i < vals.length; i++) {
        collectSubPathValues(vals[i], steps, stepIdx, out, depth + 1);
      }
    }
  }

  function evaluatePredicate(candidate, pred) {
    if (candidate === null || typeof candidate !== "object") {
      return false;
    }
    const found = [];
    collectSubPathValues(candidate, pred.subSteps, 0, found, 0);
    if (pred.op === "has") {
      return found.length > 0;
    }
    if (pred.op === "key-substr") {
      for (let i = 0; i < found.length; i++) {
        if (typeof found[i] === "string" && found[i].includes(pred.needle)) {
          return true;
        }
      }
      return false;
    }
    if (pred.op === "key-eq") {
      for (let i = 0; i < found.length; i++) {
        if (found[i] === pred.expected) {
          return true;
        }
      }
      return false;
    }
    return false;
  }

  function applyStepDirectly(node, step, steps, stepIdx, depth) {
    if (depth > 48 || node === null || typeof node !== "object") {
      return false;
    }
    let mutated = false;
    const isLast = stepIdx === steps.length - 1;

    if (step.type === "keys") {
      if (!Array.isArray(node)) {
        for (let i = 0; i < step.keys.length; i++) {
          const k = step.keys[i];
          if (Object.hasOwn(node, k)) {
            if (isLast) {
              delete node[k];
              mutated = true;
            } else if (applyJsonPruneSteps(node[k], steps, stepIdx + 1, depth + 1)) {
              mutated = true;
            }
          }
        }
      } else if (!step.recursive) {
        for (let i = 0; i < node.length; i++) {
          if (applyStepDirectly(node[i], step, steps, stepIdx, depth + 1)) {
            mutated = true;
          }
        }
      }
    } else if (step.type === "index") {
      if (Array.isArray(node) && step.index >= 0 && step.index < node.length) {
        if (isLast) {
          node.splice(step.index, 1);
          mutated = true;
        } else if (applyJsonPruneSteps(node[step.index], steps, stepIdx + 1, depth + 1)) {
          mutated = true;
        }
      }
    } else if (step.type === "wildcard") {
      if (Array.isArray(node)) {
        if (isLast) {
          if (node.length > 0) {
            node.length = 0;
            mutated = true;
          }
        } else {
          for (let i = 0; i < node.length; i++) {
            if (applyJsonPruneSteps(node[i], steps, stepIdx + 1, depth + 1)) {
              mutated = true;
            }
          }
        }
      } else {
        const keys = Object.keys(node);
        for (let i = 0; i < keys.length; i++) {
          const k = keys[i];
          if (isLast) {
            delete node[k];
            mutated = true;
          } else if (applyJsonPruneSteps(node[k], steps, stepIdx + 1, depth + 1)) {
            mutated = true;
          }
        }
      }
    } else if (step.type === "filter") {
      if (Array.isArray(node)) {
        if (isLast) {
          for (let i = node.length - 1; i >= 0; i--) {
            if (evaluatePredicate(node[i], step.pred)) {
              node.splice(i, 1);
              mutated = true;
            }
          }
        } else {
          for (let i = 0; i < node.length; i++) {
            if (
              evaluatePredicate(node[i], step.pred) &&
              applyJsonPruneSteps(node[i], steps, stepIdx + 1, depth + 1)
            ) {
              mutated = true;
            }
          }
        }
      } else {
        const keys = Object.keys(node);
        for (let i = 0; i < keys.length; i++) {
          const k = keys[i];
          if (evaluatePredicate(node[k], step.pred)) {
            if (isLast) {
              delete node[k];
              mutated = true;
            } else if (applyJsonPruneSteps(node[k], steps, stepIdx + 1, depth + 1)) {
              mutated = true;
            }
          }
        }
      }
    }

    return mutated;
  }

  function applyJsonPruneSteps(node, steps, stepIdx, depth = 0) {
    if (depth > 48 || stepIdx >= steps.length || node === null || typeof node !== "object") {
      return false;
    }
    const step = steps[stepIdx];
    let mutated = applyStepDirectly(node, step, steps, stepIdx, depth);

    if (step.recursive) {
      if (Array.isArray(node)) {
        for (let i = 0; i < node.length; i++) {
          if (applyJsonPruneSteps(node[i], steps, stepIdx, depth + 1)) {
            mutated = true;
          }
        }
      } else {
        const keys = Object.keys(node);
        for (let i = 0; i < keys.length; i++) {
          if (applyJsonPruneSteps(node[keys[i]], steps, stepIdx, depth + 1)) {
            mutated = true;
          }
        }
      }
    }

    return mutated;
  }
})();
