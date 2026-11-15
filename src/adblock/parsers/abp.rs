use regex::Regex;
use rustc_hash::FxHashSet;

use crate::adblock::config::{AdblockSourceConfig, AdblockSourceRole};
use crate::adblock::jq_transpile::transpile_jsonprune_to_jq;
use crate::adblock::model::{
    BodyRewriteKind, BodyRewriteRule, HeaderAction, HeaderDirection, HeaderRewriteRule,
    MapLocalDataType, MapLocalRule, ParsedAdblockSource, RemoveParamRule, UrlRewriteMode,
    UrlRewriteRule,
};
use crate::adblock::regex_util::{
    abp_url_pattern_to_surge_regex, is_valid_domain, is_valid_domain_wildcard,
};

const SAFE_GLOBAL_TRACKING_PARAMS: &[&str] = &[
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "fbclid",
    "gclid",
    "dclid",
    "gbraid",
    "wbraid",
    "msclkid",
    "ttclid",
    "twclid",
    "igshid",
    "mc_eid",
    "yclid",
    "_hsenc",
    "_hsmi",
    "mkt_tok",
    "srsltid",
    "tgclid",
    "spm_id_from",
    "vd_source",
    "share_source",
    "share_medium",
    "share_plat",
    "share_session_id",
    "share_tag",
];

/// Parses ABP / AdGuard / uBlock Origin static filter lists.
/// Performs a two-pass scan to honor `$badfilter` cancellations before converting rules.
pub fn parse_abp(text: &str, src: &AdblockSourceConfig, out: &mut ParsedAdblockSource) {
    let mut badfiltered: FxHashSet<(&str, Vec<&str>)> = FxHashSet::default();
    let mut candidate_lines: Vec<&str> = Vec::new();

    for raw_line in text.lines() {
        let line = raw_line.trim_start_matches('\u{feff}').trim();
        if line.is_empty()
            || line.starts_with('!')
            || line.starts_with('[')
            || (line.starts_with('#') && !is_cosmetic_marker_prefix(line))
        {
            continue;
        }
        // Strictly drop all cosmetic, CSS, scriptlet, and HTML filter lines
        if contains_cosmetic_or_scriptlet_syntax(line) {
            continue;
        }
        if let Some((pat, mods)) = split_pattern_and_modifiers(line) {
            let mut mod_list: Vec<&str> = mods
                .split(',')
                .map(str::trim)
                .filter(|m| !m.is_empty())
                .collect();
            if mod_list.contains(&"badfilter") {
                mod_list.retain(|m| *m != "badfilter");
                mod_list.sort_unstable();
                badfiltered.insert((pat, mod_list));
                continue;
            }
        }
        candidate_lines.push(line);
    }

    for line in candidate_lines {
        if let Some(exc) = line.strip_prefix("@@") {
            if src.role == AdblockSourceRole::Allowlist || is_whole_domain_exception(exc) {
                parse_exception_line(exc, out);
            }
            continue;
        }

        let (pat, mods_opt) = match split_pattern_and_modifiers(line) {
            Some((p, m)) => (p, Some(m)),
            None => (line, None),
        };
        let mut sorted_mods: Vec<&str> = mods_opt
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .collect();
        sorted_mods.sort_unstable();
        if badfiltered.contains(&(pat, sorted_mods)) {
            continue;
        }

        let mods = mods_opt.unwrap_or("");
        if parse_complex_network_modifiers(pat, mods, src, out) {
            continue;
        }
        if src.extract_fallback_domain_rules && src.role != AdblockSourceRole::Allowlist {
            parse_fallback_domain_rule(pat, mods, out);
        }
    }
}

fn is_cosmetic_marker_prefix(line: &str) -> bool {
    line.starts_with("##") || line.starts_with("#@#") || line.starts_with("#?#")
}

/// Detects ABP/uBO/AdGuard cosmetic, extended CSS, scriptlet, and HTML filtering syntax.
pub fn contains_cosmetic_or_scriptlet_syntax(line: &str) -> bool {
    for marker in [
        "##", "#@#", "#?#", "#@?#", "#$#", "#@$#", "#+js(", "##+js(", "$$", "$@$",
    ] {
        if line.contains(marker) {
            return true;
        }
    }
    false
}

fn split_pattern_and_modifiers(line: &str) -> Option<(&str, &str)> {
    // Only treat `$` as modifier delimiter when outside `/.../` regex literal
    if line.starts_with('/') {
        let bytes = line.as_bytes();
        let mut escaped = false;
        for i in 1..bytes.len() {
            if escaped {
                escaped = false;
                continue;
            }
            if bytes[i] == b'\\' {
                escaped = true;
                continue;
            }
            if bytes[i] == b'/' {
                let tail = &line[i + 1..];
                if let Some(mods) = tail.strip_prefix('$') {
                    return Some((&line[..i + 1], mods));
                }
                return None;
            }
        }
        return None;
    }

    let bytes = line.as_bytes();
    let mut last_unescaped = None;
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'$' {
            continue;
        }
        // Count preceding backslashes so escaped `\$` inside JSONPath or regex is never split
        let mut bs = 0usize;
        let mut k = i;
        while k > 0 && bytes[k - 1] == b'\\' {
            bs += 1;
            k -= 1;
        }
        if bs % 2 == 1 {
            continue;
        }
        let suffix = &line[i + 1..];
        if starts_with_known_abp_modifier(suffix) {
            return Some((&line[..i], suffix));
        }
        last_unescaped = Some(i);
    }

    let idx = last_unescaped?;
    Some((&line[..idx], &line[idx + 1..]))
}

fn starts_with_known_abp_modifier(suffix: &str) -> bool {
    let s = suffix.trim_start().trim_start_matches('~');
    const PREFIXES: &[&str] = &[
        "removeparam",
        "jsonprune",
        "replace=",
        "redirect",
        "rewrite=",
        "removeheader=",
        "domain=",
        "from=",
        "badfilter",
        "important",
        "all",
        "document",
        "doc",
        "elemhide",
        "generichide",
        "specifichide",
        "script",
        "image",
        "stylesheet",
        "xmlhttprequest",
        "xhr",
        "third-party",
        "first-party",
        "3p",
        "1p",
        "popup",
        "popunder",
        "app=",
        "csp=",
        "permissions=",
        "match-case",
        "empty",
        "mp4",
        "media",
        "font",
        "subdocument",
        "object",
        "ping",
        "other",
    ];
    PREFIXES.iter().any(|p| s.starts_with(p))
}

fn split_abp_modifiers(mods: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = mods.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut in_regex = false;
    let mut escaped = false;

    while i < bytes.len() {
        let b = bytes[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        if b == b'\\' {
            escaped = true;
            i += 1;
            continue;
        }
        if b == b'/' {
            if in_regex {
                in_regex = false;
            } else if i > start && bytes[i - 1] == b'=' {
                in_regex = true;
            }
            i += 1;
            continue;
        }
        if b == b',' && !in_regex {
            let tok = mods[start..i].trim();
            if !tok.is_empty() {
                out.push(tok);
            }
            start = i + 1;
        }
        i += 1;
    }
    let tail = mods[start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

fn is_whole_domain_exception(exc: &str) -> bool {
    let (pat, mods_opt) = match split_pattern_and_modifiers(exc) {
        Some((p, m)) => (p, Some(m)),
        None => (exc, None),
    };
    if !pat.starts_with("||") || pat[2..].contains('/') || pat[2..].contains('*') {
        return false;
    }
    match mods_opt {
        None => true,
        Some(mods) => {
            let mut valid = true;
            for m in mods.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                if !matches!(m, "important" | "all" | "document" | "doc") {
                    valid = false;
                    break;
                }
            }
            valid
        }
    }
}

fn parse_exception_line(exc: &str, out: &mut ParsedAdblockSource) {
    let (pat, mods_opt) = match split_pattern_and_modifiers(exc) {
        Some((p, m)) => (p, Some(m)),
        None => (exc, None),
    };
    if let Some(mods) = mods_opt {
        for m in mods.split(',').map(str::trim) {
            if m.starts_with("domain=")
                || m.starts_with("from=")
                || matches!(m, "elemhide" | "generichide" | "specifichide" | "jsinject")
            {
                return;
            }
        }
    }
    if let Some(dom) = extract_exact_abp_domain(pat) {
        if mods_opt.is_some_and(|m| m.split(',').any(|t| matches!(t.trim(), "document" | "doc"))) {
            out.allow_suffix_domains.insert(dom);
        } else {
            out.allow_exact_domains.insert(dom.clone());
            out.allow_suffix_domains.insert(dom);
        }
    }
}

fn parse_complex_network_modifiers(
    pat: &str,
    mods: &str,
    src: &AdblockSourceConfig,
    out: &mut ParsedAdblockSource,
) -> bool {
    if !src.extract_complex_network_rules {
        return false;
    }

    let mod_tokens = split_abp_modifiers(mods);

    // Skip client-app/CSP/popup rules that have no direct Surge equivalent
    for m in &mod_tokens {
        if m.starts_with("app=")
            || m.starts_with("csp=")
            || m.starts_with("permissions=")
            || *m == "popup"
            || *m == "popunder"
        {
            return true;
        }
    }

    let domain_scopes = extract_positive_domain_option(&mod_tokens);
    let has_domain_scope = mod_tokens
        .iter()
        .any(|m| m.starts_with("domain=") || m.starts_with("from="));
    let mut handled = false;

    for m in &mod_tokens {
        if let Some(param_spec) = m.strip_prefix("removeparam=") {
            handled = true;
            if let Some(param_name) = parse_literal_removeparam_name(param_spec) {
                emit_removeparam_rules(pat, domain_scopes.as_deref(), param_name, src.weight, out);
            }
        } else if let Some(jp) = m.strip_prefix("jsonprune=") {
            handled = true;
            if !has_domain_scope
                && let Some(jq_expr) = transpile_jsonprune_to_jq(jp)
                && let Some((regex, host_opt)) = abp_url_pattern_to_surge_regex(pat)
            {
                if let Some(ref host) = host_opt {
                    out.complex_protected_hosts.insert(host.clone());
                    out.mitm_hosts.insert(host.clone());
                }
                out.body_rewrites.push(BodyRewriteRule {
                    kind: BodyRewriteKind::HttpResponseJq,
                    pattern: regex,
                    expression: jq_expr,
                    replacement: None,
                    weight: src.weight,
                });
            }
        } else if let Some(rep_spec) = m.strip_prefix("replace=") {
            handled = true;
            if !has_domain_scope
                && let Some((body_regex, repl)) = parse_replace_spec(rep_spec)
                && let Some((url_regex, host_opt)) = abp_url_pattern_to_surge_regex(pat)
            {
                if let Some(ref host) = host_opt {
                    out.complex_protected_hosts.insert(host.clone());
                    out.mitm_hosts.insert(host.clone());
                }
                out.body_rewrites.push(BodyRewriteRule {
                    kind: BodyRewriteKind::HttpResponse,
                    pattern: url_regex,
                    expression: body_regex,
                    replacement: Some(repl),
                    weight: src.weight,
                });
            }
        } else if let Some(redir) = m
            .strip_prefix("redirect=")
            .or_else(|| m.strip_prefix("redirect-rule="))
            .or_else(|| m.strip_prefix("rewrite=abp-resource:"))
        {
            handled = true;
            if !has_domain_scope
                && src.role == AdblockSourceRole::ComplexFirst
                && let Some((data_type, data, header)) = map_redirect_resource(redir)
                && let Some((regex, host_opt)) = abp_url_pattern_to_surge_regex(pat)
            {
                if let Some(ref host) = host_opt {
                    out.complex_protected_hosts.insert(host.clone());
                    out.mitm_hosts.insert(host.clone());
                }
                out.map_locals.push(MapLocalRule {
                    pattern: regex,
                    data_type,
                    data,
                    status_code: Some(200),
                    header,
                    weight: src.weight,
                });
            }
        } else if let Some(hdr) = m.strip_prefix("removeheader=") {
            handled = true;
            if !has_domain_scope
                && let Some((dir, field)) = parse_removeheader_spec(hdr)
                && !field.eq_ignore_ascii_case("content-length")
                && !field.eq_ignore_ascii_case("transfer-encoding")
                && let Some((regex, host_opt)) = abp_url_pattern_to_surge_regex(pat)
            {
                if let Some(ref host) = host_opt {
                    out.complex_protected_hosts.insert(host.clone());
                    out.mitm_hosts.insert(host.clone());
                }
                out.header_rewrites.push(HeaderRewriteRule {
                    direction: dir,
                    pattern: regex,
                    action: HeaderAction::HeaderDel,
                    field,
                    value: None,
                    replace_regex: None,
                    weight: src.weight,
                });
            }
        }
    }

    if handled {
        return true;
    }

    // Path-specific block `||host/path/segments` from complex-first feeds with no restrictive `$domain=`/`$image`-only modifiers
    if src.role == AdblockSourceRole::ComplexFirst
        && !has_domain_scope
        && domain_scopes.is_none()
        && is_whole_request_blocking_mods(&mod_tokens)
        && pat.starts_with("||")
        && let Some((regex, Some(host))) = abp_url_pattern_to_surge_regex(pat)
        && has_non_trivial_path_segment(&regex)
    {
        out.complex_protected_hosts.insert(host.clone());
        out.mitm_hosts.insert(host);
        out.url_rewrites.push(UrlRewriteRule {
            pattern: regex,
            replacement: "_".to_string(),
            mode: UrlRewriteMode::Reject,
            weight: src.weight,
        });
        return true;
    }

    false
}

fn has_non_trivial_path_segment(regex: &str) -> bool {
    if let Some(idx) = regex.find("://") {
        let rest = &regex[idx + 3..];
        if let Some(slash) = rest.find('/') {
            let path = &rest[slash..];
            return path.len() >= 4;
        }
    }
    false
}

fn is_whole_request_blocking_mods(mods: &[&str]) -> bool {
    mods.iter().all(|m| {
        matches!(
            *m,
            "important" | "all" | "document" | "doc" | "empty" | "match-case"
        )
    })
}

fn parse_fallback_domain_rule(pat: &str, mods: &str, out: &mut ParsedAdblockSource) {
    let mod_tokens: Vec<&str> = mods
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    if !is_whole_request_blocking_mods(&mod_tokens) {
        return;
    }

    if let Some(dom) = extract_exact_abp_domain(pat) {
        out.ruleset_suffixes.insert(dom);
        return;
    }

    // Intra-label wildcard pattern like `||ad-*.example.com^`
    if let Some(inner) = pat.strip_prefix("||")
        && let Some(stripped) = inner.strip_suffix('^')
        && !stripped.contains('/')
        && !stripped.contains('?')
        && stripped.contains('*')
        && !stripped.starts_with("*.")
    {
        let pat_lower = stripped.to_ascii_lowercase();
        if is_valid_domain_wildcard(&pat_lower) {
            out.ruleset_wildcards.insert(pat_lower);
        }
    }
}

fn extract_exact_abp_domain(pat: &str) -> Option<String> {
    let inner = pat.strip_prefix("||")?.strip_suffix('^')?;
    if inner.contains(['/', '*', '?', ':', '|', '$']) {
        return None;
    }
    let dom = inner.trim_end_matches('.').to_ascii_lowercase();
    if is_valid_domain(&dom) {
        Some(dom)
    } else {
        None
    }
}

fn extract_positive_domain_option(mods: &[&str]) -> Option<Vec<String>> {
    for m in mods {
        if let Some(raw) = m
            .strip_prefix("domain=")
            .or_else(|| m.strip_prefix("from="))
        {
            let mut out = Vec::new();
            for item in raw.split('|').map(str::trim) {
                if item.is_empty() || item.starts_with('~') {
                    return None;
                }
                let dom = item.trim_end_matches('.').to_ascii_lowercase();
                if is_valid_domain(&dom) {
                    out.push(dom);
                }
            }
            if !out.is_empty() {
                return Some(out);
            }
        }
    }
    None
}

fn parse_literal_removeparam_name(spec: &str) -> Option<String> {
    let clean = spec.trim();
    if clean.is_empty()
        || clean.starts_with('/')
        || clean.starts_with('~')
        || clean.contains('=')
        || clean.contains('|')
        || clean.contains('*')
    {
        return None;
    }
    if clean.len() >= 2
        && clean.len() <= 48
        && clean
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        Some(clean.to_string())
    } else {
        None
    }
}

fn emit_removeparam_rules(
    pat: &str,
    domain_scopes: Option<&[String]>,
    param_name: String,
    weight: u16,
    out: &mut ParsedAdblockSource,
) {
    if let Some(domains) = domain_scopes {
        for dom in domains {
            out.remove_params.push(RemoveParamRule {
                host_scope: dom.clone(),
                param: param_name.clone(),
                weight,
            });
        }
        return;
    }

    if let Some(dom) = extract_exact_abp_domain(pat) {
        out.remove_params.push(RemoveParamRule {
            host_scope: dom,
            param: param_name,
            weight,
        });
        return;
    }

    if let Some((_, Some(host))) = abp_url_pattern_to_surge_regex(pat) {
        out.remove_params.push(RemoveParamRule {
            host_scope: host,
            param: param_name,
            weight,
        });
        return;
    }

    if matches!(pat, "" | "*" | "*^" | "|http" | "||*")
        && SAFE_GLOBAL_TRACKING_PARAMS
            .iter()
            .any(|p| p.eq_ignore_ascii_case(&param_name))
    {
        out.remove_params.push(RemoveParamRule {
            host_scope: "*".to_string(),
            param: param_name,
            weight,
        });
    }
}

fn map_redirect_resource(name: &str) -> Option<(MapLocalDataType, Option<String>, Option<String>)> {
    match name.trim().to_ascii_lowercase().as_str() {
        "noopjson" | "noop.json" => Some((
            MapLocalDataType::Text,
            Some("{}".to_string()),
            Some("Content-Type: application/json; charset=utf-8".to_string()),
        )),
        "nooparray" => Some((
            MapLocalDataType::Text,
            Some("[]".to_string()),
            Some("Content-Type: application/json; charset=utf-8".to_string()),
        )),
        "nooptext" | "empty" => Some((MapLocalDataType::Text, Some(String::new()), None)),
        "noopjs" | "noop.js" => Some((
            MapLocalDataType::Text,
            Some("(function(){})();".to_string()),
            Some("Content-Type: application/javascript; charset=utf-8".to_string()),
        )),
        "1x1-transparent.gif" | "1x1.gif" | "2x2-transparent.png" | "blank-gif" => {
            Some((MapLocalDataType::TinyGif, None, None))
        }
        _ => None,
    }
}

fn parse_removeheader_spec(spec: &str) -> Option<(HeaderDirection, String)> {
    let trimmed = spec.trim();
    let (dir, field) = if let Some(rest) = trimmed.strip_prefix("request:") {
        (HeaderDirection::HttpRequest, rest.trim())
    } else if let Some(rest) = trimmed.strip_prefix("response:") {
        (HeaderDirection::HttpResponse, rest.trim())
    } else {
        (HeaderDirection::HttpResponse, trimmed)
    };
    if field.is_empty()
        || !field
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return None;
    }
    Some((dir, field.to_string()))
}

fn parse_replace_spec(spec: &str) -> Option<(String, String)> {
    let trimmed = spec.trim();
    let rest = trimmed.strip_prefix('/')?;
    let mut parts = Vec::with_capacity(3);
    let mut cur = String::new();
    let mut chars = rest.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                if next == '/' {
                    cur.push('/');
                    chars.next();
                } else {
                    cur.push('\\');
                    cur.push(chars.next()?);
                }
            } else {
                return None;
            }
        } else if c == '/' {
            parts.push(std::mem::take(&mut cur));
            if parts.len() == 2 {
                // Remaining chars are regex flags
                let flags: String = chars.collect();
                cur = flags;
                break;
            }
        } else {
            cur.push(c);
        }
    }
    if parts.len() != 2 {
        return None;
    }
    let body_pat_raw = &parts[0];
    let repl = parts[1].trim();
    let flags = cur.trim();
    if body_pat_raw.is_empty()
        || repl.is_empty()
        || body_pat_raw
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        || repl.chars().any(|c| c.is_whitespace() || c.is_control())
        || !flags.chars().all(|c| matches!(c, 'i' | 'g' | 'm'))
    {
        return None;
    }
    let body_regex = if flags.contains('i') {
        format!("(?i){}", body_pat_raw)
    } else {
        body_pat_raw.to_string()
    };
    if Regex::new(&body_regex).is_err() {
        return None;
    }
    Some((body_regex, repl.to_string()))
}
