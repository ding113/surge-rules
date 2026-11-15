use regex::Regex;
use rustc_hash::FxHashSet;

use crate::adblock::config::{AdblockSourceConfig, AdblockSourceRole};
use crate::adblock::jq_transpile::transpile_jsonprune_to_jq;
use crate::adblock::model::{
    AdguardTransformOp, AdguardTransformRule, BodyRewriteKind, BodyRewriteRule, HeaderAction,
    HeaderDirection, HeaderRewriteRule, MapLocalDataType, MapLocalRule, ParsedAdblockSource,
    RemoveParamRule, UrlRewriteMode, UrlRewriteRule,
};
use crate::adblock::regex_util::{
    abp_surgical_pattern_to_surge_regex, abp_url_pattern_to_surge_regex, extract_hosts_from_regex,
    is_valid_domain, is_valid_domain_wildcard,
};

const SAFE_GLOBAL_TRACKING_PARAMS: &[&str] = &[
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "utm_name",
    "utm_reader",
    "utm_viz_id",
    "utm_pubreferrer",
    "utm_swu",
    "fbclid",
    "gclid",
    "dclid",
    "gbraid",
    "wbraid",
    "msclkid",
    "ttclid",
    "twclid",
    "igshid",
    "igsh",
    "mc_eid",
    "mc_cid",
    "yclid",
    "ymclid",
    "_openstat",
    "_hsenc",
    "_hsmi",
    "mkt_tok",
    "srsltid",
    "tgclid",
    "li_fat_id",
    "wickedid",
    "vero_id",
    "vero_conv",
    "rb_clickid",
    "s_kwcid",
    "ef_id",
    "epik",
    "irclickid",
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
            let mut mod_list = split_abp_modifiers(mods);
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
            parse_removeparam_exception(exc, out);
            if src.role == AdblockSourceRole::Allowlist || is_whole_domain_exception(exc) {
                parse_exception_line(exc, out);
            }
            continue;
        }

        let (pat, mods_opt) = match split_pattern_and_modifiers(line) {
            Some((p, m)) => (p, Some(m)),
            None => (line, None),
        };
        let mut sorted_mods = mods_opt.map(split_abp_modifiers).unwrap_or_default();
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
    line.starts_with("##")
        || line.starts_with("#@#")
        || line.starts_with("#?#")
        || line.starts_with("#%#")
        || line.starts_with("#@%#")
        || line.starts_with("#$#")
        || line.starts_with("#@$#")
}

/// Detects ABP/uBO/AdGuard cosmetic, extended CSS, scriptlet, and HTML filtering syntax.
pub fn contains_cosmetic_or_scriptlet_syntax(line: &str) -> bool {
    for marker in [
        "##", "#@#", "#?#", "#@?#", "#$#", "#@$#", "#%#", "#@%#", "#+js(", "##+js(", "$$", "$@$",
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
        let mut in_class = false;
        for i in 1..bytes.len() {
            if escaped {
                escaped = false;
                continue;
            }
            if bytes[i] == b'\\' {
                escaped = true;
                continue;
            }
            if bytes[i] == b'[' {
                in_class = true;
                continue;
            }
            if bytes[i] == b']' && in_class {
                in_class = false;
                continue;
            }
            if bytes[i] == b'/' && !in_class {
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
        "jsonprune=",
        "replace=",
        "hls=",
        "xmlprune=",
        "redirect",
        "rewrite=",
        "removeheader=",
        "header=",
        "domain=",
        "from=",
        "to=",
        "denyallow=",
        "method=",
        "stealth",
        "urltransform=",
        "badfilter",
        "important",
        "all",
        "document",
        "doc",
        "elemhide",
        "generichide",
        "specifichide",
        "jsinject",
        "content",
        "urlblock",
        "extension",
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
        "websocket",
        "webrtc",
        "other",
    ];
    PREFIXES.iter().any(|p| s.starts_with(p))
}

/// Splits ABP/AdGuard modifier lists on top-level commas while respecting:
/// - `\,` escaped commas (e.g. inside `$jsonprune=\$..[a\, b]` or `$xmlprune`)
/// - `/pat/repl/flags` two-section regex literals on `replace=/.../.../`
/// - `/pat/flags` one-section regex literals on `removeparam=/.../i`, `hls=/.../t`, etc.
/// - `/` inside `[...]` character classes inside regex literals
pub fn split_abp_modifiers(mods: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = mods.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut slashes_remaining = 0u8;
    let mut in_char_class = false;
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
        if slashes_remaining > 0 {
            if b == b'[' {
                in_char_class = true;
            } else if b == b']' && in_char_class {
                in_char_class = false;
            } else if b == b'/' && !in_char_class {
                slashes_remaining -= 1;
            }
            i += 1;
            continue;
        }
        if b == b'/' && i > start && bytes[i - 1] == b'=' {
            let key = mods[start..i - 1].trim();
            slashes_remaining = if key == "replace" || key == "urltransform" {
                2
            } else {
                1
            };
            i += 1;
            continue;
        }
        if b == b',' {
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
            for m in split_abp_modifiers(mods) {
                if !matches!(m, "important" | "all" | "document" | "doc") {
                    valid = false;
                    break;
                }
            }
            valid
        }
    }
}

fn parse_removeparam_exception(exc: &str, out: &mut ParsedAdblockSource) {
    let Some((pat, mods)) = split_pattern_and_modifiers(exc) else {
        return;
    };
    let mod_tokens = split_abp_modifiers(mods);
    let mut exempt_tokens: Vec<String> = Vec::new();
    for m in &mod_tokens {
        if *m == "removeparam" {
            exempt_tokens.push("*".to_string());
        } else if let Some(spec) = m.strip_prefix("removeparam=")
            && let Some(lit) = parse_literal_removeparam_name(spec)
        {
            exempt_tokens.push(lit.to_ascii_lowercase());
        }
    }
    if exempt_tokens.is_empty() {
        return;
    }

    let domain_opt = extract_domain_option(&mod_tokens);
    let target_hosts: Vec<String> = match domain_opt {
        DomainOption::Positive(doms) => doms,
        DomainOption::None => {
            if let Some(dom) = extract_exact_abp_domain(pat) {
                vec![dom]
            } else if let Some((_, Some(host))) = abp_url_pattern_to_surge_regex(pat) {
                vec![host]
            } else {
                Vec::new()
            }
        }
        DomainOption::HasNegative(_) => Vec::new(),
    };

    for host in target_hosts {
        for tok in &exempt_tokens {
            out.removeparam_exceptions.push((host.clone(), tok.clone()));
        }
    }
}

fn parse_exception_line(exc: &str, out: &mut ParsedAdblockSource) {
    let (pat, mods_opt) = match split_pattern_and_modifiers(exc) {
        Some((p, m)) => (p, Some(m)),
        None => (exc, None),
    };
    let Some(dom) = extract_exact_abp_domain(pat) else {
        return;
    };
    if let Some(mods) = mods_opt {
        let mod_tokens = split_abp_modifiers(mods);
        for m in &mod_tokens {
            if m.starts_with("removeparam")
                || m.starts_with("redirect")
                || m.starts_with("replace=")
                || m.starts_with("jsonprune=")
                || matches!(
                    *m,
                    "elemhide"
                        | "generichide"
                        | "specifichide"
                        | "jsinject"
                        | "content"
                        | "urlblock"
                )
            {
                return;
            }
            if m.starts_with("domain=") || m.starts_with("from=") {
                // Only accept `$domain=` exceptions when they are first-party self-unbreaks
                // (e.g. `@@||console.bce.baidu.com^$domain=console.bce.baidu.com`).
                match extract_domain_option(&mod_tokens) {
                    DomainOption::Positive(pos_doms)
                        if pos_doms
                            .iter()
                            .any(|pd| dom == *pd || dom.ends_with(&format!(".{}", pd))) => {}
                    _ => return,
                }
            }
        }
        if mod_tokens.iter().any(|t| matches!(*t, "document" | "doc")) {
            out.allow_suffix_domains.insert(dom);
            return;
        }
    }
    out.allow_exact_domains.insert(dom.clone());
    out.allow_suffix_domains.insert(dom);
}

enum DomainOption {
    None,
    Positive(Vec<String>),
    HasNegative(Vec<String>),
}

fn extract_domain_option(mods: &[&str]) -> DomainOption {
    for m in mods {
        if let Some(raw) = m
            .strip_prefix("domain=")
            .or_else(|| m.strip_prefix("from="))
        {
            let mut pos = Vec::new();
            let mut neg = Vec::new();
            for item in raw.split('|').map(str::trim) {
                if item.is_empty() {
                    continue;
                }
                if let Some(stripped) = item.strip_prefix('~') {
                    let dom = stripped.trim_end_matches('.').to_ascii_lowercase();
                    if is_valid_domain(&dom) {
                        neg.push(dom);
                    } else {
                        return DomainOption::HasNegative(Vec::new());
                    }
                } else {
                    let dom = item.trim_end_matches('.').to_ascii_lowercase();
                    if is_valid_domain(&dom) {
                        pos.push(dom);
                    }
                }
            }
            if !neg.is_empty() {
                return DomainOption::HasNegative(neg);
            }
            if !pos.is_empty() {
                return DomainOption::Positive(pos);
            }
            return DomainOption::HasNegative(Vec::new());
        }
    }
    DomainOption::None
}

fn register_complex_target(
    is_complex_first: bool,
    regex: &str,
    concrete_hosts: &[String],
    out: &mut ParsedAdblockSource,
) {
    if !is_complex_first {
        return;
    }
    let info = extract_hosts_from_regex(regex);
    for m in info.mitm_patterns {
        out.mitm_hosts.insert(m);
    }
    for ch in info.concrete_hosts {
        out.complex_protected_hosts.insert(ch);
    }
    for ch in concrete_hosts {
        if is_valid_domain(ch) {
            out.complex_protected_hosts.insert(ch.clone());
            out.mitm_hosts.insert(ch.clone());
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

    // Skip client-app/CSP/popup/denyallow rules that have no direct Surge equivalent
    for m in &mod_tokens {
        if m.starts_with("app=")
            || m.starts_with("csp=")
            || m.starts_with("permissions=")
            || m.starts_with("denyallow=")
            || m.starts_with("header=")
            || m.starts_with("urltransform=")
            || m.starts_with("stealth")
            || *m == "popup"
            || *m == "popunder"
        {
            return true;
        }
    }

    let is_complex_first = src.role == AdblockSourceRole::ComplexFirst;
    let domain_opt = extract_domain_option(&mod_tokens);
    let has_any_domain_scope = !matches!(domain_opt, DomainOption::None);
    let positive_domains: Option<&[String]> = match &domain_opt {
        DomainOption::Positive(v) => Some(v.as_slice()),
        _ => None,
    };
    let has_negative_domains = matches!(domain_opt, DomainOption::HasNegative(_));

    let mut handled = false;

    for m in &mod_tokens {
        if *m == "removeparam" {
            handled = true;
            if is_complex_first
                && !has_negative_domains
                && positive_domains.is_none()
                && let Some(dom) = extract_exact_abp_domain(pat)
            {
                out.remove_params.push(RemoveParamRule {
                    host_scope: dom,
                    param: "*".to_string(),
                    weight: src.weight,
                });
            }
        } else if let Some(param_spec) = m.strip_prefix("removeparam=") {
            handled = true;
            if let DomainOption::HasNegative(ref negs) = domain_opt
                && let Some(param_tok) = parse_removeparam_token(param_spec)
            {
                // Record negative domain exclusions (`domain=~site.com`) so global removeparam respects them
                for nd in negs {
                    out.removeparam_exceptions
                        .push((nd.clone(), param_tok.clone()));
                }
            }
            if !has_negative_domains && let Some(param_tok) = parse_removeparam_token(param_spec) {
                emit_removeparam_rules(pat, positive_domains, param_tok, src.weight, out);
            }
        } else if let Some(jp) = m.strip_prefix("jsonprune=") {
            handled = true;
            if !has_negative_domains
                && let Some((regex, concrete_hosts)) =
                    abp_surgical_pattern_to_surge_regex(pat, positive_domains, true)
            {
                register_complex_target(is_complex_first, &regex, &concrete_hosts, out);
                if let Some(jq_expr) = transpile_jsonprune_to_jq(jp) {
                    let rule = BodyRewriteRule {
                        kind: BodyRewriteKind::HttpResponseJq,
                        pattern: regex,
                        expression: jq_expr,
                        replacement: None,
                        weight: src.weight,
                    };
                    if is_complex_first {
                        out.body_rewrites.push(rule);
                    } else {
                        out.fallback_body_rewrites.push(rule);
                    }
                } else if let Some(clean_expr) = normalize_jsonprune_runtime_expr(jp) {
                    let rule = AdguardTransformRule {
                        pattern: regex,
                        op: AdguardTransformOp::JsonPrune { expr: clean_expr },
                        weight: src.weight,
                    };
                    if is_complex_first {
                        out.adguard_transforms.push(rule);
                    } else {
                        out.fallback_adguard_transforms.push(rule);
                    }
                }
            }
        } else if let Some(rep_spec) = m.strip_prefix("replace=") {
            handled = true;
            if !has_negative_domains
                && let Some((url_regex, concrete_hosts)) =
                    abp_surgical_pattern_to_surge_regex(pat, positive_domains, is_complex_first)
            {
                if let Some((body_regex, repl)) = parse_native_replace_spec(rep_spec) {
                    register_complex_target(is_complex_first, &url_regex, &concrete_hosts, out);
                    let rule = BodyRewriteRule {
                        kind: BodyRewriteKind::HttpResponse,
                        pattern: url_regex,
                        expression: body_regex,
                        replacement: Some(repl),
                        weight: src.weight,
                    };
                    if is_complex_first {
                        out.body_rewrites.push(rule);
                    } else {
                        out.fallback_body_rewrites.push(rule);
                    }
                } else if let Some((pat_js, rep_js, flags_js)) =
                    parse_runtime_replace_spec(rep_spec)
                {
                    register_complex_target(is_complex_first, &url_regex, &concrete_hosts, out);
                    let rule = AdguardTransformRule {
                        pattern: url_regex,
                        op: AdguardTransformOp::Replace {
                            pat: pat_js,
                            rep: rep_js,
                            flags: flags_js,
                        },
                        weight: src.weight,
                    };
                    if is_complex_first {
                        out.adguard_transforms.push(rule);
                    } else {
                        out.fallback_adguard_transforms.push(rule);
                    }
                }
            }
        } else if let Some(hls_spec) = m.strip_prefix("hls=") {
            handled = true;
            if !has_negative_domains
                && let Some((pat_js, flags_js)) = parse_single_regex_modifier(hls_spec)
                && let Some((url_regex, concrete_hosts)) =
                    abp_surgical_pattern_to_surge_regex(pat, positive_domains, true)
            {
                register_complex_target(is_complex_first, &url_regex, &concrete_hosts, out);
                let rule = AdguardTransformRule {
                    pattern: url_regex,
                    op: AdguardTransformOp::Hls {
                        pat: pat_js,
                        flags: flags_js,
                    },
                    weight: src.weight,
                };
                if is_complex_first {
                    out.adguard_transforms.push(rule);
                } else {
                    out.fallback_adguard_transforms.push(rule);
                }
            }
        } else if let Some(xp_spec) = m.strip_prefix("xmlprune=") {
            handled = true;
            if !has_negative_domains
                && let Some(clean_xp) = normalize_xmlprune_expr(xp_spec)
                && let Some((url_regex, concrete_hosts)) =
                    abp_surgical_pattern_to_surge_regex(pat, positive_domains, true)
            {
                register_complex_target(is_complex_first, &url_regex, &concrete_hosts, out);
                let rule = AdguardTransformRule {
                    pattern: url_regex,
                    op: AdguardTransformOp::XmlPrune { expr: clean_xp },
                    weight: src.weight,
                };
                if is_complex_first {
                    out.adguard_transforms.push(rule);
                } else {
                    out.fallback_adguard_transforms.push(rule);
                }
            }
        } else if let Some(redir) = m
            .strip_prefix("redirect=")
            .or_else(|| m.strip_prefix("redirect-rule="))
            .or_else(|| m.strip_prefix("rewrite=abp-resource:"))
        {
            handled = true;
            if !has_any_domain_scope
                && let Some((data_type, data, header)) = map_redirect_resource(redir)
                && let Some((regex, host_opt)) = abp_url_pattern_to_surge_regex(pat)
            {
                if is_complex_first && let Some(ref host) = host_opt {
                    out.complex_protected_hosts.insert(host.clone());
                    out.mitm_hosts.insert(host.clone());
                }
                let rule = MapLocalRule {
                    pattern: regex,
                    data_type,
                    data,
                    status_code: Some(200),
                    header,
                    weight: src.weight,
                };
                if is_complex_first {
                    out.map_locals.push(rule);
                } else {
                    out.fallback_map_locals.push(rule);
                }
            }
        } else if let Some(hdr) = m.strip_prefix("removeheader=") {
            handled = true;
            if !has_negative_domains
                && let Some((dir, field)) = parse_removeheader_spec(hdr)
                && !field.eq_ignore_ascii_case("content-length")
                && !field.eq_ignore_ascii_case("transfer-encoding")
                && let Some((regex, concrete_hosts)) =
                    abp_surgical_pattern_to_surge_regex(pat, positive_domains, true)
            {
                register_complex_target(is_complex_first, &regex, &concrete_hosts, out);
                let rule = HeaderRewriteRule {
                    direction: dir,
                    pattern: regex,
                    action: HeaderAction::HeaderDel,
                    field,
                    value: None,
                    replace_regex: None,
                    weight: src.weight,
                };
                if is_complex_first {
                    out.header_rewrites.push(rule);
                } else {
                    out.fallback_header_rewrites.push(rule);
                }
            }
        }
    }

    if handled {
        return true;
    }

    // Path-specific block `||host/path/segments` from complex-first feeds with no restrictive `$domain=`/`$image`-only modifiers
    if is_complex_first
        && !has_any_domain_scope
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
    let mod_tokens = split_abp_modifiers(mods);

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
    let after_anchor = pat.strip_prefix("||")?;
    let inner = after_anchor.strip_suffix('^').unwrap_or(after_anchor);
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
    if clean.len() <= 64
        && clean
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        Some(clean.to_string())
    } else {
        None
    }
}

fn percent_encode_arg_token(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 12);
    for b in raw.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn parse_removeparam_token(spec: &str) -> Option<String> {
    let trimmed = spec.trim();
    if trimmed.starts_with('/') {
        let (pat, flags) = parse_single_regex_modifier(trimmed)?;
        // Anchor check: reject overly broad `.` or `.*` regexes
        if matches!(pat.as_str(), "" | "." | ".*" | ".+" | "^.*$") {
            return None;
        }
        return Some(format!("~{}:{}", flags, percent_encode_arg_token(&pat)));
    }
    let lit = parse_literal_removeparam_name(trimmed)?;
    // Single-letter literal params (`c`, `s`, `p`, `q`, `t`) are only safe on explicit host scopes;
    // `emit_removeparam_rules` enforces `SAFE_GLOBAL_TRACKING_PARAMS` for global `*`.
    Some(lit)
}

fn is_safe_global_removeparam_token(token: &str) -> bool {
    if let Some(rest) = token.strip_prefix('~') {
        let Some((_flags, encoded)) = rest.split_once(':') else {
            return false;
        };
        // Only allow `^`-anchored safe tracking prefix regexes globally
        let lower = encoded.to_ascii_lowercase();
        return lower.starts_with("%5eutm_")
            || lower.starts_with("%5emtm_")
            || lower.starts_with("%5epk_")
            || lower.starts_with("%5ehsa_")
            || lower.starts_with("%5ematomo_");
    }
    SAFE_GLOBAL_TRACKING_PARAMS
        .iter()
        .any(|p| p.eq_ignore_ascii_case(token))
}

fn emit_removeparam_rules(
    pat: &str,
    domain_scopes: Option<&[String]>,
    param_token: String,
    weight: u16,
    out: &mut ParsedAdblockSource,
) {
    // 1. If URL pattern itself has a concrete target host (e.g. `||brightcovecdn.com/playback/...$removeparam=ad_config_id,domain=tvnz.co.nz`),
    //    scope to the request URL's host rather than the referring page's domain!
    if let Some(dom) = extract_exact_abp_domain(pat) {
        out.remove_params.push(RemoveParamRule {
            host_scope: dom,
            param: param_token,
            weight,
        });
        return;
    }

    if let Some((_, Some(host))) = abp_url_pattern_to_surge_regex(pat) {
        out.remove_params.push(RemoveParamRule {
            host_scope: host,
            param: param_token,
            weight,
        });
        return;
    }

    // 2. Otherwise use positive `domain=` scopes when pattern is path-only or empty
    if let Some(domains) = domain_scopes {
        for dom in domains {
            out.remove_params.push(RemoveParamRule {
                host_scope: dom.clone(),
                param: param_token.clone(),
                weight,
            });
        }
        return;
    }

    // 3. Global tracking param (`$removeparam=utm_source`)
    if (matches!(pat, "" | "*" | "*^" | "|http" | "||*")
        || (!pat.starts_with("||") && !pat.contains("://") && pat.len() <= 24))
        && is_safe_global_removeparam_token(&param_token)
    {
        out.remove_params.push(RemoveParamRule {
            host_scope: "*".to_string(),
            param: param_token,
            weight,
        });
    }
}

fn map_redirect_resource(name: &str) -> Option<(MapLocalDataType, Option<String>, Option<String>)> {
    let clean = name
        .trim()
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    match clean.as_str() {
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
        "noopcss" | "noop.css" => Some((
            MapLocalDataType::Text,
            Some(String::new()),
            Some("Content-Type: text/css; charset=utf-8".to_string()),
        )),
        "noopframe" | "noophtml" | "noop.html" | "click2load.html" => Some((
            MapLocalDataType::Text,
            Some("<!DOCTYPE html><html><head></head><body></body></html>".to_string()),
            Some("Content-Type: text/html; charset=utf-8".to_string()),
        )),
        "noopvast-2.0" | "noopvast-3.0" | "noopvast-4.0" | "empty-vast" => Some((
            MapLocalDataType::Text,
            Some("<VAST version=\"3.0\"/>".to_string()),
            Some("Content-Type: application/xml; charset=utf-8".to_string()),
        )),
        "noopvmap-1.0" | "noop-vmap1.0" | "noop-vmap1.0.xml" => Some((
            MapLocalDataType::Text,
            Some(
                "<vmap:VMAP xmlns:vmap=\"http://www.iab.net/videosuite/vmap\" version=\"1.0\"/>"
                    .to_string(),
            ),
            Some("Content-Type: application/xml; charset=utf-8".to_string()),
        )),
        "noopjs"
        | "noop.js"
        | "nobab"
        | "nobab.js"
        | "prevent-fab-3.2.0"
        | "fuckadblock.js-3.2.0"
        | "google-analytics"
        | "google-analytics.com/analytics.js"
        | "googletagmanager-gtm"
        | "googletagmanager.com/gtm.js"
        | "googletagservices-gpt"
        | "googletagservices.com/gpt.js"
        | "googlesyndication-adsbygoogle"
        | "googlesyndication.com/adsbygoogle.js"
        | "google-ima3"
        | "imasdk.googleapis.com/js/sdkloader/ima3.js"
        | "amazon-apstag"
        | "amazon-adsystem.com/aax2/apstag.js"
        | "scorecardresearch-beacon"
        | "fingerprintjs2"
        | "fingerprintjs3"
        | "prebid"
        | "pardot-1.0"
        | "matomo"
        | "metrika-yandex-tag"
        | "metrika-yandex-watch"
        | "didomi-loader" => Some((
            MapLocalDataType::Text,
            Some("(function(){})();".to_string()),
            Some("Content-Type: application/javascript; charset=utf-8".to_string()),
        )),
        "1x1-transparent.gif"
        | "1x1.gif"
        | "2x2-transparent.png"
        | "2x2.png"
        | "32x32-transparent.png"
        | "32x32.png"
        | "blank-gif" => Some((MapLocalDataType::TinyGif, None, None)),
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

fn normalize_jsonprune_runtime_expr(raw: &str) -> Option<String> {
    let clean = unescape_adguard_modifier_text(raw);
    let trimmed = clean.trim();
    if trimmed.is_empty() || trimmed.len() > 512 || trimmed.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(trimmed.to_string())
}

fn normalize_xmlprune_expr(raw: &str) -> Option<String> {
    let clean = unescape_adguard_modifier_text(raw);
    let trimmed = clean.trim();
    if trimmed.is_empty() || trimmed.len() > 512 || trimmed.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(trimmed.to_string())
}

/// Unescapes AdGuard modifier-level `\$` -> `$`, `\,` -> `,`, `\/` -> `/` while preserving
/// regex escapes (`\d`, `\s`, `\(`, `\\`, etc.).
fn unescape_adguard_modifier_text(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek().copied() {
                Some('$') | Some(',') | Some('/') => {
                    out.push(chars.next().unwrap());
                }
                Some(next) => {
                    out.push('\\');
                    out.push(next);
                    chars.next();
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn unescape_adguard_replacement(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn split_slash_delimited_sections(
    spec: &str,
    expected_sections: usize,
) -> Option<(Vec<String>, String)> {
    let rest = spec.trim().strip_prefix('/')?;
    let mut sections = Vec::with_capacity(expected_sections);
    let mut cur = String::new();
    let mut in_class = false;
    let mut chars = rest.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            let next = chars.next()?;
            if next == '/' && !in_class {
                cur.push('/');
            } else {
                cur.push('\\');
                cur.push(next);
            }
            continue;
        }
        if c == '[' && sections.is_empty() {
            in_class = true;
            cur.push(c);
            continue;
        }
        if c == ']' && in_class {
            in_class = false;
            cur.push(c);
            continue;
        }
        if c == '/' && !in_class {
            sections.push(std::mem::take(&mut cur));
            if sections.len() == expected_sections {
                let flags: String = chars.collect();
                return Some((sections, flags.trim().to_string()));
            }
            continue;
        }
        cur.push(c);
    }
    None
}

fn sanitize_js_regex_flags(raw_flags: &str) -> String {
    let mut out = String::new();
    for ch in raw_flags.chars() {
        if matches!(ch, 'i' | 'm' | 's' | 'u') && !out.contains(ch) {
            out.push(ch);
        }
    }
    out
}

fn parse_single_regex_modifier(spec: &str) -> Option<(String, String)> {
    let (sections, raw_flags) = split_slash_delimited_sections(spec, 1)?;
    let pat = unescape_adguard_modifier_text(&sections[0]);
    if pat.is_empty() || pat.len() > 512 || pat.chars().any(|c| c.is_control()) {
        return None;
    }
    let flags = sanitize_js_regex_flags(&raw_flags);
    let probe = pat.replace("[\\s\\S]", "(?:.|\\n)");
    if !pat.contains("(?=")
        && !pat.contains("(?!")
        && !pat.contains("(?<=")
        && !pat.contains("(?<!")
        && Regex::new(&probe).is_err()
    {
        return None;
    }
    Some((pat, flags))
}

fn parse_native_replace_spec(spec: &str) -> Option<(String, String)> {
    let (sections, raw_flags) = split_slash_delimited_sections(spec, 2)?;
    let body_pat_raw = unescape_adguard_modifier_text(&sections[0]);
    let repl_raw = unescape_adguard_replacement(&sections[1]);
    if body_pat_raw.is_empty()
        || repl_raw.is_empty()
        || body_pat_raw.contains("[\\s\\S]")
        || repl_raw.contains('$')
        || body_pat_raw
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        || repl_raw
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        || !raw_flags.chars().all(|c| matches!(c, 'i' | 'g' | 'm'))
    {
        return None;
    }
    let body_regex = if raw_flags.contains('i') {
        format!("(?i){}", body_pat_raw)
    } else {
        body_pat_raw
    };
    if Regex::new(&body_regex).is_err() {
        return None;
    }
    Some((body_regex, repl_raw))
}

fn parse_runtime_replace_spec(spec: &str) -> Option<(String, String, String)> {
    let (sections, raw_flags) = split_slash_delimited_sections(spec, 2)?;
    let pat = unescape_adguard_modifier_text(&sections[0]);
    let rep = unescape_adguard_replacement(&sections[1]);
    if pat.is_empty()
        || pat.len() > 1024
        || rep.len() > 1024
        || pat.chars().any(|c| matches!(c, '\r' | '\n' | '\0'))
    {
        return None;
    }
    let probe = pat.replace("[\\s\\S]", "(?:.|\\n)");
    if !pat.contains("(?=")
        && !pat.contains("(?!")
        && !pat.contains("(?<=")
        && !pat.contains("(?<!")
        && Regex::new(&probe).is_err()
    {
        return None;
    }
    let mut flags = String::from("g");
    for ch in sanitize_js_regex_flags(&raw_flags).chars() {
        if !flags.contains(ch) {
            flags.push(ch);
        }
    }
    Some((pat, rep, flags))
}
