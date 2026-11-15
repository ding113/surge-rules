use std::net::IpAddr;

use regex::Regex;

/// Normalizes a Surge URL regex pattern and rejects malformed or catch-all patterns.
pub fn normalize_surge_regex(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || !trimmed.is_ascii()
        || trimmed.chars().any(|c| c.is_control() || c.is_whitespace())
        || trimmed.contains('"')
        || trimmed.contains(",,")
        || trimmed.ends_with(',')
    {
        return None;
    }

    // Repair common upstream typos (`^http?:` -> `^https?:`, `(>?` -> `(?:`) and unescape `\/` -> `/`
    let mut normalized = trimmed.replace("\\/", "/").replace("(>?", "(?:");
    if let Some(rest) = normalized.strip_prefix("^http?://") {
        normalized = format!("^https?://{}", rest);
    }

    if is_catch_all_regex(&normalized) || !has_balanced_delimiters(&normalized) {
        return None;
    }

    let syntax_probe = normalized.replace("(?>", "(?:");
    if !uses_pcre_lookaround_or_backref(&syntax_probe) && Regex::new(&syntax_probe).is_err() {
        return None;
    }

    Some(normalized)
}

fn uses_pcre_lookaround_or_backref(pat: &str) -> bool {
    if pat.contains("(?=")
        || pat.contains("(?!")
        || pat.contains("(?<=")
        || pat.contains("(?<!")
        || pat.contains("*+")
        || pat.contains("++")
        || pat.contains("?+")
    {
        return true;
    }
    let bytes = pat.as_bytes();
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i] == b'\\' && matches!(bytes[i + 1], b'1'..=b'9') {
            return true;
        }
    }
    false
}

fn is_catch_all_regex(pat: &str) -> bool {
    let bare = pat.trim_start_matches('^').trim_end_matches('$');
    if matches!(
        bare,
        "" | "."
            | ".*"
            | ".+"
            | "http://"
            | "https://"
            | "https?://"
            | "https?://.*"
            | "https?://.+"
            | "https?://[^/]+"
            | "https?://[^/]+/"
            | "https?://[^/]+/.*"
    ) {
        return true;
    }
    if bare.len() < 8 && !bare.contains('.') {
        return true;
    }
    if let Some(after_scheme) = strip_regex_scheme_prefix(pat) {
        let auth = read_authority_segment(after_scheme);
        let host_expr = strip_trailing_port_regex(auth);
        if extract_hosts_from_regex(pat).mitm_patterns.is_empty()
            && !authority_has_concrete_domain_or_ip(host_expr)
        {
            return true;
        }
    }
    false
}

fn authority_has_concrete_domain_or_ip(host_expr: &str) -> bool {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut in_class = false;
    let mut escaped = false;

    for ch in host_expr.chars() {
        if escaped {
            escaped = false;
            if !in_class {
                match ch {
                    '.' | '-' => current.push(ch),
                    _ => {
                        if !current.is_empty() {
                            segments.push(std::mem::take(&mut current));
                        }
                    }
                }
            }
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if in_class {
            if ch == ']' {
                in_class = false;
            }
            continue;
        }
        match ch {
            '[' => {
                in_class = true;
                if !current.is_empty() {
                    segments.push(std::mem::take(&mut current));
                }
            }
            c if c.is_ascii_alphanumeric() || c == '-' || c == '.' => current.push(c),
            _ => {
                if !current.is_empty() {
                    segments.push(std::mem::take(&mut current));
                }
            }
        }
    }
    if !current.is_empty() {
        segments.push(current);
    }

    segments.into_iter().any(|seg| {
        if seg.parse::<IpAddr>().is_ok() {
            return true;
        }
        let labels: Vec<&str> = seg.split('.').filter(|l| !l.is_empty()).collect();
        labels.len() >= 2
            && !is_bare_multipart_public_suffix(&labels)
            && labels.iter().all(|l| {
                !l.starts_with('-')
                    && !l.ends_with('-')
                    && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            })
            && labels
                .last()
                .is_some_and(|tld| tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic()))
    })
}

fn is_bare_multipart_public_suffix(labels: &[&str]) -> bool {
    if labels.len() != 2 {
        return false;
    }
    let joined = format!(
        "{}.{}",
        labels[0].to_ascii_lowercase(),
        labels[1].to_ascii_lowercase()
    );
    matches!(
        joined.as_str(),
        "com.cn"
            | "net.cn"
            | "org.cn"
            | "gov.cn"
            | "edu.cn"
            | "ac.cn"
            | "co.uk"
            | "org.uk"
            | "ac.uk"
            | "gov.uk"
            | "co.jp"
            | "ne.jp"
            | "or.jp"
            | "ac.jp"
            | "com.hk"
            | "com.tw"
            | "org.tw"
            | "com.au"
            | "net.au"
            | "co.kr"
            | "or.kr"
            | "com.sg"
            | "com.my"
            | "com.br"
            | "co.in"
            | "com.ru"
    )
}

/// Computes a canonical deduplication signature for Surge URL regex patterns so semantically
/// identical patterns across upstream modules (`^https://` vs `^https?://`, `(?>` vs `(?:` vs `(`,
/// leading `(?i)`) resolve cleanly by source weight rather than coexisting as duplicates.
pub fn canonical_url_pattern_key(pattern: &str) -> String {
    let mut s = pattern.trim();
    if let Some(rest) = s.strip_prefix("(?i)") {
        s = rest;
    }
    s = s.trim_start_matches('^');
    let normalized_scheme = for_scheme_normalization(s);
    normalized_scheme.replace("(?>", "(").replace("(?:", "(")
}

fn for_scheme_normalization(s: &str) -> String {
    for prefix in [
        "https?://",
        "http(s)?://",
        "(https|http)://",
        "(http|https)://",
        "https://",
    ] {
        if let Some(rest) = s.strip_prefix(prefix) {
            return format!("https?://{}", rest);
        }
    }
    s.to_string()
}

/// Generates concrete sample URLs covering top-level alternation branches of a URL regex
/// so the compiler can detect when a lower-weight `[Script]` is 100% shadowed by an already
/// accepted higher-weight `[Script]` of the same type.
pub fn sample_urls_for_regex_subsumption(pattern: &str) -> Vec<String> {
    let mut s = pattern.trim();
    if let Some(rest) = s.strip_prefix("(?i)") {
        s = rest;
    }
    let has_end_anchor = s.ends_with('$');
    let body = s.trim_start_matches('^').trim_end_matches('$');
    let Some(after_scheme) = strip_regex_scheme_prefix(body) else {
        return Vec::new();
    };
    let scheme = if body.starts_with("http://") {
        "http://"
    } else {
        "https://"
    };

    let expanded = expand_regex_branches(after_scheme, 16);
    if expanded.is_empty() || expanded.len() > 16 {
        return Vec::new();
    }

    let mut urls = Vec::with_capacity(expanded.len());
    for branch in expanded {
        let Some(mut concrete) = instantiate_regex_branch(&branch) else {
            return Vec::new();
        };
        if !has_end_anchor && concrete.ends_with('?') {
            concrete.push_str("k=1");
        }
        urls.push(format!("{}{}", scheme, concrete));
    }
    urls
}

fn expand_regex_branches(expr: &str, max_branches: usize) -> Vec<String> {
    let bytes = expr.as_bytes();
    let mut paren = 0i32;
    let mut in_class = false;
    let mut escaped = false;
    let mut group_span: Option<(usize, usize, usize)> = None;
    let mut group_start = 0usize;

    for (idx, ch) in expr.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if in_class {
            if ch == ']' {
                in_class = false;
            }
            continue;
        }
        match ch {
            '[' => in_class = true,
            '(' => {
                if paren == 0 {
                    group_start = idx;
                }
                paren += 1;
            }
            ')' => {
                paren -= 1;
                if paren == 0 {
                    let inner_start = if expr[group_start..].starts_with("(?:")
                        || expr[group_start..].starts_with("(?>")
                    {
                        group_start + 3
                    } else if expr[group_start..].starts_with("(?") {
                        return Vec::new();
                    } else {
                        group_start + 1
                    };
                    let inner = &expr[inner_start..idx];
                    // Check if followed by `?` optional quantifier
                    let next_b = bytes.get(idx + 1).copied();
                    if matches!(next_b, Some(b'*') | Some(b'+') | Some(b'{')) {
                        return Vec::new();
                    }
                    let alts = split_top_level_alternations(inner);
                    if alts.len() > 1 || next_b == Some(b'?') {
                        let end_after = if next_b == Some(b'?') {
                            idx + 2
                        } else {
                            idx + 1
                        };
                        group_span = Some((group_start, idx, end_after));
                        break;
                    }
                }
            }
            _ => {}
        }
    }

    let Some((g_start, g_close, g_after)) = group_span else {
        let top_alts = split_top_level_alternations(expr);
        if top_alts.len() > 1 {
            if top_alts.len() > max_branches {
                return Vec::new();
            }
            return top_alts.into_iter().map(str::to_string).collect();
        }
        return vec![expr.to_string()];
    };

    let inner_start = if expr[g_start..].starts_with("(?:") || expr[g_start..].starts_with("(?>") {
        g_start + 3
    } else {
        g_start + 1
    };
    let inner = &expr[inner_start..g_close];
    let mut alts: Vec<&str> = split_top_level_alternations(inner);
    if g_after == g_close + 2 {
        alts.push("");
    }
    if alts.len() > max_branches {
        return Vec::new();
    }

    let prefix = &expr[..g_start];
    let suffix = &expr[g_after..];
    let mut out = Vec::new();
    for alt in alts {
        let combined = format!("{}{}{}", prefix, alt, suffix);
        let sub = expand_regex_branches(&combined, max_branches.saturating_sub(out.len()));
        if sub.is_empty() || out.len() + sub.len() > max_branches {
            return Vec::new();
        }
        out.extend(sub);
    }
    out
}

fn instantiate_regex_branch(expr: &str) -> Option<String> {
    let mut out = String::with_capacity(expr.len());
    let mut chars = expr.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let next = chars.next()?;
                let sample = match next {
                    'd' => "1",
                    'w' => "a",
                    '.' => ".",
                    '?' => "?",
                    '-' => "-",
                    '/' => "/",
                    '_' => "_",
                    _ => return None,
                };
                out.push_str(sample);
                consume_simple_quantifier(&mut chars, &mut out, sample)?;
            }
            '[' => {
                let mut cls = String::new();
                let mut closed = false;
                for ch in chars.by_ref() {
                    if ch == ']' {
                        closed = true;
                        break;
                    }
                    cls.push(ch);
                }
                if !closed || cls.starts_with('^') {
                    return None;
                }
                let sample_ch = if cls.contains('a') || cls.contains("a-z") {
                    "a"
                } else if cls.contains('0') || cls.contains("0-9") {
                    "1"
                } else {
                    return None;
                };
                out.push_str(sample_ch);
                consume_simple_quantifier(&mut chars, &mut out, sample_ch)?;
            }
            '(' | ')' | '|' | '.' | '*' | '+' | '{' | '}' | '^' | '$' => return None,
            '?' => {
                // Optional preceding literal char — keep the literal char as instantiated
            }
            lit => {
                let mut buf = [0u8; 4];
                let s = lit.encode_utf8(&mut buf);
                out.push_str(s);
                consume_simple_quantifier(&mut chars, &mut out, s)?;
            }
        }
    }
    if out.contains('/') && out.contains('.') {
        Some(out)
    } else {
        None
    }
}

fn consume_simple_quantifier(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    out: &mut String,
    unit: &str,
) -> Option<()> {
    match chars.peek().copied() {
        Some('+') | Some('*') | Some('?') => {
            chars.next();
            Some(())
        }
        Some('{') => {
            chars.next();
            let mut q = String::new();
            let mut closed = false;
            for ch in chars.by_ref() {
                if ch == '}' {
                    closed = true;
                    break;
                }
                q.push(ch);
            }
            if !closed {
                return None;
            }
            let min_str = q.split(',').next()?.trim();
            let min_n: usize = min_str.parse().ok()?;
            if min_n == 0 || min_n > 16 {
                return None;
            }
            for _ in 1..min_n {
                out.push_str(unit);
            }
            Some(())
        }
        _ => Some(()),
    }
}

pub fn has_balanced_delimiters(pat: &str) -> bool {
    let mut paren = 0i32;
    let mut brace = 0i32;
    let mut in_class = false;
    let mut escaped = false;

    for ch in pat.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if in_class {
            if ch == ']' {
                in_class = false;
            }
            continue;
        }
        match ch {
            '[' => in_class = true,
            '(' => paren += 1,
            ')' => {
                paren -= 1;
                if paren < 0 {
                    return false;
                }
            }
            '{' => brace += 1,
            '}' => {
                brace -= 1;
                if brace < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }

    !in_class && paren == 0 && brace == 0 && !escaped
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegexHostInfo {
    pub mitm_patterns: Vec<String>,
    pub concrete_hosts: Vec<String>,
}

/// Extracts MITM host patterns and exact protected hostnames from a URL regex.
pub fn extract_hosts_from_regex(pattern: &str) -> RegexHostInfo {
    let mut mitm_patterns = Vec::new();
    let mut concrete_hosts = Vec::new();

    let Some(after_scheme) = strip_regex_scheme_prefix(pattern) else {
        return RegexHostInfo {
            mitm_patterns,
            concrete_hosts,
        };
    };

    let auth_expr = read_authority_segment(after_scheme);
    if auth_expr.is_empty() {
        return RegexHostInfo {
            mitm_patterns,
            concrete_hosts,
        };
    }

    // Strip optional `:port` matcher on the authority
    let host_expr = strip_trailing_port_regex(auth_expr);
    let branches = split_top_level_alternations(host_expr);

    for branch in branches {
        if let Some(opt_sub_rest) = branch
            .trim()
            .strip_prefix("(?:[^/?#]+\\.)?")
            .or_else(|| branch.trim().strip_prefix("(?:[a-z0-9-]+\\.)*"))
            && let Some((dom, true)) = regex_host_to_surge_pattern(opt_sub_rest)
        {
            mitm_patterns.push(dom.clone());
            let wildcard = format!("*.{}", dom);
            if is_valid_mitm_host(&wildcard) {
                mitm_patterns.push(wildcard);
            }
            concrete_hosts.push(dom);
            continue;
        }
        if let Some((mitm_host, is_exact)) = regex_host_to_surge_pattern(branch) {
            mitm_patterns.push(mitm_host.clone());
            if is_exact && !mitm_host.contains(':') && is_valid_domain(&mitm_host) {
                concrete_hosts.push(mitm_host);
            }
        }
    }

    RegexHostInfo {
        mitm_patterns,
        concrete_hosts,
    }
}

fn strip_regex_scheme_prefix(pat: &str) -> Option<&str> {
    let mut s = pat.trim_start_matches('^');
    for prefix in [
        "https?://",
        "http(s)?://",
        "(https|http)://",
        "(http|https)://",
        "https://",
        "http://",
        "wss?://",
    ] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest;
            return Some(s);
        }
    }
    None
}

fn read_authority_segment(s: &str) -> &str {
    let mut paren = 0i32;
    let mut in_class = false;
    let mut escaped = false;
    for (idx, ch) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if in_class {
            if ch == ']' {
                in_class = false;
            }
            continue;
        }
        match ch {
            '[' => in_class = true,
            '(' => paren += 1,
            ')' => {
                if paren > 0 {
                    paren -= 1;
                }
            }
            '/' | '$' | '?' if paren == 0 => return &s[..idx],
            _ => {}
        }
    }
    s
}

fn strip_trailing_port_regex(auth: &str) -> &str {
    if let Some(idx) = auth.rfind(':') {
        let right = &auth[idx + 1..];
        if right.chars().all(|c| c.is_ascii_digit()) {
            return &auth[..idx];
        }
    }
    for suffix in ["(:\\d+)?", "(?::\\d+)?", ":\\d+"] {
        if let Some(prefix) = auth.strip_suffix(suffix) {
            return prefix;
        }
    }
    auth
}

fn split_top_level_alternations(mut expr: &str) -> Vec<&str> {
    loop {
        if expr.starts_with('(') && expr.ends_with(')') && is_single_outer_group(expr) {
            let inner = expr
                .trim_start_matches("(?:")
                .trim_start_matches('(')
                .trim_end_matches(')');
            if inner != expr && !inner.is_empty() {
                expr = inner;
                continue;
            }
        }
        break;
    }

    let mut out = Vec::new();
    let mut paren = 0i32;
    let mut in_class = false;
    let mut escaped = false;
    let mut start = 0usize;

    for (idx, ch) in expr.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if in_class {
            if ch == ']' {
                in_class = false;
            }
            continue;
        }
        match ch {
            '[' => in_class = true,
            '(' => paren += 1,
            ')' => paren -= 1,
            '|' if paren == 0 => {
                out.push(&expr[start..idx]);
                start = idx + 1;
            }
            _ => {}
        }
    }
    out.push(&expr[start..]);
    out
}

fn is_single_outer_group(expr: &str) -> bool {
    let mut paren = 0i32;
    let mut in_class = false;
    let mut escaped = false;
    let len = expr.len();
    for (idx, ch) in expr.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if in_class {
            if ch == ']' {
                in_class = false;
            }
            continue;
        }
        match ch {
            '[' => in_class = true,
            '(' => paren += 1,
            ')' => {
                paren -= 1;
                if paren == 0 && idx + 1 < len {
                    return false;
                }
            }
            _ => {}
        }
    }
    paren == 0
}

fn regex_host_to_surge_pattern(branch: &str) -> Option<(String, bool)> {
    let mut s = branch.trim();
    while s.starts_with('(') && s.ends_with(')') && is_single_outer_group(s) {
        s = s
            .strip_prefix("(?:")
            .or_else(|| s.strip_prefix('('))?
            .strip_suffix(')')?;
    }
    if s.is_empty() {
        return None;
    }

    // Exact hostname with only escaped dots (`api\.weibo\.cn`)
    let mut exact = String::with_capacity(s.len());
    let mut has_wildcard = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('.') => exact.push('.'),
                Some('-') => exact.push('-'),
                Some('w') | Some('d') | Some('s') | Some('S') => has_wildcard = true,
                Some(_) => return None,
                None => return None,
            }
        } else if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
            exact.push(c);
        } else {
            has_wildcard = true;
            break;
        }
    }

    if !has_wildcard {
        let lower = exact.to_ascii_lowercase();
        if is_valid_mitm_host(&lower) && is_valid_domain(&lower) {
            return Some((lower, true));
        }
        return None;
    }

    // Replace leading regex subdomain wildcard patterns with `*.`
    for prefix in [
        ".*\\.",
        ".+\\.",
        "[a-zA-Z0-9_-]+\\.",
        "[\\w-]+\\.",
        "[\\w.-]+\\.",
        "[^./]+\\.",
        "([a-z0-9-]+\\.)+",
        "(?:[a-z0-9-]+\\.)+",
        "([\\w-]+\\.)*",
    ] {
        if let Some(rest) = s.strip_prefix(prefix) {
            let unescaped = rest.replace("\\.", ".").to_ascii_lowercase();
            let candidate = format!("*.{}", unescaped.trim_start_matches('.'));
            if is_valid_mitm_host(&candidate) {
                return Some((candidate, false));
            }
        }
    }

    // Handle leading bare `.*domain\.com`
    if let Some(rest) = s.strip_prefix(".*") {
        let unescaped = rest.replace("\\.", ".").to_ascii_lowercase();
        let candidate = format!("*{}", unescaped);
        if candidate.contains('.') && is_valid_mitm_host(&candidate) {
            return Some((candidate, false));
        }
    }

    None
}

/// Validates a domain name suitable for Surge `DOMAIN` or `DOMAIN-SUFFIX`.
pub fn is_valid_domain(raw: &str) -> bool {
    let s = raw.trim().trim_end_matches('.');
    if s.is_empty() || s.len() > 253 || !s.contains('.') {
        return false;
    }
    if s.parse::<IpAddr>().is_ok() {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for (i, label) in labels.iter().enumerate() {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        let bytes = label.as_bytes();
        if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            return false;
        }
        if !bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return false;
        }
        if i + 1 == labels.len() {
            // TLD cannot be purely numeric
            if bytes.iter().all(|b| b.is_ascii_digit()) || label.len() < 2 {
                return false;
            }
        }
    }
    true
}

/// Validates a Surge `DOMAIN-WILDCARD` pattern.
pub fn is_valid_domain_wildcard(raw: &str) -> bool {
    let s = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() || s.len() > 253 || !s.contains('.') {
        return false;
    }
    if !(s.contains('*') || s.contains('?')) {
        return false;
    }
    if s.contains(',') || s.contains('/') || s.chars().any(|c| c.is_whitespace()) {
        return false;
    }
    // Reject overly broad top-level wildcards such as `*.com` or `*`
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let concrete_labels = labels
        .iter()
        .filter(|l| !l.is_empty() && !l.contains('*') && !l.contains('?'))
        .count();
    concrete_labels >= 1
}

/// Validates a Surge `[MITM] hostname` item (without leading `-` exclusion flag).
pub fn is_valid_mitm_host(raw: &str) -> bool {
    let s = raw.trim();
    if s.is_empty() || s.contains(',') || s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    if matches!(
        s,
        "<ip-address>" | "<ipv4-address>" | "<ipv6-address>" | "<simple-hostname>"
    ) {
        return true;
    }
    if matches!(s, "*" | "*:0" | "*.*" | "*:*") {
        return false;
    }

    let (host_part, port_part) = if let Some(rest) = s.strip_prefix('[') {
        if let Some(close) = rest.find(']') {
            let ip_str = &rest[..close];
            let port = rest[close + 1..].strip_prefix(':');
            if ip_str.parse::<IpAddr>().is_err() {
                return false;
            }
            if let Some(p) = port
                && p.parse::<u16>().is_err()
            {
                return false;
            }
            return true;
        }
        return false;
    } else if let Some(colon) = s.rfind(':') {
        let p = &s[colon + 1..];
        if p != "0" && p.parse::<u16>().is_err() {
            return false;
        }
        (&s[..colon], Some(p))
    } else {
        (s, None)
    };
    let _ = port_part;

    if host_part.parse::<IpAddr>().is_ok() {
        return true;
    }
    if !host_part.contains('.') || host_part.to_ascii_lowercase().ends_with("hostname") {
        return false;
    }

    let bare = host_part.trim_start_matches("*.").trim_start_matches('.');
    // Require at least two domain labels after wildcard strip (never allow `*.com`, `*.net`, or `*.com.cn`)
    let non_wild_labels: Vec<&str> = host_part
        .split('.')
        .filter(|seg| !seg.is_empty() && *seg != "*" && *seg != "?")
        .collect();
    if non_wild_labels.len() < 2 && bare.split('.').count() < 2 {
        return false;
    }
    if (host_part.contains('*') || host_part.contains('?'))
        && is_bare_multipart_public_suffix(&non_wild_labels)
    {
        return false;
    }
    host_part
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'*' | b'?'))
}

/// Converts a literal ABP wildcard pattern (such as `||ads.example.com/banner/*`) into a Surge regex.
pub fn abp_url_pattern_to_surge_regex(pattern: &str) -> Option<(String, Option<String>)> {
    let mut raw = pattern.trim();
    if raw.is_empty() {
        return None;
    }

    // Raw `/regex/` pattern in ABP
    if raw.starts_with('/') && raw.ends_with('/') && raw.len() >= 10 {
        let inner = &raw[1..raw.len() - 1];
        let regex_str = normalize_surge_regex(inner)?;
        let hosts = extract_hosts_from_regex(&regex_str);
        return Some((regex_str, hosts.concrete_hosts.into_iter().next()));
    }

    let mut host_anchored = false;
    let mut url_start_anchored = false;
    if let Some(rest) = raw.strip_prefix("||") {
        host_anchored = true;
        raw = rest;
    } else if let Some(rest) = raw.strip_prefix('|') {
        url_start_anchored = true;
        raw = rest;
    }

    let trailing_anchor = if let Some(rest) = raw.strip_suffix('|') {
        raw = rest;
        true
    } else {
        false
    };

    if host_anchored {
        let sep_idx = raw.find(['/', '^', '?'])?;
        let host = &raw[..sep_idx];
        let tail = &raw[sep_idx..];
        let host_lower = host.trim_end_matches('^').to_ascii_lowercase();
        if !is_valid_domain(&host_lower) {
            return None;
        }
        // Only treat as complex path rule if there is a path/query beyond a bare `^`
        let clean_tail = tail.trim_start_matches('^');
        if clean_tail.is_empty() || clean_tail == "/" || clean_tail == "*" {
            return None;
        }
        let host_escaped = escape_literal_regex(&host_lower);
        let tail_regex = abp_wildcard_to_regex(clean_tail);
        let suffix_anchor = if trailing_anchor { "$" } else { "" };
        let full = format!("^https?://{}{}{}", host_escaped, tail_regex, suffix_anchor);
        let verified = normalize_surge_regex(&full)?;
        return Some((verified, Some(host_lower)));
    }

    if url_start_anchored && (raw.starts_with("http://") || raw.starts_with("https://")) {
        let regex_body = abp_wildcard_to_regex(raw);
        let suffix_anchor = if trailing_anchor { "$" } else { "" };
        let full = format!("^{}{}", regex_body, suffix_anchor);
        let verified = normalize_surge_regex(&full)?;
        let hosts = extract_hosts_from_regex(&verified);
        return Some((verified, hosts.concrete_hosts.into_iter().next()));
    }

    None
}

/// Converts an ABP URL pattern for surgical modifiers (`$jsonprune`, `$replace`, `$hls`, `$xmlprune`, `$removeheader`)
/// into `(surge_url_regex, concrete_hosts)`, supporting:
/// 1. Standard host+path or `/regex/` patterns (`abp_url_pattern_to_surge_regex`).
/// 2. Whole-host `||host^` patterns when `allow_whole_host` is true.
/// 3. Path/extension patterns paired with positive `domain=d1|d2` scopes (up to 16 concrete domains).
pub fn abp_surgical_pattern_to_surge_regex(
    pattern: &str,
    domain_scopes: Option<&[String]>,
    allow_whole_host: bool,
) -> Option<(String, Vec<String>)> {
    if let Some((regex, host_opt)) = abp_url_pattern_to_surge_regex(pattern) {
        let hosts = extract_hosts_from_regex(&regex);
        let mut concrete = hosts.concrete_hosts;
        if concrete.is_empty()
            && let Some(h) = host_opt
        {
            concrete.push(h);
        }
        if !concrete.is_empty() || !hosts.mitm_patterns.is_empty() {
            return Some((regex, concrete));
        }
    }

    let raw = pattern.trim();

    if allow_whole_host
        && let Some(inner) = raw.strip_prefix("||")
        && let Some(dom_raw) = inner.strip_suffix('^')
    {
        let dom = dom_raw.trim_end_matches('.').to_ascii_lowercase();
        if is_valid_domain(&dom) {
            let escaped = escape_literal_regex(&dom);
            let full = format!("^https?://(?:[^/?#]+\\.)?{}(?::\\d+)?/", escaped);
            let verified = normalize_surge_regex(&full)?;
            return Some((verified, vec![dom]));
        }
    }

    let domains = domain_scopes?;
    if domains.is_empty() || domains.len() > 16 {
        return None;
    }
    if raw.starts_with("||") || raw.starts_with('|') || raw.contains("://") {
        return None;
    }

    let mut path_raw = raw;
    let trailing_anchor = if let Some(rest) = path_raw.strip_suffix('|') {
        path_raw = rest;
        true
    } else {
        false
    };

    // Normalize patterns like `.com/watch?` paired with `domain=youtube.com|youtubekids.com`
    if path_raw.starts_with('.')
        && let Some(slash_idx) = path_raw.find('/')
    {
        let leading_tld = &path_raw[..slash_idx];
        if domains.iter().all(|d| d.ends_with(leading_tld)) {
            path_raw = &path_raw[slash_idx..];
        }
    }

    let trimmed_path = path_raw.trim_start_matches('*');
    if trimmed_path.len() < 3 {
        return None;
    }

    let host_atoms: Vec<String> = domains
        .iter()
        .map(|d| format!("(?:[^/?#]+\\.)?{}", escape_literal_regex(d)))
        .collect();
    let host_group = format!("(?:{})", host_atoms.join("|"));

    let tail_expr = if let Some(after_slash) = trimmed_path.strip_prefix('/') {
        format!("/(?:[^?#]*/)?{}", abp_path_wildcard_to_regex(after_slash))
    } else {
        format!("/[^?#]*{}", abp_path_wildcard_to_regex(trimmed_path))
    };
    let suffix_anchor = if trailing_anchor { "$" } else { "" };
    let full = format!(
        "^https?://{}(?::\\d+)?{}{}",
        host_group, tail_expr, suffix_anchor
    );
    let verified = normalize_surge_regex(&full)?;
    Some((verified, domains.to_vec()))
}

fn abp_path_wildcard_to_regex(tail: &str) -> String {
    let mut out = String::with_capacity(tail.len() * 2);
    for ch in tail.chars() {
        match ch {
            '*' => out.push_str("[^?#]*"),
            '^' => out.push_str("(?:[^\\w.%-]|$)"),
            '.' | '+' | '?' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

pub fn escape_literal_regex(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        if matches!(
            ch,
            '.' | '+' | '*' | '?' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\'
        ) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

fn abp_wildcard_to_regex(tail: &str) -> String {
    let mut out = String::with_capacity(tail.len() * 2);
    for ch in tail.chars() {
        match ch {
            '*' => out.push_str(".*"),
            '^' => out.push_str("(?:[^\\w.%-]|$)"),
            '.' | '+' | '?' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_ascii_and_broken_commas_and_quotes() {
        assert_eq!(
            normalize_surge_regex("^https://j1\\.pupuapi\\.com/client/a朴朴"),
            None
        );
        assert_eq!(normalize_surge_regex("^https://example\\.com/ad,,"), None);
        assert_eq!(normalize_surge_regex("^https://example\\.com/ad,"), None);
        assert_eq!(normalize_surge_regex("^https://example\\.com/\"ad\""), None);
    }

    #[test]
    fn rejects_hostname_free_catch_all_authorities() {
        assert_eq!(
            normalize_surge_regex(
                "^https?://[a-zA-Z0-9_-]+(\\.[a-zA-Z0-9_-]+){1,4}:/amdc/mobileDispatch"
            ),
            None
        );
        assert_eq!(normalize_surge_regex("^https?://[^/]+/wp-json/"), None);
        assert_eq!(
            normalize_surge_regex("^https?://([a-z0-9-]+\\.)+[a-z]{2,}/api/v\\d/movie"),
            None
        );
        assert_eq!(
            normalize_surge_regex("^https?://[a-z0-9.-]+/api/v\\d/movie/index_recommend"),
            None
        );
    }

    #[test]
    fn keeps_concrete_domain_and_quantified_path_regexes() {
        assert_eq!(
            normalize_surge_regex("^https?://s\\d+\\.example\\.com/ad/v{1,4}$"),
            Some("^https?://s\\d+\\.example\\.com/ad/v{1,4}$".to_string())
        );
        assert_eq!(
            normalize_surge_regex("^https?://(?:app|api)\\.example\\.com/v1"),
            Some("^https?://(?:app|api)\\.example\\.com/v1".to_string())
        );
        assert_eq!(
            normalize_surge_regex("^http://127\\.0\\.0\\.1/ad"),
            Some("^http://127\\.0\\.0\\.1/ad".to_string())
        );
    }
}
