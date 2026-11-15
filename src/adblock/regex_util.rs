use std::net::IpAddr;

use regex::Regex;

/// Normalizes a Surge URL regex pattern and rejects malformed or catch-all patterns.
pub fn normalize_surge_regex(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }

    // Repair common upstream typos (`^http?:` -> `^https?:`) and unescape `\/` -> `/`
    let mut normalized = trimmed.replace("\\/", "/");
    if let Some(rest) = normalized.strip_prefix("^http?://") {
        normalized = format!("^https?://{}", rest);
    }

    if is_catch_all_regex(&normalized) || !has_balanced_delimiters(&normalized) {
        return None;
    }

    // Reject patterns containing Surge comma/quote breaking syntax if unquoted inside scripts later
    if !uses_pcre_lookaround_or_backref(&normalized) && Regex::new(&normalized).is_err() {
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
    bare.len() < 8 && !bare.contains('.')
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
    if !host_part.contains('.') {
        return false;
    }

    let bare = host_part.trim_start_matches("*.").trim_start_matches('.');
    // Require at least two domain labels after wildcard strip (never allow `*.com` or `*.net`)
    let non_wild_labels: Vec<&str> = host_part
        .split('.')
        .filter(|seg| !seg.is_empty() && *seg != "*" && *seg != "?")
        .collect();
    if non_wild_labels.len() < 2 && bare.split('.').count() < 2 {
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
