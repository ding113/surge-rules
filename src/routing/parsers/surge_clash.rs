use ipnet::IpNet;

use crate::adblock::parsers::ruleset::{
    is_comment_or_empty, parse_canonical_cidr, strip_inline_comment,
};
use crate::adblock::parsers::surge_module::split_top_level_commas;
use crate::routing::config::RoutingRuleKind;
use crate::routing::model::ParsedRoutingSource;

pub fn parse_surge_ruleset(text: &str, out: &mut ParsedRoutingSource) {
    for raw_line in text.lines() {
        let line = strip_inline_comment(raw_line.trim_start_matches('\u{feff}')).trim();
        if is_comment_or_empty(line) || line.starts_with('[') {
            continue;
        }
        parse_classical_rule_line(line, out);
    }
}

pub fn parse_domain_set(text: &str, out: &mut ParsedRoutingSource) {
    for raw_line in text.lines() {
        let line = strip_inline_comment(raw_line.trim_start_matches('\u{feff}')).trim();
        if is_comment_or_empty(line) {
            continue;
        }
        let cleaned = strip_matching_quotes(line).trim();
        if cleaned.is_empty() {
            continue;
        }
        if let Some(rest) = cleaned.strip_prefix("||") {
            let inner = rest.strip_suffix('^').unwrap_or(rest);
            if !inner.contains(['/', '$', '*', '?']) {
                out.push_normalized(RoutingRuleKind::DomainSuffix, inner, false);
            }
        } else if let Some(rest) = cleaned.strip_prefix("+.") {
            out.push_normalized(RoutingRuleKind::DomainSuffix, rest, false);
        } else if let Some(rest) = cleaned.strip_prefix('.') {
            out.push_normalized(RoutingRuleKind::DomainSuffix, rest, false);
        } else if cleaned.contains('*') || cleaned.contains('?') {
            out.push_normalized(RoutingRuleKind::DomainWildcard, cleaned, false);
        } else {
            out.push_normalized(RoutingRuleKind::Domain, cleaned, false);
        }
    }
}

pub fn parse_abp_routing(text: &str, out: &mut ParsedRoutingSource) {
    let mut badfiltered: rustc_hash::FxHashSet<String> = rustc_hash::FxHashSet::default();
    let mut lines_buf: Vec<&str> = Vec::new();

    for raw_line in text.lines() {
        let line = raw_line.trim_start_matches('\u{feff}').trim();
        if line.is_empty()
            || line.starts_with('!')
            || line.starts_with('#')
            || line.starts_with('[')
            || line.starts_with("@@")
            || crate::adblock::parsers::abp::contains_cosmetic_or_scriptlet_syntax(line)
        {
            continue;
        }
        if let Some(stripped) = line.strip_suffix("$badfilter") {
            badfiltered.insert(stripped.to_ascii_lowercase());
            continue;
        }
        if let Some(stripped) = line.strip_suffix(",badfilter") {
            badfiltered.insert(stripped.to_ascii_lowercase());
            continue;
        }
        lines_buf.push(line);
    }

    for line in lines_buf {
        if badfiltered.contains(&line.to_ascii_lowercase()) {
            continue;
        }
        let pat = match line.split_once('$') {
            Some((p, mods)) => {
                // Skip context-scoped ABP rules (`domain=`, `image`, `script`, etc.)
                let m_lower = mods.to_ascii_lowercase();
                if !matches!(
                    m_lower.as_str(),
                    "" | "important" | "all" | "doc" | "document"
                ) {
                    continue;
                }
                p
            }
            None => line,
        };
        let Some(after) = pat.strip_prefix("||") else {
            continue;
        };
        let inner = after.strip_suffix('^').unwrap_or(after);
        if inner.contains(['/', '?', ':', '|', '$']) {
            continue;
        }
        if inner.contains('*') && !inner.starts_with("*.") {
            out.push_normalized(RoutingRuleKind::DomainWildcard, inner, false);
        } else {
            let clean = inner.strip_prefix("*.").unwrap_or(inner);
            out.push_normalized(RoutingRuleKind::DomainSuffix, clean, false);
        }
    }
}

pub fn parse_hosts_routing(text: &str, out: &mut ParsedRoutingSource) {
    for raw_line in text.lines() {
        let line = strip_inline_comment(raw_line.trim_start_matches('\u{feff}')).trim();
        if is_comment_or_empty(line) {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(first) = parts.next() else {
            continue;
        };
        if matches!(
            first,
            "0.0.0.0" | "127.0.0.1" | "::1" | "::" | "0:0:0:0:0:0:0:0"
        ) {
            for host in parts {
                let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
                if matches!(
                    h.as_str(),
                    "" | "0.0.0.0"
                        | "127.0.0.1"
                        | "localhost"
                        | "localhost.localdomain"
                        | "local"
                        | "broadcasthost"
                        | "ip6-localhost"
                        | "ip6-loopback"
                        | "ip6-localnet"
                        | "ip6-mcastprefix"
                        | "ip6-allnodes"
                        | "ip6-allrouters"
                        | "ip6-allhosts"
                ) {
                    continue;
                }
                out.push_normalized(RoutingRuleKind::Domain, &h, false);
            }
        } else if !first.contains(':') && first.contains('.') {
            out.push_normalized(RoutingRuleKind::Domain, first, false);
        }
    }
}

pub fn parse_clash_classical(text: &str, out: &mut ParsedRoutingSource) {
    for raw_line in text.lines() {
        let stripped = strip_yaml_comment_and_dash(raw_line);
        let Some(item) = stripped else {
            continue;
        };
        if item.eq_ignore_ascii_case("payload:") || item.starts_with("behavior:") {
            continue;
        }
        parse_classical_rule_line(&item, out);
    }
}

pub fn parse_clash_yaml(text: &str, out: &mut ParsedRoutingSource) {
    let mut in_payload = false;
    let mut saw_payload_key = false;

    for raw_line in text.lines() {
        let trimmed_bom = raw_line.trim_start_matches('\u{feff}');
        let trimmed = trimmed_bom.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed == "payload:" || trimmed.starts_with("payload:") {
            saw_payload_key = true;
            in_payload = true;
            continue;
        }
        if saw_payload_key && !trimmed_bom.starts_with('-') && !trimmed_bom.starts_with(' ') {
            in_payload = false;
        }
        if saw_payload_key && !in_payload {
            continue;
        }
        let Some(item) = strip_yaml_comment_and_dash(trimmed_bom) else {
            continue;
        };
        if item.starts_with("payload:") || item.starts_with("behavior:") {
            continue;
        }

        // Handle Clash classical rules embedded inside `payload:` if present.
        if let Some((head, _)) = item.split_once(',')
            && RoutingRuleKind::parse_token(head).is_some()
        {
            parse_classical_rule_line(&item, out);
            continue;
        }

        if let Some(net) = parse_canonical_cidr(&item) {
            match net {
                IpNet::V4(v4) => {
                    out.push_normalized(RoutingRuleKind::IpCidr, &v4.to_string(), false)
                }
                IpNet::V6(v6) => {
                    out.push_normalized(RoutingRuleKind::IpCidr6, &v6.to_string(), false)
                }
            }
            continue;
        }

        if let Some(rest) = item.strip_prefix("+.") {
            out.push_normalized(RoutingRuleKind::DomainSuffix, rest, false);
        } else if let Some(rest) = item.strip_prefix('.') {
            out.push_normalized(RoutingRuleKind::DomainSuffix, rest, false);
        } else if item.contains('*') || item.contains('?') {
            out.push_normalized(RoutingRuleKind::DomainWildcard, &item, false);
        } else {
            out.push_normalized(RoutingRuleKind::Domain, &item, false);
        }
    }
}

pub fn parse_ip_cidr_list(text: &str, out: &mut ParsedRoutingSource) {
    for raw_line in text.lines() {
        let line = strip_inline_comment(raw_line.trim_start_matches('\u{feff}')).trim();
        if is_comment_or_empty(line) {
            continue;
        }
        if line.contains(',') {
            parse_classical_rule_line(line, out);
            continue;
        }
        let token = line.split_whitespace().next().unwrap_or("");
        match parse_canonical_cidr(token) {
            Some(IpNet::V4(net)) => {
                out.push_normalized(RoutingRuleKind::IpCidr, &net.to_string(), false);
            }
            Some(IpNet::V6(net)) => {
                out.push_normalized(RoutingRuleKind::IpCidr6, &net.to_string(), false);
            }
            None => {}
        }
    }
}

pub fn parse_asn_list(text: &str, out: &mut ParsedRoutingSource) {
    for raw_line in text.lines() {
        let line = strip_inline_comment(raw_line.trim_start_matches('\u{feff}')).trim();
        if is_comment_or_empty(line) {
            continue;
        }
        if line.contains(',') {
            parse_classical_rule_line(line, out);
            continue;
        }
        out.push_normalized(RoutingRuleKind::IpAsn, line, false);
    }
}

fn parse_classical_rule_line(line: &str, out: &mut ParsedRoutingSource) {
    let parts = split_top_level_commas(line);
    if parts.len() < 2 {
        return;
    }
    let Some(kind) = RoutingRuleKind::parse_token(&parts[0]) else {
        return;
    };
    let raw_val = strip_matching_quotes(parts[1].trim());
    let mut extended = false;
    for opt in parts.iter().skip(2) {
        if opt.trim().eq_ignore_ascii_case("extended-matching") {
            extended = true;
        }
    }
    out.push_normalized(kind, raw_val, extended);
}

fn strip_yaml_comment_and_dash(raw: &str) -> Option<String> {
    let s = strip_inline_hash_preserving_quotes(raw.trim_start_matches('\u{feff}')).trim();
    if s.is_empty() {
        return None;
    }
    let after_dash = if let Some(rest) = s.strip_prefix("- ") {
        rest.trim()
    } else if s == "-" {
        return None;
    } else if let Some(rest) = s.strip_prefix('-')
        && (rest.starts_with('\'') || rest.starts_with('"'))
    {
        rest.trim()
    } else {
        s
    };
    let unquoted = strip_matching_quotes(after_dash).trim();
    if unquoted.is_empty() {
        None
    } else {
        Some(unquoted.to_string())
    }
}

fn strip_inline_hash_preserving_quotes(s: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let bytes = s.as_bytes();
    for i in 0..bytes.len() {
        match bytes[i] {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'#' if !in_single && !in_double && (i == 0 || bytes[i - 1].is_ascii_whitespace()) => {
                return s[..i].trim_end();
            }
            _ => {}
        }
    }
    s
}

fn strip_matching_quotes(s: &str) -> &str {
    let trimmed = s.trim();
    if trimmed.len() >= 2
        && ((trimmed.starts_with('\'') && trimmed.ends_with('\''))
            || (trimmed.starts_with('"') && trimmed.ends_with('"')))
    {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    }
}
