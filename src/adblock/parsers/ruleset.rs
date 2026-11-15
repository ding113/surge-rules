use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::adblock::config::{AdblockSourceConfig, AdblockSourceRole};
use crate::adblock::model::ParsedAdblockSource;
use crate::adblock::regex_util::{is_valid_domain, is_valid_domain_wildcard};

/// Splits a Surge rule/list line by removing trailing `#`, `//`, or `;` inline comments
/// when preceded by whitespace, matching Surge's profile comment rules.
pub fn strip_inline_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    for i in 0..bytes.len() {
        if i > 0 && bytes[i - 1].is_ascii_whitespace() {
            if bytes[i] == b'#' || bytes[i] == b';' {
                return line[..i].trim();
            }
            if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                return line[..i].trim();
            }
        }
    }
    line.trim()
}

/// Checks whether a line is a pure comment or empty line in Surge / ABP lists.
pub fn is_comment_or_empty(line: &str) -> bool {
    let t = line.trim();
    t.is_empty() || t.starts_with('#') || t.starts_with(';') || t.starts_with("//")
}

/// Parses canonical Surge `RULE-SET` or Clash/Surge classical list lines into `ParsedAdblockSource`.
pub fn parse_surge_ruleset(text: &str, src: &AdblockSourceConfig, out: &mut ParsedAdblockSource) {
    let is_allow = src.role == AdblockSourceRole::Allowlist;
    for raw_line in text.lines() {
        let line = strip_inline_comment(raw_line.trim_start_matches('\u{feff}'));
        if is_comment_or_empty(line) {
            continue;
        }
        // Skip Surge section headers if a .conf/.list file includes `[Rule]`
        if line.starts_with('[') && line.ends_with(']') {
            continue;
        }
        let parts: Vec<&str> = line.split(',').map(str::trim).collect();
        if parts.len() < 2 {
            continue;
        }
        let kind = parts[0].to_ascii_uppercase();
        let val = parts[1].trim_matches('"');
        if is_allow {
            match kind.as_str() {
                "DOMAIN" => {
                    let dom = val.trim_end_matches('.').to_ascii_lowercase();
                    if is_valid_domain(&dom) {
                        out.allow_exact_domains.insert(dom);
                    }
                }
                "DOMAIN-SUFFIX" => {
                    let dom = val
                        .trim_start_matches('.')
                        .trim_end_matches('.')
                        .to_ascii_lowercase();
                    if is_valid_domain(&dom) {
                        out.allow_suffix_domains.insert(dom);
                    }
                }
                _ => {}
            }
            continue;
        }

        // Ignore explicit non-reject policy lines if present in classical lists
        if let Some(policy) = parts.get(2) {
            let p_upper = policy.to_ascii_uppercase();
            if matches!(p_upper.as_str(), "DIRECT" | "PROXY") {
                if kind == "DOMAIN" {
                    let dom = val.trim_end_matches('.').to_ascii_lowercase();
                    if is_valid_domain(&dom) {
                        out.allow_exact_domains.insert(dom);
                    }
                }
                continue;
            }
        }

        insert_ruleset_entry(&kind, val, out);
    }
}

pub fn insert_ruleset_entry(kind: &str, value: &str, out: &mut ParsedAdblockSource) {
    match kind {
        "DOMAIN" => {
            let dom = value.trim_end_matches('.').to_ascii_lowercase();
            if is_valid_domain(&dom) {
                out.ruleset_domains.insert(dom);
            }
        }
        "DOMAIN-SUFFIX" => {
            let dom = value
                .trim_start_matches('.')
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if is_valid_domain(&dom) {
                out.ruleset_suffixes.insert(dom);
            }
        }
        "DOMAIN-KEYWORD" => {
            let kw = value.trim().to_ascii_lowercase();
            if kw.len() >= 4
                && !kw.contains(',')
                && !kw.contains('/')
                && !kw.chars().any(char::is_whitespace)
            {
                out.ruleset_keywords.insert(kw);
            }
        }
        "DOMAIN-WILDCARD" => {
            let pat = value.trim().trim_end_matches('.').to_ascii_lowercase();
            if is_valid_domain_wildcard(&pat) {
                out.ruleset_wildcards.insert(pat);
            }
        }
        "IP-CIDR" => {
            if let Some(v4) = parse_canonical_v4(value) {
                out.ruleset_cidrs_v4.insert(v4);
            }
        }
        "IP-CIDR6" => {
            if let Some(v6) = parse_canonical_v6(value) {
                out.ruleset_cidrs_v6.insert(v6);
            }
        }
        "IP-ASN" => {
            if let Ok(asn) = value.trim().parse::<u32>()
                && asn > 0
            {
                out.ruleset_asns.insert(asn);
            }
        }
        "USER-AGENT" => {
            let ua = value.trim();
            if ua.len() >= 3 && !ua.contains(',') && !ua.chars().any(|c| c.is_control()) {
                out.ruleset_user_agents.insert(ua.to_string());
            }
        }
        "PROCESS-NAME" => {
            let proc_name = value.trim();
            if !proc_name.is_empty()
                && !proc_name.contains(',')
                && !proc_name.chars().any(|c| c.is_control())
            {
                out.ruleset_process_names.insert(proc_name.to_string());
            }
        }
        _ => {}
    }
}

pub fn parse_surge_domainset(text: &str, src: &AdblockSourceConfig, out: &mut ParsedAdblockSource) {
    let is_allow = src.role == AdblockSourceRole::Allowlist;
    for raw_line in text.lines() {
        let line = strip_inline_comment(raw_line.trim_start_matches('\u{feff}'));
        if is_comment_or_empty(line) {
            continue;
        }
        if let Some(suffix) = line.strip_prefix('.') {
            let dom = suffix.trim().trim_end_matches('.').to_ascii_lowercase();
            if is_valid_domain(&dom) {
                if is_allow {
                    out.allow_suffix_domains.insert(dom);
                } else {
                    out.ruleset_suffixes.insert(dom);
                }
            }
        } else {
            let dom = line.trim().trim_end_matches('.').to_ascii_lowercase();
            if is_valid_domain(&dom) {
                if is_allow {
                    out.allow_exact_domains.insert(dom);
                } else {
                    out.ruleset_domains.insert(dom);
                }
            }
        }
    }
}

pub fn parse_hosts(text: &str, src: &AdblockSourceConfig, out: &mut ParsedAdblockSource) {
    let is_allow = src.role == AdblockSourceRole::Allowlist;
    for raw_line in text.lines() {
        let line = strip_inline_comment(raw_line.trim_start_matches('\u{feff}'));
        if is_comment_or_empty(line) {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(first) = fields.next() else {
            continue;
        };
        let host = if first.parse::<IpAddr>().is_ok() {
            match fields.next() {
                Some(h) => h,
                None => continue,
            }
        } else {
            first
        };
        let dom = host.trim_end_matches('.').to_ascii_lowercase();
        if is_local_hosts_sentinel(&dom) || !is_valid_domain(&dom) {
            continue;
        }
        if is_allow {
            out.allow_exact_domains.insert(dom);
        } else {
            out.ruleset_domains.insert(dom);
        }
    }
}

pub fn parse_domain_list(text: &str, src: &AdblockSourceConfig, out: &mut ParsedAdblockSource) {
    let is_allow = src.role == AdblockSourceRole::Allowlist;
    // Detect explicit `# Syntax:` header declarations (e.g. HaGeZi `Domains (without subdomains)` vs `Domains (wildcards)`)
    let header_declares_exact_only = text
        .lines()
        .take(30)
        .any(|l| l.to_ascii_lowercase().contains("without subdomains"));
    let default_bare_is_suffix = !header_declares_exact_only
        && (src.id.contains("pro_domains")
            || src.id.contains("wildcards")
            || src.endpoints.iter().any(|e| {
                matches!(
                    e,
                    crate::config::EndpointConfig::Direct { url }
                        if url.contains("/wildcard/")
                            || url.ends_with("-onlydomains.txt")
                            || url.ends_with(".wildcards")
                )
            }));

    for raw_line in text.lines() {
        let line = strip_inline_comment(raw_line.trim_start_matches('\u{feff}'));
        if is_comment_or_empty(line) || (line.starts_with('[') && line.ends_with(']')) {
            continue;
        }
        // Support `full:`, `domain:`, `*.`, `.`, and `||domain^` / `@@||domain^` prefixes cleanly
        let (is_suffix, raw_dom) = if let Some(rest) = line.strip_prefix("@@||") {
            (true, rest.trim_end_matches('^'))
        } else if let Some(rest) = line.strip_prefix("||") {
            if rest.contains('/') || rest.contains('$') || rest.contains('*') {
                continue;
            }
            (true, rest.trim_end_matches('^'))
        } else if let Some(rest) = line.strip_prefix("full:") {
            (false, rest)
        } else if let Some(rest) = line.strip_prefix("domain:") {
            (true, rest)
        } else if let Some(rest) = line.strip_prefix("*.") {
            (true, rest)
        } else if let Some(rest) = line.strip_prefix('.') {
            (true, rest)
        } else {
            (default_bare_is_suffix, line)
        };

        let dom = raw_dom.trim().trim_end_matches('.').to_ascii_lowercase();
        if is_local_hosts_sentinel(&dom) || !is_valid_domain(&dom) {
            continue;
        }
        if is_allow {
            if is_suffix {
                out.allow_suffix_domains.insert(dom);
            } else {
                out.allow_exact_domains.insert(dom);
            }
        } else if is_suffix {
            out.ruleset_suffixes.insert(dom);
        } else {
            out.ruleset_domains.insert(dom);
        }
    }
}

fn parse_canonical_v4(raw: &str) -> Option<Ipv4Net> {
    if let Ok(net) = raw.trim().parse::<Ipv4Net>() {
        return Some(net.trunc());
    }
    if let Ok(IpAddr::V4(ip)) = raw.trim().parse::<IpAddr>() {
        return Ipv4Net::new(ip, 32).ok();
    }
    None
}

fn parse_canonical_v6(raw: &str) -> Option<Ipv6Net> {
    if let Ok(net) = raw.trim().parse::<Ipv6Net>() {
        return Some(net.trunc());
    }
    if let Ok(IpAddr::V6(ip)) = raw.trim().parse::<IpAddr>() {
        return Ipv6Net::new(ip, 128).ok();
    }
    None
}

pub fn parse_canonical_cidr(raw: &str) -> Option<IpNet> {
    if let Some(v4) = parse_canonical_v4(raw) {
        return Some(IpNet::V4(v4));
    }
    parse_canonical_v6(raw).map(IpNet::V6)
}

fn is_local_hosts_sentinel(dom: &str) -> bool {
    matches!(
        dom,
        "localhost"
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
    )
}
