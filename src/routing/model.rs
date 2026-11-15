use std::collections::BTreeMap;

use ipnet::IpNet;

use crate::adblock::parsers::ruleset::parse_canonical_cidr;
use crate::adblock::regex_util::{
    is_valid_domain, is_valid_domain_wildcard, normalize_surge_regex,
};
use crate::routing::config::{RoutingRuleKind, RoutingTarget};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RoutingRuleKey {
    pub kind: RoutingRuleKind,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutingRule {
    pub key: RoutingRuleKey,
    pub extended_matching: bool,
}

#[derive(Clone, Debug)]
pub struct ParsedRoutingSource {
    pub source_id: String,
    pub target: RoutingTarget,
    pub lineage: String,
    pub weight: u16,
    pub rules: Vec<RoutingRule>,
}

impl ParsedRoutingSource {
    pub fn new(source_id: &str, target: RoutingTarget, lineage: &str, weight: u16) -> Self {
        Self {
            source_id: source_id.to_string(),
            target,
            lineage: lineage.to_string(),
            weight,
            rules: Vec::new(),
        }
    }

    pub fn push_normalized(&mut self, kind: RoutingRuleKind, raw_value: &str, extended: bool) {
        if let Some(value) = normalize_rule_value(kind, raw_value) {
            let extended_matching = extended && kind.supports_extended_matching();
            self.rules.push(RoutingRule {
                key: RoutingRuleKey { kind, value },
                extended_matching,
            });
        }
    }
}

/// Checks whether `raw` is a valid single-label public TLD such as `cn`, `ai`, or `xn--fiqs8s`.
pub fn is_valid_single_label_tld(raw: &str) -> bool {
    let s = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.len() < 2 || s.len() > 63 || s.contains('.') {
        return false;
    }
    if matches!(s.as_str(), "localhost" | "local" | "internal" | "arpa") {
        return false;
    }
    if let Some(rest) = s.strip_prefix("xn--") {
        return !rest.is_empty()
            && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !rest.starts_with('-')
            && !rest.ends_with('-');
    }
    s.len() <= 24 && s.bytes().all(|b| b.is_ascii_lowercase())
}

/// Validates a domain name (`>= 2` labels) or single-label TLD (permitted for `DOMAIN-SUFFIX`).
pub fn is_valid_domain_or_tld(raw: &str) -> bool {
    let clean = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    is_valid_domain(&clean) || is_valid_single_label_tld(&clean)
}

/// Normalizes a rule value according to Surge external RULE-SET syntax and rejects invalid inputs.
pub fn normalize_rule_value(kind: RoutingRuleKind, raw_value: &str) -> Option<String> {
    let trimmed = raw_value.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return None;
    }
    match kind {
        RoutingRuleKind::Domain => {
            let dom = trimmed
                .trim_start_matches('.')
                .trim_end_matches('.')
                .to_ascii_lowercase();
            is_valid_domain(&dom).then_some(dom)
        }
        RoutingRuleKind::DomainSuffix => {
            let dom = trimmed
                .trim_start_matches("+.")
                .trim_start_matches('.')
                .trim_end_matches('.')
                .to_ascii_lowercase();
            is_valid_domain_or_tld(&dom).then_some(dom)
        }
        RoutingRuleKind::DomainKeyword => {
            let kw = trimmed.to_ascii_lowercase();
            if kw.len() >= 2 && !kw.contains(',') && !kw.chars().any(char::is_whitespace) {
                Some(kw)
            } else {
                None
            }
        }
        RoutingRuleKind::DomainWildcard => {
            let wc = trimmed.trim_end_matches('.').to_ascii_lowercase();
            is_valid_domain_wildcard(&wc).then_some(wc)
        }
        RoutingRuleKind::IpCidr => match parse_canonical_cidr(trimmed) {
            Some(IpNet::V4(net)) => Some(net.to_string()),
            _ => None,
        },
        RoutingRuleKind::IpCidr6 => match parse_canonical_cidr(trimmed) {
            Some(IpNet::V6(net)) => Some(net.to_string()),
            _ => None,
        },
        RoutingRuleKind::IpAsn => normalize_asn_value(trimmed),
        RoutingRuleKind::UrlRegex => normalize_surge_regex(trimmed),
        RoutingRuleKind::UserAgent | RoutingRuleKind::ProcessName => {
            if !trimmed.contains(',') {
                Some(trimmed.to_string())
            } else {
                None
            }
        }
        RoutingRuleKind::And => normalize_logical_and_value(trimmed),
    }
}

fn split_balanced_top_level(input: &str) -> Option<Vec<&str>> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut paren = 0i32;
    let mut bracket = 0i32;
    let mut brace = 0i32;
    let mut in_quotes = false;
    let mut escaped = false;

    for (idx, ch) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' && paren == 0 && bracket == 0 && brace == 0 {
            in_quotes = !in_quotes;
            continue;
        }
        if in_quotes {
            continue;
        }
        match ch {
            '(' => paren += 1,
            ')' => {
                paren -= 1;
                if paren < 0 {
                    return None;
                }
            }
            '[' => bracket += 1,
            ']' => {
                bracket -= 1;
                if bracket < 0 {
                    return None;
                }
            }
            '{' => brace += 1,
            '}' => {
                brace -= 1;
                if brace < 0 {
                    return None;
                }
            }
            ',' if paren == 0 && bracket == 0 && brace == 0 => {
                let piece = input[start..idx].trim();
                if piece.is_empty() {
                    return None;
                }
                parts.push(piece);
                start = idx + 1;
            }
            _ => {}
        }
    }

    if paren != 0 || bracket != 0 || brace != 0 || in_quotes || escaped {
        return None;
    }
    let tail = input[start..].trim();
    if tail.is_empty() {
        return None;
    }
    parts.push(tail);
    Some(parts)
}

fn is_forbidden_logical_token(tok: &str) -> bool {
    matches!(
        tok.trim().to_ascii_uppercase().as_str(),
        "DIRECT"
            | "PROXY"
            | "REJECT"
            | "REJECT-TINYGIF"
            | "REJECT-DROP"
            | "REJECT-NO-DROP"
            | "FINAL"
            | "PRE-MATCHING"
            | "FORCE-REMOTE-DNS"
    )
}

/// Parses and canonicalizes the clauses of a Surge `AND,((...),(...))` value.
pub fn parse_logical_and_clauses(
    raw: &str,
) -> Option<Vec<(RoutingRuleKind, String, Option<String>)>> {
    let trimmed = raw.trim();
    if trimmed.chars().any(char::is_control) {
        return None;
    }
    let inner = trimmed.strip_prefix('(')?.strip_suffix(')')?.trim();
    let raw_clauses = split_balanced_top_level(inner)?;
    if raw_clauses.len() < 2 {
        return None;
    }

    let mut dedup: BTreeMap<(RoutingRuleKind, String), Option<String>> = BTreeMap::new();
    for raw_clause in raw_clauses {
        let clause_body = raw_clause
            .trim()
            .strip_prefix('(')?
            .strip_suffix(')')?
            .trim();
        let parts = split_balanced_top_level(clause_body)?;
        if parts.len() < 2 || parts.len() > 3 {
            return None;
        }
        let kind = RoutingRuleKind::parse_token(parts[0])?;
        if kind == RoutingRuleKind::And {
            return None;
        }
        if is_forbidden_logical_token(parts[1]) {
            return None;
        }
        let val = normalize_rule_value(kind, parts[1])?;
        let opt = if kind.requires_no_resolve() {
            if let Some(flag) = parts.get(2)
                && !flag.eq_ignore_ascii_case("no-resolve")
            {
                return None;
            }
            Some("no-resolve".to_string())
        } else if let Some(flag) = parts.get(2) {
            if !kind.supports_extended_matching() || !flag.eq_ignore_ascii_case("extended-matching")
            {
                return None;
            }
            Some("extended-matching".to_string())
        } else {
            None
        };

        dedup
            .entry((kind, val))
            .and_modify(|prev| {
                if prev.is_none() {
                    *prev = opt.clone();
                }
            })
            .or_insert(opt);
    }

    if dedup.len() < 2 {
        return None;
    }

    Some(dedup.into_iter().map(|((k, v), opt)| (k, v, opt)).collect())
}

/// Normalizes a Surge `AND` rule value into sorted, deduplicated canonical `((K1,V1),(K2,V2))` form.
pub fn normalize_logical_and_value(raw: &str) -> Option<String> {
    let clauses = parse_logical_and_clauses(raw)?;
    let rendered: Vec<String> = clauses
        .into_iter()
        .map(|(k, v, opt)| match opt {
            Some(flag) => format!("({},{},{})", k.as_str(), v, flag),
            None => format!("({},{})", k.as_str(), v),
        })
        .collect();
    Some(format!("({})", rendered.join(",")))
}

pub fn normalize_asn_value(raw: &str) -> Option<String> {
    let token = raw.split_whitespace().next()?.trim();
    let stripped = token
        .strip_prefix("AS")
        .or_else(|| token.strip_prefix("as"))
        .or_else(|| token.strip_prefix("As"))
        .unwrap_or(token);
    let asn: u32 = stripped.parse().ok()?;
    (asn > 0).then(|| asn.to_string())
}

pub fn format_routing_rule_line(rule: &RoutingRule) -> String {
    let kind = rule.key.kind;
    if kind.requires_no_resolve() {
        format!("{},{},no-resolve", kind.as_str(), rule.key.value)
    } else if rule.extended_matching && kind.supports_extended_matching() {
        format!("{},{},extended-matching", kind.as_str(), rule.key.value)
    } else {
        format!("{},{}", kind.as_str(), rule.key.value)
    }
}
