use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result, bail};
use ipnet::{Ipv4Net, Ipv6Net};
use regex::Regex;
use rustc_hash::FxHashSet;

use crate::adblock::compiler::{
    DomainTrie, overlaps_reserved_v4, overlaps_reserved_v6, wildcard_matches_domain,
};
use crate::adblock::parsers::surge_module::split_top_level_commas;
use crate::adblock::regex_util::{is_valid_domain, is_valid_domain_wildcard};
use crate::adblock::verify::{AdblockFileSummary, file_summary};
use crate::routing::config::{RoutingOverrides, RoutingRuleKind, RoutingTarget};
use crate::routing::model::{
    is_valid_domain_or_tld, normalize_asn_value, normalize_logical_and_value,
    parse_logical_and_clauses,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct RoutingThresholds {
    pub min_direct_lines: usize,
    pub min_ai_lines: usize,
    pub min_payment_lines: usize,
    pub min_telemetry_lines: usize,
    pub min_proxy_lines: usize,
}

#[derive(Clone, Debug)]
pub struct RoutingVerificationReport {
    pub direct: AdblockFileSummary,
    pub ai: AdblockFileSummary,
    pub payment: AdblockFileSummary,
    pub telemetry: AdblockFileSummary,
    pub proxy: AdblockFileSummary,
    pub direct_total: usize,
    pub ai_total: usize,
    pub payment_total: usize,
    pub telemetry_total: usize,
    pub proxy_total: usize,
    pub direct_extended_count: usize,
    pub ai_extended_count: usize,
    pub payment_extended_count: usize,
    pub telemetry_extended_count: usize,
    pub proxy_extended_count: usize,
    pub canaries_checked: usize,
}

#[derive(Default)]
struct ParsedListIndex {
    trie: DomainTrie,
    exact_domains: BTreeMap<String, bool>,
    suffix_domains: BTreeMap<String, bool>,
    keywords: BTreeMap<String, bool>,
    wildcards: BTreeMap<String, bool>,
    url_regexes: BTreeMap<String, bool>,
    user_agents: BTreeSet<String>,
    process_names: BTreeSet<String>,
    logical_ands: BTreeSet<String>,
    v4_cidrs: Vec<Ipv4Net>,
    v6_cidrs: Vec<Ipv6Net>,
    asns: BTreeSet<u32>,
    total_rules: usize,
    extended_count: usize,
}

impl ParsedListIndex {
    fn covers_domain(&self, dom: &str) -> bool {
        let lower = dom.trim().trim_end_matches('.').to_ascii_lowercase();
        if self.trie.matches_domain(&lower) {
            return true;
        }
        if self
            .wildcards
            .keys()
            .any(|wc| wildcard_matches_domain(wc, &lower))
        {
            return true;
        }
        self.keywords.keys().any(|kw| lower.contains(kw.as_str()))
    }

    fn covers_domain_exact_or_suffix(&self, dom: &str) -> bool {
        let lower = dom.trim().trim_end_matches('.').to_ascii_lowercase();
        self.trie.matches_domain(&lower)
            || self
                .wildcards
                .keys()
                .any(|wc| wildcard_matches_domain(wc, &lower))
    }

    fn covers_suffix_with_ext(&self, suffix: &str, required_ext: bool) -> bool {
        let lower = suffix.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Some(&ext) = self.suffix_domains.get(&lower)
            && (!required_ext || ext)
        {
            return true;
        }
        let dot_positions: Vec<usize> = lower.match_indices('.').map(|(idx, _)| idx).collect();
        for idx in dot_positions {
            let anc = &lower[idx + 1..];
            if let Some(&ext) = self.suffix_domains.get(anc)
                && (!required_ext || ext)
            {
                return true;
            }
        }
        false
    }

    fn covers_domain_with_ext(&self, dom: &str, required_ext: bool) -> bool {
        let lower = dom.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Some(&ext) = self.exact_domains.get(&lower)
            && (!required_ext || ext)
        {
            return true;
        }
        self.covers_suffix_with_ext(&lower, required_ext)
    }

    fn covers_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.v4_cidrs.iter().any(|net| net.contains(&v4)),
            IpAddr::V6(v6) => self.v6_cidrs.iter().any(|net| net.contains(&v6)),
        }
    }
}

pub fn verify_routing_dir(
    dir: &Path,
    overrides: &RoutingOverrides,
    thresholds: RoutingThresholds,
    check_canaries: bool,
) -> Result<RoutingVerificationReport> {
    let direct_path = dir.join(RoutingTarget::Direct.filename());
    let ai_path = dir.join(RoutingTarget::Ai.filename());
    let payment_path = dir.join(RoutingTarget::Payment.filename());
    let telemetry_path = dir.join(RoutingTarget::Telemetry.filename());
    let proxy_path = dir.join(RoutingTarget::Proxy.filename());

    let direct_raw = fs::read_to_string(&direct_path)
        .with_context(|| format!("missing {}", direct_path.display()))?;
    let ai_raw =
        fs::read_to_string(&ai_path).with_context(|| format!("missing {}", ai_path.display()))?;
    let payment_raw = fs::read_to_string(&payment_path)
        .with_context(|| format!("missing {}", payment_path.display()))?;
    let telemetry_raw = fs::read_to_string(&telemetry_path)
        .with_context(|| format!("missing {}", telemetry_path.display()))?;
    let proxy_raw = fs::read_to_string(&proxy_path)
        .with_context(|| format!("missing {}", proxy_path.display()))?;

    let direct_idx =
        parse_and_validate_ruleset("Direct.list", &direct_raw, thresholds.min_direct_lines)?;
    let ai_idx = parse_and_validate_ruleset("AI.list", &ai_raw, thresholds.min_ai_lines)?;
    let payment_idx =
        parse_and_validate_ruleset("Payment.list", &payment_raw, thresholds.min_payment_lines)?;
    let telemetry_idx = parse_and_validate_ruleset(
        "Telemetry.list",
        &telemetry_raw,
        thresholds.min_telemetry_lines,
    )?;
    let proxy_idx =
        parse_and_validate_ruleset("Proxy.list", &proxy_raw, thresholds.min_proxy_lines)?;

    if direct_idx.extended_count != 0 {
        bail!(
            "Direct.list must have 0 extended-matching rules (found {}); a single line enables extended-matching on the whole RULE-SET in Surge",
            direct_idx.extended_count
        );
    }

    for (label, idx) in [
        ("AI.list", &ai_idx),
        ("Payment.list", &payment_idx),
        ("Telemetry.list", &telemetry_idx),
    ] {
        verify_shared_infra_safety(label, idx, overrides)?;
        verify_subset_of_proxy(label, idx, &proxy_idx)?;
    }

    verify_clean_targets_disjoint(&ai_idx, &payment_idx, &telemetry_idx)?;
    verify_reserved_ip_absence(&[
        ("Direct.list", &direct_idx),
        ("AI.list", &ai_idx),
        ("Payment.list", &payment_idx),
        ("Telemetry.list", &telemetry_idx),
        ("Proxy.list", &proxy_idx),
    ])?;

    let canaries_checked = if check_canaries {
        run_production_canaries(
            &direct_idx,
            &ai_idx,
            &payment_idx,
            &telemetry_idx,
            &proxy_idx,
        )?
    } else {
        0
    };

    Ok(RoutingVerificationReport {
        direct: file_summary("Direct.list", direct_raw.as_bytes(), direct_idx.total_rules),
        ai: file_summary("AI.list", ai_raw.as_bytes(), ai_idx.total_rules),
        payment: file_summary(
            "Payment.list",
            payment_raw.as_bytes(),
            payment_idx.total_rules,
        ),
        telemetry: file_summary(
            "Telemetry.list",
            telemetry_raw.as_bytes(),
            telemetry_idx.total_rules,
        ),
        proxy: file_summary("Proxy.list", proxy_raw.as_bytes(), proxy_idx.total_rules),
        direct_total: direct_idx.total_rules,
        ai_total: ai_idx.total_rules,
        payment_total: payment_idx.total_rules,
        telemetry_total: telemetry_idx.total_rules,
        proxy_total: proxy_idx.total_rules,
        direct_extended_count: direct_idx.extended_count,
        ai_extended_count: ai_idx.extended_count,
        payment_extended_count: payment_idx.extended_count,
        telemetry_extended_count: telemetry_idx.extended_count,
        proxy_extended_count: proxy_idx.extended_count,
        canaries_checked,
    })
}

fn parse_and_validate_ruleset(
    label: &str,
    text: &str,
    min_lines: usize,
) -> Result<ParsedListIndex> {
    let mut idx = ParsedListIndex::default();
    let mut seen_keys: FxHashSet<(RoutingRuleKind, String)> = FxHashSet::default();

    for (line_no, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with("//")
            || line.starts_with(';')
        {
            continue;
        }
        for bad in [
            "##",
            "#@#",
            "#+js(",
            "FINAL",
            "pre-matching",
            "force-remote-dns",
        ] {
            if line.contains(bad) {
                bail!(
                    "{} line {} contains invalid token '{}': {}",
                    label,
                    line_no + 1,
                    bad,
                    line
                );
            }
        }

        let parts = split_top_level_commas(line);
        if parts.len() < 2 || parts.len() > 3 {
            bail!(
                "{} line {} must have 2 or 3 comma-separated fields: {}",
                label,
                line_no + 1,
                line
            );
        }
        let kind = RoutingRuleKind::parse_token(&parts[0]).with_context(|| {
            format!(
                "{} line {} unknown rule kind '{}'",
                label,
                line_no + 1,
                parts[0]
            )
        })?;
        let val = parts[1].trim();
        let opt = parts.get(2).map(|s| s.trim());

        let mut ext = false;
        if kind.requires_no_resolve() {
            if opt != Some("no-resolve") {
                bail!(
                    "{} line {} {} must carry ',no-resolve': {}",
                    label,
                    line_no + 1,
                    kind.as_str(),
                    line
                );
            }
        } else if let Some(flag) = opt {
            if flag == "extended-matching" && kind.supports_extended_matching() {
                ext = true;
            } else {
                bail!(
                    "{} line {} unsupported trailing option '{}' (policy names are illegal in external RULE-SET): {}",
                    label,
                    line_no + 1,
                    flag,
                    line
                );
            }
        }

        if !seen_keys.insert((kind, val.to_string())) {
            bail!("{} line {} duplicate rule: {}", label, line_no + 1, line);
        }

        if ext {
            idx.extended_count += 1;
        }

        match kind {
            RoutingRuleKind::Domain => {
                if !is_valid_domain(val) {
                    bail!("{} line {} invalid DOMAIN '{}'", label, line_no + 1, val);
                }
                idx.trie.insert_exact(val);
                idx.exact_domains.insert(val.to_string(), ext);
            }
            RoutingRuleKind::DomainSuffix => {
                if !is_valid_domain_or_tld(val) {
                    bail!(
                        "{} line {} invalid DOMAIN-SUFFIX '{}'",
                        label,
                        line_no + 1,
                        val
                    );
                }
                idx.trie.insert_suffix(val);
                idx.suffix_domains.insert(val.to_string(), ext);
            }
            RoutingRuleKind::DomainKeyword => {
                if val.len() < 2 || val.chars().any(char::is_whitespace) {
                    bail!(
                        "{} line {} invalid DOMAIN-KEYWORD '{}'",
                        label,
                        line_no + 1,
                        val
                    );
                }
                idx.keywords.insert(val.to_string(), ext);
            }
            RoutingRuleKind::DomainWildcard => {
                if !is_valid_domain_wildcard(val) {
                    bail!(
                        "{} line {} invalid DOMAIN-WILDCARD '{}'",
                        label,
                        line_no + 1,
                        val
                    );
                }
                idx.wildcards.insert(val.to_string(), ext);
            }
            RoutingRuleKind::UrlRegex => {
                if Regex::new(val).is_err() {
                    bail!("{} line {} invalid URL-REGEX '{}'", label, line_no + 1, val);
                }
                idx.url_regexes.insert(val.to_string(), ext);
            }
            RoutingRuleKind::UserAgent => {
                if val.is_empty() {
                    bail!("{} line {} empty USER-AGENT", label, line_no + 1);
                }
                idx.user_agents.insert(val.to_string());
            }
            RoutingRuleKind::ProcessName => {
                if val.is_empty() {
                    bail!("{} line {} empty PROCESS-NAME", label, line_no + 1);
                }
                idx.process_names.insert(val.to_string());
            }
            RoutingRuleKind::IpCidr => {
                let net: Ipv4Net = val.parse().with_context(|| {
                    format!("{} line {} invalid IP-CIDR '{}'", label, line_no + 1, val)
                })?;
                if net.trunc() != net {
                    bail!(
                        "{} line {} non-canonical IP-CIDR '{}'",
                        label,
                        line_no + 1,
                        val
                    );
                }
                if overlaps_reserved_v4(net) {
                    bail!(
                        "{} line {} IP-CIDR {} overlaps reserved/LAN/Fake-IP/mesh range",
                        label,
                        line_no + 1,
                        net
                    );
                }
                idx.v4_cidrs.push(net);
            }
            RoutingRuleKind::IpCidr6 => {
                let net: Ipv6Net = val.parse().with_context(|| {
                    format!("{} line {} invalid IP-CIDR6 '{}'", label, line_no + 1, val)
                })?;
                if net.trunc() != net {
                    bail!(
                        "{} line {} non-canonical IP-CIDR6 '{}'",
                        label,
                        line_no + 1,
                        val
                    );
                }
                if overlaps_reserved_v6(net) {
                    bail!(
                        "{} line {} IP-CIDR6 {} overlaps reserved/ULA/mesh range",
                        label,
                        line_no + 1,
                        net
                    );
                }
                idx.v6_cidrs.push(net);
            }
            RoutingRuleKind::IpAsn => {
                let normalized = normalize_asn_value(val).with_context(|| {
                    format!("{} line {} invalid IP-ASN '{}'", label, line_no + 1, val)
                })?;
                let asn: u32 = normalized.parse()?;
                idx.asns.insert(asn);
            }
            RoutingRuleKind::And => {
                let Some(canon) = normalize_logical_and_value(val) else {
                    bail!("{} line {} invalid AND rule '{}'", label, line_no + 1, val);
                };
                if canon != val {
                    bail!(
                        "{} line {} non-canonical AND rule '{}' (expected '{}')",
                        label,
                        line_no + 1,
                        val,
                        canon
                    );
                }
                let clauses = parse_logical_and_clauses(&canon).unwrap_or_default();
                for (sub_kind, sub_val, _) in clauses {
                    match sub_kind {
                        RoutingRuleKind::IpCidr => {
                            let net: Ipv4Net = sub_val.parse()?;
                            if overlaps_reserved_v4(net) {
                                bail!(
                                    "{} line {} AND sub-clause {} overlaps reserved IPv4 range",
                                    label,
                                    line_no + 1,
                                    net
                                );
                            }
                        }
                        RoutingRuleKind::IpCidr6 => {
                            let net: Ipv6Net = sub_val.parse()?;
                            if overlaps_reserved_v6(net) {
                                bail!(
                                    "{} line {} AND sub-clause {} overlaps reserved IPv6 range",
                                    label,
                                    line_no + 1,
                                    net
                                );
                            }
                        }
                        _ => {}
                    }
                }
                idx.logical_ands.insert(canon);
            }
        }

        idx.total_rules += 1;
    }

    if idx.total_rules < min_lines {
        bail!(
            "{} only has {} rules (minimum required: {})",
            label,
            idx.total_rules,
            min_lines
        );
    }

    Ok(idx)
}

fn verify_shared_infra_safety(
    label: &str,
    idx: &ParsedListIndex,
    overrides: &RoutingOverrides,
) -> Result<()> {
    for entry in &overrides.shared_infra_roots {
        let root = entry
            .domain
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if idx.exact_domains.contains_key(&root) || idx.suffix_domains.contains_key(&root) {
            bail!(
                "{} unlawfully captures shared infrastructure apex '{}'",
                label,
                root
            );
        }
    }
    for non_clean_host in [
        "s3.amazonaws.com",
        "console.aws.amazon.com",
        "gist.github.com",
        "cloud.google.com",
        "portal.azure.com",
        "www.cloudflare.com",
        "cdn.jsdelivr.net",
        "www.apple.com",
        "auth0.com",
        "sentry.io",
    ] {
        if idx.covers_domain(non_clean_host) {
            bail!(
                "{} false-positive captures shared multi-tenant host '{}'",
                label,
                non_clean_host
            );
        }
    }
    let shared_roots: FxHashSet<String> = overrides
        .shared_infra_roots
        .iter()
        .map(|e| e.domain.trim().trim_end_matches('.').to_ascii_lowercase())
        .collect();
    for and_val in &idx.logical_ands {
        let Some(clauses) = parse_logical_and_clauses(and_val) else {
            bail!("{} contains unparseable AND rule '{}'", label, and_val);
        };
        let has_context_guard = clauses.iter().any(|(k, _, _)| {
            matches!(k, RoutingRuleKind::ProcessName | RoutingRuleKind::UserAgent)
        });
        let touches_shared = clauses.iter().any(|(k, v, _)| {
            matches!(
                k,
                RoutingRuleKind::Domain
                    | RoutingRuleKind::DomainSuffix
                    | RoutingRuleKind::DomainKeyword
                    | RoutingRuleKind::DomainWildcard
            ) && (shared_roots.contains(v)
                || shared_roots
                    .iter()
                    .any(|root| v == root || v.ends_with(&format!(".{}", root))))
        });
        if touches_shared && !has_context_guard {
            bail!(
                "{} AND rule '{}' references shared infrastructure without PROCESS-NAME/USER-AGENT",
                label,
                and_val
            );
        }
    }
    Ok(())
}

/// Verifies that `AI.list`, `Payment.list`, and `Telemetry.list` are pairwise mutually disjoint
/// across exact rule keys, `DomainTrie` suffix hierarchies, `*.tail` wildcards, and IPv4/IPv6 CIDRs.
fn verify_clean_targets_disjoint(
    ai_idx: &ParsedListIndex,
    payment_idx: &ParsedListIndex,
    telemetry_idx: &ParsedListIndex,
) -> Result<()> {
    let targets = [
        ("AI.list", ai_idx),
        ("Payment.list", payment_idx),
        ("Telemetry.list", telemetry_idx),
    ];
    for (i, (label_a, a)) in targets.iter().enumerate() {
        for (j, (label_b, b)) in targets.iter().enumerate() {
            if i == j {
                continue;
            }
            for dom in a.exact_domains.keys() {
                if b.exact_domains.contains_key(dom) || b.trie.matches_domain(dom) {
                    bail!(
                        "disjointness violation between {} and {}: DOMAIN '{}' overlaps",
                        label_a,
                        label_b,
                        dom
                    );
                }
            }
            for sfx in a.suffix_domains.keys() {
                if b.suffix_domains.contains_key(sfx) || b.trie.matches_domain(sfx) {
                    bail!(
                        "disjointness violation between {} and {}: DOMAIN-SUFFIX '{}' overlaps",
                        label_a,
                        label_b,
                        sfx
                    );
                }
            }
            for kw in a.keywords.keys() {
                if b.keywords.contains_key(kw) {
                    bail!(
                        "disjointness violation between {} and {}: shared DOMAIN-KEYWORD '{}'",
                        label_a,
                        label_b,
                        kw
                    );
                }
            }
            for wc in a.wildcards.keys() {
                if b.wildcards.contains_key(wc) {
                    bail!(
                        "disjointness violation between {} and {}: shared DOMAIN-WILDCARD '{}'",
                        label_a,
                        label_b,
                        wc
                    );
                }
                if let Some(tail) = wc.strip_prefix("*.")
                    && !tail.contains('*')
                    && !tail.contains('?')
                    && b.trie.has_suffix_ancestor_or_eq(tail)
                {
                    bail!(
                        "disjointness violation between {} and {}: DOMAIN-WILDCARD '{}' covered by suffix in {}",
                        label_a,
                        label_b,
                        wc,
                        label_b
                    );
                }
            }
            for re in a.url_regexes.keys() {
                if b.url_regexes.contains_key(re) {
                    bail!(
                        "disjointness violation between {} and {}: shared URL-REGEX '{}'",
                        label_a,
                        label_b,
                        re
                    );
                }
            }
            for ua in &a.user_agents {
                if b.user_agents.contains(ua) {
                    bail!(
                        "disjointness violation between {} and {}: shared USER-AGENT '{}'",
                        label_a,
                        label_b,
                        ua
                    );
                }
            }
            for proc_name in &a.process_names {
                if b.process_names.contains(proc_name) {
                    bail!(
                        "disjointness violation between {} and {}: shared PROCESS-NAME '{}'",
                        label_a,
                        label_b,
                        proc_name
                    );
                }
            }
            for and_val in &a.logical_ands {
                if b.logical_ands.contains(and_val) {
                    bail!(
                        "disjointness violation between {} and {}: shared AND '{}'",
                        label_a,
                        label_b,
                        and_val
                    );
                }
            }
            for asn in &a.asns {
                if b.asns.contains(asn) {
                    bail!(
                        "disjointness violation between {} and {}: shared IP-ASN,{}",
                        label_a,
                        label_b,
                        asn
                    );
                }
            }
            if i < j {
                for net_a in &a.v4_cidrs {
                    for net_b in &b.v4_cidrs {
                        if net_a.contains(&net_b.network()) || net_b.contains(&net_a.network()) {
                            bail!(
                                "disjointness violation between {} and {}: IP-CIDR {} overlaps {}",
                                label_a,
                                label_b,
                                net_a,
                                net_b
                            );
                        }
                    }
                }
                for net_a in &a.v6_cidrs {
                    for net_b in &b.v6_cidrs {
                        if net_a.contains(&net_b.network()) || net_b.contains(&net_a.network()) {
                            bail!(
                                "disjointness violation between {} and {}: IP-CIDR6 {} overlaps {}",
                                label_a,
                                label_b,
                                net_a,
                                net_b
                            );
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn verify_subset_of_proxy(
    label: &str,
    sub_idx: &ParsedListIndex,
    proxy_idx: &ParsedListIndex,
) -> Result<()> {
    for (dom, &ext) in &sub_idx.exact_domains {
        if !proxy_idx.covers_domain_with_ext(dom, ext) {
            bail!(
                "Proxy.list is not a strict superset of {}: missing or weaker DOMAIN '{}' (extended={})",
                label,
                dom,
                ext
            );
        }
    }
    for (sfx, &ext) in &sub_idx.suffix_domains {
        if !proxy_idx.covers_suffix_with_ext(sfx, ext) {
            bail!(
                "Proxy.list is not a strict superset of {}: missing or weaker DOMAIN-SUFFIX '{}' (extended={})",
                label,
                sfx,
                ext
            );
        }
    }
    for (kw, &ext) in &sub_idx.keywords {
        match proxy_idx.keywords.get(kw) {
            Some(&p_ext) if !ext || p_ext => {}
            _ => bail!(
                "Proxy.list is not a strict superset of {}: missing DOMAIN-KEYWORD '{}'",
                label,
                kw
            ),
        }
    }
    for (wc, &ext) in &sub_idx.wildcards {
        let exact_ok = proxy_idx
            .wildcards
            .get(wc)
            .is_some_and(|&p_ext| !ext || p_ext);
        let suffix_ok = wc
            .strip_prefix("*.")
            .filter(|tail| !tail.contains('*') && !tail.contains('?'))
            .is_some_and(|tail| proxy_idx.covers_suffix_with_ext(tail, ext));
        if !exact_ok && !suffix_ok {
            bail!(
                "Proxy.list is not a strict superset of {}: missing DOMAIN-WILDCARD '{}'",
                label,
                wc
            );
        }
    }
    for (re, &ext) in &sub_idx.url_regexes {
        match proxy_idx.url_regexes.get(re) {
            Some(&p_ext) if !ext || p_ext => {}
            _ => bail!(
                "Proxy.list is not a strict superset of {}: missing URL-REGEX '{}'",
                label,
                re
            ),
        }
    }
    for ua in &sub_idx.user_agents {
        if !proxy_idx.user_agents.contains(ua) {
            bail!(
                "Proxy.list is not a strict superset of {}: missing USER-AGENT '{}'",
                label,
                ua
            );
        }
    }
    for proc_name in &sub_idx.process_names {
        if !proxy_idx.process_names.contains(proc_name) {
            bail!(
                "Proxy.list is not a strict superset of {}: missing PROCESS-NAME '{}'",
                label,
                proc_name
            );
        }
    }
    for and_val in &sub_idx.logical_ands {
        if !proxy_idx.logical_ands.contains(and_val) {
            bail!(
                "Proxy.list is not a strict superset of {}: missing AND '{}'",
                label,
                and_val
            );
        }
    }
    for sub_v4 in &sub_idx.v4_cidrs {
        if !proxy_idx
            .v4_cidrs
            .iter()
            .any(|p| p.prefix_len() <= sub_v4.prefix_len() && p.contains(&sub_v4.network()))
        {
            bail!(
                "Proxy.list is not a strict superset of {}: missing IP-CIDR {}",
                label,
                sub_v4
            );
        }
    }
    for sub_v6 in &sub_idx.v6_cidrs {
        if !proxy_idx
            .v6_cidrs
            .iter()
            .any(|p| p.prefix_len() <= sub_v6.prefix_len() && p.contains(&sub_v6.network()))
        {
            bail!(
                "Proxy.list is not a strict superset of {}: missing IP-CIDR6 {}",
                label,
                sub_v6
            );
        }
    }
    for asn in &sub_idx.asns {
        if !proxy_idx.asns.contains(asn) {
            bail!(
                "Proxy.list is not a strict superset of {}: missing IP-ASN,{}",
                label,
                asn
            );
        }
    }
    Ok(())
}

fn verify_reserved_ip_absence(lists: &[(&str, &ParsedListIndex)]) -> Result<()> {
    for reserved_ip in [
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "198.18.0.1",
        "100.64.0.1",
        "100.100.100.100",
        "127.0.0.1",
        "fd7a:115c:a1e0::1",
        "fd01::1",
    ] {
        let ip: IpAddr = reserved_ip.parse()?;
        for (name, idx) in lists {
            if idx.covers_ip(ip) {
                bail!("{} unlawfully matches reserved/mesh IP {}", name, ip);
            }
        }
    }
    Ok(())
}

fn run_production_canaries(
    direct_idx: &ParsedListIndex,
    ai_idx: &ParsedListIndex,
    payment_idx: &ParsedListIndex,
    telemetry_idx: &ParsedListIndex,
    proxy_idx: &ParsedListIndex,
) -> Result<usize> {
    let mut checked = 0usize;

    // 1. Direct domains (Mainland services, domestic streaming, domestic AI, CN CDN endpoints)
    for dom in [
        "www.baidu.com",
        "www.qq.com",
        "www.taobao.com",
        "www.alipay.com",
        "www.bilibili.com",
        "www.iqiyi.com",
        "v.qq.com",
        "www.youku.com",
        "www.mgtv.com",
        "music.163.com",
        "www.12306.cn",
        "www.cnki.net",
        "chat.deepseek.com",
        "api.deepseek.com",
        "kimi.moonshot.cn",
        "www.kimi.com",
        "www.doubao.com",
        "chatglm.cn",
        "open.bigmodel.cn",
        "api.siliconflow.cn",
        "www.aispeech.com",
        "www.coze.cn",
        "www.marscode.cn",
        "www.trae.com.cn",
        "dl.google.com",
        "gstatic-cn.com",
        "googleapis-cn.com",
        "swcdn.apple.com",
        "mesu.apple.com",
        "officecdnmac.microsoft.com",
        "dl.delivery.mp.microsoft.com",
        "steamserver.net",
    ] {
        if !direct_idx.covers_domain(dom) {
            bail!("canary failed: Direct.list does not match '{}'", dom);
        }
        for (label, clean_idx) in [
            ("AI.list", ai_idx),
            ("Payment.list", payment_idx),
            ("Telemetry.list", telemetry_idx),
        ] {
            if clean_idx.covers_domain_exact_or_suffix(dom) {
                bail!(
                    "canary failed: {} must NOT match domestic/direct domain '{}'",
                    label,
                    dom
                );
            }
        }
        checked += 4;
    }

    // 2. Overseas AI applications & AI-dedicated feature flags (must match AI.list + Proxy.list ONLY)
    for dom in [
        "chatgpt.com",
        "api.openai.com",
        "claude.ai",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
        "gemini.google.com",
        "aistudio.google.com",
        "notebooklm.google.com",
        "api.githubcopilot.com",
        "api2.cursor.sh",
        "www.perplexity.ai",
        "grok.com",
        "openrouter.ai",
        "huggingface.co",
        "moonshot.ai",
        "chat.qwen.ai",
        "chat.z.ai",
        "www.trae.ai",
        "www.cici.com",
        "www.dola.com",
        "coderabbit.ai",
        "www.marscode.com",
        "www.midjourney.com",
        "api.elevenlabs.io",
        "suno.com",
        "api.mistral.ai",
        "api.groq.com",
        "api.together.xyz",
        "oaistatsig.com",
        "statsig.anthropic.com",
        "prodregistryv2.org",
    ] {
        if !ai_idx.covers_domain(dom) {
            bail!("canary failed: AI.list does not match '{}'", dom);
        }
        if !proxy_idx.covers_domain(dom) {
            bail!(
                "canary failed: Proxy.list does not match AI canary '{}'",
                dom
            );
        }
        if payment_idx.covers_domain(dom) || telemetry_idx.covers_domain(dom) {
            bail!(
                "canary failed: AI canary '{}' leaked into Payment.list or Telemetry.list",
                dom
            );
        }
        if direct_idx.covers_domain_exact_or_suffix(dom) {
            bail!("canary failed: Direct.list must NOT match '{}'", dom);
        }
        checked += 5;
    }

    // 3. Overseas banking, payments, brokerages & payment-exclusive risk/3DS (Payment.list + Proxy.list ONLY)
    for dom in [
        "www.paypal.com",
        "www.paypalobjects.com",
        "paypalbeacon.com",
        "api.stripe.com",
        "m.stripe.network",
        "pay.google.com",
        "payments.google.com",
        "apple-pay-gateway.apple.com",
        "wise.com",
        "www.revolut.com",
        "www.hsbc.com.hk",
        "www.bochk.com",
        "www.zabank.com",
        "www.chase.com",
        "www.citi.com",
        "www.americanexpress.com",
        "www.visa.com",
        "www.mastercard.com",
        "www.interactivebrokers.com",
        "songbird.cardinalcommerce.com",
    ] {
        if !payment_idx.covers_domain(dom) {
            bail!("canary failed: Payment.list does not match '{}'", dom);
        }
        if !proxy_idx.covers_domain(dom) {
            bail!(
                "canary failed: Proxy.list does not match Payment canary '{}'",
                dom
            );
        }
        if ai_idx.covers_domain(dom) || telemetry_idx.covers_domain(dom) {
            bail!(
                "canary failed: Payment canary '{}' leaked into AI.list or Telemetry.list",
                dom
            );
        }
        if direct_idx.covers_domain_exact_or_suffix(dom) {
            bail!("canary failed: Direct.list must NOT match '{}'", dom);
        }
        checked += 5;
    }

    // 4. General risk-control, CAPTCHA, IP-geo-detect & telemetry (Telemetry.list + Proxy.list ONLY)
    for dom in [
        "challenges.cloudflare.com",
        "client-api.arkoselabs.com",
        "hcaptcha.com",
        "h.online-metrix.net",
        "api.sift.com",
        "cdn.riskified.com",
        "api.fpjs.io",
        "withpersona.com",
        "scamalytics.com",
        "ipinfo.io",
        "static.cloudflareinsights.com",
        "firebaseappcheck.googleapis.com",
    ] {
        if !telemetry_idx.covers_domain(dom) {
            bail!("canary failed: Telemetry.list does not match '{}'", dom);
        }
        if !proxy_idx.covers_domain(dom) {
            bail!(
                "canary failed: Proxy.list does not match Telemetry canary '{}'",
                dom
            );
        }
        if ai_idx.covers_domain(dom) || payment_idx.covers_domain(dom) {
            bail!(
                "canary failed: Telemetry canary '{}' leaked into AI.list or Payment.list",
                dom
            );
        }
        if direct_idx.covers_domain_exact_or_suffix(dom) {
            bail!("canary failed: Direct.list must NOT match '{}'", dom);
        }
        checked += 5;
    }

    // 5. Overseas streaming & password managers (must match Proxy.list ONLY)
    for dom in [
        "www.netflix.com",
        "www.disneyplus.com",
        "www.youtube.com",
        "open.spotify.com",
        "www.tiktok.com",
        "ani.gamer.com.tw",
        "abema.tv",
        "www.bilibili.tv",
        "www.biliintl.com",
        "p.bstarstatic.com",
        "www.iq.com",
        "wetv.vip",
        "www.joox.com",
        "1password.com",
        "bitwarden.com",
    ] {
        if !proxy_idx.covers_domain(dom) {
            bail!(
                "canary failed: Proxy.list does not match proxy-only domain '{}'",
                dom
            );
        }
        for (label, clean_idx) in [
            ("AI.list", ai_idx),
            ("Payment.list", payment_idx),
            ("Telemetry.list", telemetry_idx),
        ] {
            if clean_idx.covers_domain_exact_or_suffix(dom) {
                bail!(
                    "canary failed: {} must NOT match proxy-only domain '{}'",
                    label,
                    dom
                );
            }
        }
        if direct_idx.covers_domain_exact_or_suffix(dom) {
            bail!(
                "canary failed: Direct.list must NOT match overseas proxy domain '{}'",
                dom
            );
        }
        checked += 5;
    }

    // 6. General overseas Proxy domains (must match Proxy.list and NOT Direct.list)
    for dom in [
        "www.google.com",
        "github.com",
        "en.wikipedia.org",
        "x.com",
        "web.telegram.org",
        "www.reddit.com",
        "discord.com",
    ] {
        if !proxy_idx.covers_domain(dom) {
            bail!("canary failed: Proxy.list does not match '{}'", dom);
        }
        if direct_idx.covers_domain_exact_or_suffix(dom) {
            bail!(
                "canary failed: Direct.list must NOT match overseas domain '{}'",
                dom
            );
        }
        checked += 2;
    }

    // 7. IP / ASN / Process / AND canaries
    let cn_dns_ip: IpAddr = "114.114.114.114".parse()?;
    if !direct_idx.covers_ip(cn_dns_ip) {
        bail!("canary failed: Direct.list does not cover CN IP 114.114.114.114");
    }
    checked += 1;

    let tg_ip: IpAddr = "149.154.167.51".parse()?;
    if !proxy_idx.covers_ip(tg_ip) {
        bail!("canary failed: Proxy.list does not cover Telegram IP 149.154.167.51");
    }
    checked += 1;

    if !proxy_idx.asns.contains(&62041) {
        bail!("canary failed: Proxy.list is missing Telegram IP-ASN,62041");
    }
    checked += 1;

    if !direct_idx.process_names.contains("WeChat") {
        bail!("canary failed: Direct.list is missing PROCESS-NAME,WeChat");
    }
    for proc_name in ["Cursor", "Codex", "Claude"] {
        if !ai_idx.process_names.contains(proc_name) || !proxy_idx.process_names.contains(proc_name)
        {
            bail!(
                "canary failed: AI.list/Proxy.list is missing PROCESS-NAME,{}",
                proc_name
            );
        }
    }
    if ai_idx.logical_ands.is_empty() {
        bail!("canary failed: AI.list must contain curated macOS AND composite rules");
    }
    checked += 4;

    Ok(checked)
}

pub fn render_routing_notes(report: &RoutingVerificationReport) -> String {
    format!(
        "## Routing Rule Sets\n\n\
| Artifact | Rules | Extended Matching | Size | SHA-256 |\n\
| :--- | ---: | ---: | ---: | :--- |\n\
| `{}` | {} | {} | {} B | `{}` |\n\
| `{}` | {} | {} | {} B | `{}` |\n\
| `{}` | {} | {} | {} B | `{}` |\n\
| `{}` | {} | {} | {} B | `{}` |\n\
| `{}` | {} | {} | {} B | `{}` |\n\n\
Verified invariants: `(AI.list ∪ Payment.list ∪ Telemetry.list) ⊆ Proxy.list` (100% syntactic & semantic subset), `AI.list`, `Payment.list`, and `Telemetry.list` pairwise disjoint, `sharedInfraRoots` apex protection active, reserved/LAN/Fake-IP/Tailscale/Cloudflare-Mesh CIDRs excluded, all IP/ASN entries emit `no-resolve`, and {} production canaries passed.\n",
        report.direct.file_name,
        report.direct_total,
        report.direct_extended_count,
        report.direct.size_bytes,
        report.direct.sha256,
        report.ai.file_name,
        report.ai_total,
        report.ai_extended_count,
        report.ai.size_bytes,
        report.ai.sha256,
        report.payment.file_name,
        report.payment_total,
        report.payment_extended_count,
        report.payment.size_bytes,
        report.payment.sha256,
        report.telemetry.file_name,
        report.telemetry_total,
        report.telemetry_extended_count,
        report.telemetry.size_bytes,
        report.telemetry.sha256,
        report.proxy.file_name,
        report.proxy_total,
        report.proxy_extended_count,
        report.proxy.size_bytes,
        report.proxy.sha256,
        report.canaries_checked
    )
}
