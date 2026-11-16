use std::collections::{BTreeMap, BTreeSet};

use ipnet::{Ipv4Net, Ipv6Net};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::adblock::compiler::{
    DomainTrie, overlaps_reserved_v4, overlaps_reserved_v6, wildcard_matches_domain,
};
use crate::adblock::config::AdblockOverrides;
use crate::adblock::parsers::ruleset::parse_canonical_cidr;
use crate::routing::config::{RoutingOverrides, RoutingRuleKind, RoutingTarget};
use crate::routing::model::{
    ParsedRoutingSource, RoutingRule, RoutingRuleKey, format_routing_rule_line,
    normalize_rule_value, parse_logical_and_clauses,
};

const KNOWN_AD_DOMAIN_SUFFIXES: &[&str] = &[
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "adservice.google.com",
    "adnxs.com",
    "taboola.com",
    "outbrain.com",
    "criteo.com",
    "adsrvr.org",
    "rubiconproject.com",
    "pubmatic.com",
    "openx.net",
    "casalemedia.com",
    "applovin.com",
    "unityads.unity3d.com",
    "pangolin-sdk-toutiao.com",
    "pglstatp-toutiao.com",
    "umeng.com",
    "umengcloud.com",
    "appsflyer.com",
    "doubleverify.com",
    "scorecardresearch.com",
    "exoclick.com",
    "juicyads.com",
    "trafficjunky.net",
    "trafficstars.com",
    "propellerads.com",
    "popads.net",
    "popcash.net",
    "ero-advertising.com",
    "plugrush.com",
];

#[derive(Clone, Debug, Default)]
pub struct TargetStats {
    pub total_rules: usize,
    pub domain_count: usize,
    pub domain_suffix_count: usize,
    pub domain_keyword_count: usize,
    pub domain_wildcard_count: usize,
    pub url_regex_count: usize,
    pub user_agent_count: usize,
    pub process_name_count: usize,
    pub logical_and_count: usize,
    pub ip_cidr_count: usize,
    pub ip_cidr6_count: usize,
    pub ip_asn_count: usize,
    pub extended_matching_count: usize,
    pub subsumed_by_trie: usize,
    pub reserved_cidrs_dropped: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RoutingSourceCounts {
    pub active_direct: usize,
    pub total_direct: usize,
    pub active_ai: usize,
    pub total_ai: usize,
    pub active_proxy: usize,
    pub total_proxy: usize,
}

#[derive(Clone, Debug)]
pub struct CompiledRoutingArtifacts {
    pub direct_text: String,
    pub ai_text: String,
    pub proxy_text: String,
    pub direct_stats: TargetStats,
    pub ai_stats: TargetStats,
    pub proxy_stats: TargetStats,
    pub ad_domains_filtered: usize,
    pub conflicts_resolved: usize,
    pub ai_merged_into_proxy: usize,
}

#[derive(Clone, Debug, Default)]
struct CandidateRule {
    lineage_weights: FxHashMap<String, u16>,
    extended_matching: bool,
    forced: bool,
}

impl CandidateRule {
    fn ingest(&mut self, lineage: &str, weight: u16, extended: bool) {
        self.lineage_weights
            .entry(lineage.to_string())
            .and_modify(|prev| {
                if weight > *prev {
                    *prev = weight;
                }
            })
            .or_insert(weight);
        self.extended_matching |= extended;
    }

    fn force(&mut self, extended: bool) {
        self.forced = true;
        self.extended_matching |= extended;
    }

    fn score(&self) -> u16 {
        if self.forced {
            return 250;
        }
        let max_w = self.lineage_weights.values().copied().max().unwrap_or(0);
        let extra = (self.lineage_weights.len().saturating_sub(1) as u16).saturating_mul(12);
        max_w.saturating_add(extra).min(200)
    }
}

struct AdGuard {
    allow_trie: DomainTrie,
    ad_trie: DomainTrie,
}

impl AdGuard {
    fn from_overrides(adblock_overrides: &AdblockOverrides) -> Self {
        let mut allow_trie = DomainTrie::default();
        for entry in &adblock_overrides.allow_domains {
            let dom = entry
                .domain
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            match entry.match_type {
                crate::adblock::config::AllowDomainMatchType::Exact => {
                    allow_trie.insert_exact(&dom)
                }
                crate::adblock::config::AllowDomainMatchType::Suffix => {
                    allow_trie.insert_suffix(&dom)
                }
            }
        }

        let mut ad_trie = DomainTrie::default();
        for sfx in KNOWN_AD_DOMAIN_SUFFIXES {
            if !allow_trie.matches_domain(sfx) {
                ad_trie.insert_suffix(sfx);
            }
        }
        for entry in &adblock_overrides.force_rule_set_entries {
            let val = entry
                .value
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if allow_trie.matches_domain(&val) {
                continue;
            }
            match entry.kind.as_str() {
                "DOMAIN" => ad_trie.insert_exact(&val),
                "DOMAIN-SUFFIX" => ad_trie.insert_suffix(&val),
                _ => {}
            }
        }
        Self {
            allow_trie,
            ad_trie,
        }
    }

    fn is_ad_domain(&self, dom: &str) -> bool {
        !self.allow_trie.matches_domain(dom) && self.ad_trie.matches_domain(dom)
    }
}

#[derive(Default)]
struct RuleMatcher {
    trie: DomainTrie,
    wildcards: Vec<String>,
    exact_keys: FxHashSet<RoutingRuleKey>,
}

impl RuleMatcher {
    fn insert_key(&mut self, key: &RoutingRuleKey) {
        self.exact_keys.insert(key.clone());
        match key.kind {
            RoutingRuleKind::Domain => self.trie.insert_exact(&key.value),
            RoutingRuleKind::DomainSuffix => self.trie.insert_suffix(&key.value),
            RoutingRuleKind::DomainWildcard => self.wildcards.push(key.value.clone()),
            _ => {}
        }
    }

    fn matches_key(&self, key: &RoutingRuleKey) -> bool {
        if self.exact_keys.contains(key) {
            return true;
        }
        match key.kind {
            RoutingRuleKind::Domain | RoutingRuleKind::DomainSuffix => {
                self.trie.matches_domain(&key.value)
                    || self
                        .wildcards
                        .iter()
                        .any(|wc| wildcard_matches_domain(wc, &key.value))
            }
            RoutingRuleKind::DomainWildcard => {
                if let Some(tail) = key.value.strip_prefix("*.")
                    && !tail.contains('*')
                    && !tail.contains('?')
                {
                    return self.trie.has_suffix_ancestor_or_eq(tail);
                }
                false
            }
            _ => false,
        }
    }
}

pub fn compile_routing(
    sources: &[ParsedRoutingSource],
    overrides: &RoutingOverrides,
    adblock_overrides: &AdblockOverrides,
    source_counts: RoutingSourceCounts,
) -> CompiledRoutingArtifacts {
    let mut direct_map: FxHashMap<RoutingRuleKey, CandidateRule> = FxHashMap::default();
    let mut ai_map: FxHashMap<RoutingRuleKey, CandidateRule> = FxHashMap::default();
    let mut proxy_map: FxHashMap<RoutingRuleKey, CandidateRule> = FxHashMap::default();

    for src in sources {
        let target_map = match src.target {
            RoutingTarget::Direct => &mut direct_map,
            RoutingTarget::Ai => &mut ai_map,
            RoutingTarget::Proxy => &mut proxy_map,
        };
        for rule in &src.rules {
            target_map.entry(rule.key.clone()).or_default().ingest(
                &src.lineage,
                src.weight,
                rule.extended_matching,
            );
        }
    }

    let mut direct_forced = RuleMatcher::default();
    let mut proxy_forced = RuleMatcher::default();
    for ov in &overrides.force_entries {
        let Some(val) = normalize_rule_value(ov.kind, &ov.value) else {
            continue;
        };
        let key = RoutingRuleKey {
            kind: ov.kind,
            value: val,
        };
        let extended = ov.extended_matching && ov.kind.supports_extended_matching();
        match ov.target {
            RoutingTarget::Direct => {
                direct_forced.insert_key(&key);
                direct_map.entry(key).or_default().force(extended);
            }
            RoutingTarget::Ai => {
                ai_map.entry(key).or_default().force(extended);
            }
            RoutingTarget::Proxy => {
                proxy_forced.insert_key(&key);
                proxy_map.entry(key).or_default().force(extended);
            }
        }
    }

    // Strip known pure-ad/tracker domains unless explicitly forced by routing overrides.
    let ad_guard = AdGuard::from_overrides(adblock_overrides);
    let mut ad_domains_filtered = 0usize;
    for map in [&mut direct_map, &mut ai_map, &mut proxy_map] {
        let before = map.len();
        map.retain(|key, cand| {
            if cand.forced {
                return true;
            }
            match key.kind {
                RoutingRuleKind::Domain | RoutingRuleKind::DomainSuffix => {
                    !ad_guard.is_ad_domain(&key.value)
                }
                _ => true,
            }
        });
        ad_domains_filtered += before - map.len();
    }

    // Protect shared cloud/auth/repo apexes inside AI.list so non-AI traffic is never hijacked.
    let mut shared_infra_set: FxHashSet<String> = overrides
        .shared_infra_roots
        .iter()
        .map(|e| e.domain.trim().trim_end_matches('.').to_ascii_lowercase())
        .collect();
    shared_infra_set.insert("amazon.com".to_string());
    shared_infra_set.insert("aws.amazon.com".to_string());

    const NON_AI_PROBE_HOSTS: &[&str] = &[
        "s3.amazonaws.com",
        "console.aws.amazon.com",
        "gist.github.com",
        "cloud.google.com",
        "portal.azure.com",
        "www.cloudflare.com",
        "cdn.jsdelivr.net",
        "www.apple.com",
    ];

    ai_map.retain(|key, cand| {
        match key.kind {
            RoutingRuleKind::Domain | RoutingRuleKind::DomainSuffix => {
                if shared_infra_set.contains(&key.value) || is_cn_or_generic_tld(&key.value) {
                    return false;
                }
                if !cand.forced && direct_forced.matches_key(key) {
                    return false;
                }
            }
            RoutingRuleKind::DomainKeyword => {
                if key.value.len() <= 3
                    || shared_infra_set
                        .iter()
                        .any(|root| root.contains(&key.value))
                    || NON_AI_PROBE_HOSTS
                        .iter()
                        .any(|host| host.contains(&key.value))
                {
                    return false;
                }
            }
            RoutingRuleKind::DomainWildcard => {
                let is_shared_wildcard = key
                    .value
                    .strip_prefix("*.")
                    .is_some_and(|tail| shared_infra_set.contains(tail))
                    || shared_infra_set
                        .iter()
                        .any(|root| wildcard_matches_domain(&key.value, root))
                    || NON_AI_PROBE_HOSTS
                        .iter()
                        .any(|host| wildcard_matches_domain(&key.value, host));
                if is_shared_wildcard || is_cn_wildcard(&key.value) {
                    return false;
                }
                if !cand.forced && direct_forced.matches_key(key) {
                    return false;
                }
            }
            RoutingRuleKind::And => {
                let Some(clauses) = parse_logical_and_clauses(&key.value) else {
                    return false;
                };
                let has_context_guard = clauses.iter().any(|(k, _, _)| {
                    matches!(k, RoutingRuleKind::ProcessName | RoutingRuleKind::UserAgent)
                });
                let touches_shared_or_cn = clauses.iter().any(|(k, v, _)| {
                    matches!(
                        k,
                        RoutingRuleKind::Domain
                            | RoutingRuleKind::DomainSuffix
                            | RoutingRuleKind::DomainKeyword
                            | RoutingRuleKind::DomainWildcard
                    ) && (shared_infra_set.contains(v)
                        || is_cn_or_generic_tld(v)
                        || shared_infra_set
                            .iter()
                            .any(|root| v == root || v.ends_with(&format!(".{}", root)))
                        || NON_AI_PROBE_HOSTS
                            .iter()
                            .any(|host| *host == v || wildcard_matches_domain(v, host)))
                });
                if touches_shared_or_cn && !has_context_guard {
                    return false;
                }
                if !cand.forced && direct_forced.matches_key(key) {
                    return false;
                }
            }
            _ => {
                if !cand.forced && direct_forced.matches_key(key) {
                    return false;
                }
            }
        }
        true
    });

    // Apply target-specific explicit exclusions before cross-target reconciliation.
    let mut direct_exclude = RuleMatcher::default();
    let mut ai_exclude = RuleMatcher::default();
    let mut proxy_exclude = RuleMatcher::default();
    for ex in &overrides.exclude_entries {
        let Some(val) = normalize_rule_value(ex.kind, &ex.value) else {
            continue;
        };
        let key = RoutingRuleKey {
            kind: ex.kind,
            value: val,
        };
        match ex.target {
            RoutingTarget::Direct => direct_exclude.insert_key(&key),
            RoutingTarget::Ai => ai_exclude.insert_key(&key),
            RoutingTarget::Proxy => proxy_exclude.insert_key(&key),
        }
    }
    direct_map.retain(|k, c| c.forced || !is_excluded(&direct_exclude, k));
    ai_map.retain(|k, c| c.forced || !is_excluded(&ai_exclude, k));
    proxy_map.retain(|k, c| c.forced || !is_excluded(&proxy_exclude, k));

    // Resolve overlaps between Direct and AI: surviving AI rules take precedence over non-forced Direct rules.
    let mut ai_matcher = RuleMatcher::default();
    for key in ai_map.keys() {
        ai_matcher.insert_key(key);
    }
    let mut conflicts_resolved = 0usize;
    direct_map.retain(|k, c| {
        if !c.forced && ai_matcher.matches_key(k) {
            conflicts_resolved += 1;
            false
        } else {
            true
        }
    });

    // Resolve overlaps between Direct and Proxy.
    let shared_keys: Vec<RoutingRuleKey> = direct_map
        .keys()
        .filter(|k| proxy_map.contains_key(*k))
        .cloned()
        .collect();
    for key in shared_keys {
        let d = &direct_map[&key];
        let p = &proxy_map[&key];
        let keep_in_proxy = match (d.forced, p.forced) {
            (true, false) => false,
            (false, true) => true,
            _ => p.score() >= d.score(),
        };
        if keep_in_proxy {
            direct_map.remove(&key);
        } else {
            proxy_map.remove(&key);
        }
        conflicts_resolved += 1;
    }

    // Remove non-forced Direct entries overridden by Proxy forced entries (e.g., overseas editions of domestic media).
    direct_map.retain(|k, c| {
        if !c.forced && proxy_forced.matches_key(k) && !direct_forced.matches_key(k) {
            conflicts_resolved += 1;
            false
        } else {
            true
        }
    });

    // Remove non-forced Proxy entries overridden by Direct forced entries (e.g., CN CDN endpoints),
    // `.cn` domestic TLD entries, or higher-scored Direct ancestor suffixes / overlapping CN DNS CIDRs.
    let mut direct_suffix_scores: FxHashMap<String, u16> = FxHashMap::default();
    let mut direct_v4_cidrs: Vec<(Ipv4Net, u16)> = Vec::new();
    let mut direct_v6_cidrs: Vec<(Ipv6Net, u16)> = Vec::new();
    for (dk, dc) in &direct_map {
        match dk.kind {
            RoutingRuleKind::DomainSuffix => {
                let sc = dc.score();
                direct_suffix_scores
                    .entry(dk.value.clone())
                    .and_modify(|prev| *prev = (*prev).max(sc))
                    .or_insert(sc);
            }
            RoutingRuleKind::IpCidr => {
                if let Ok(net) = dk.value.parse::<Ipv4Net>() {
                    direct_v4_cidrs.push((net.trunc(), dc.score()));
                }
            }
            RoutingRuleKind::IpCidr6 => {
                if let Ok(net) = dk.value.parse::<Ipv6Net>() {
                    direct_v6_cidrs.push((net.trunc(), dc.score()));
                }
            }
            _ => {}
        }
    }

    proxy_map.retain(|k, c| {
        if c.forced || proxy_forced.matches_key(k) {
            return true;
        }
        if direct_forced.matches_key(k) {
            conflicts_resolved += 1;
            return false;
        }
        match k.kind {
            RoutingRuleKind::Domain | RoutingRuleKind::DomainSuffix => {
                if k.value == "cn" || k.value.ends_with(".cn") {
                    conflicts_resolved += 1;
                    return false;
                }
                let p_score = c.score();
                if let Some(&d_score) = direct_suffix_scores.get(&k.value)
                    && d_score > p_score
                {
                    conflicts_resolved += 1;
                    return false;
                }
                for (idx, _) in k.value.match_indices('.') {
                    let anc = &k.value[idx + 1..];
                    if let Some(&d_score) = direct_suffix_scores.get(anc)
                        && d_score > p_score
                    {
                        conflicts_resolved += 1;
                        return false;
                    }
                }
                true
            }
            RoutingRuleKind::IpCidr => {
                if let Ok(net) = k.value.parse::<Ipv4Net>() {
                    let net = net.trunc();
                    let p_score = c.score();
                    if direct_v4_cidrs.iter().any(|(dn, ds)| {
                        *ds > p_score
                            && (dn.contains(&net.network()) || net.contains(&dn.network()))
                    }) {
                        conflicts_resolved += 1;
                        return false;
                    }
                }
                true
            }
            RoutingRuleKind::IpCidr6 => {
                if let Ok(net) = k.value.parse::<Ipv6Net>() {
                    let net = net.trunc();
                    let p_score = c.score();
                    if direct_v6_cidrs.iter().any(|(dn, ds)| {
                        *ds > p_score
                            && (dn.contains(&net.network()) || net.contains(&dn.network()))
                    }) {
                        conflicts_resolved += 1;
                        return false;
                    }
                }
                true
            }
            _ => true,
        }
    });

    // Enforce AI.list as a strict subset of Proxy.list BEFORE compression and rendering.
    let mut ai_merged_into_proxy = 0usize;
    for (key, ai_cand) in &ai_map {
        match proxy_map.get_mut(key) {
            Some(proxy_cand) => {
                proxy_cand.extended_matching |= ai_cand.extended_matching;
                proxy_cand.forced |= ai_cand.forced;
            }
            None => {
                proxy_map.insert(key.clone(), ai_cand.clone());
                ai_merged_into_proxy += 1;
            }
        }
    }

    let (direct_text, direct_stats) = compress_and_render(
        RoutingTarget::Direct,
        direct_map,
        source_counts.active_direct,
        source_counts.total_direct,
    );
    let (ai_text, ai_stats) = compress_and_render(
        RoutingTarget::Ai,
        ai_map,
        source_counts.active_ai,
        source_counts.total_ai,
    );
    let (proxy_text, proxy_stats) = compress_and_render(
        RoutingTarget::Proxy,
        proxy_map,
        source_counts.active_proxy,
        source_counts.total_proxy,
    );

    CompiledRoutingArtifacts {
        direct_text,
        ai_text,
        proxy_text,
        direct_stats,
        ai_stats,
        proxy_stats,
        ad_domains_filtered,
        conflicts_resolved,
        ai_merged_into_proxy,
    }
}

fn is_excluded(matcher: &RuleMatcher, key: &RoutingRuleKey) -> bool {
    if key.kind == RoutingRuleKind::DomainKeyword {
        return matcher.exact_keys.contains(key);
    }
    matcher.matches_key(key)
}

fn is_cn_or_generic_tld(dom: &str) -> bool {
    dom == "cn"
        || dom.ends_with(".cn")
        || matches!(
            dom,
            "com" | "net" | "org" | "io" | "ai" | "dev" | "app" | "cloud" | "co" | "me"
        )
}

fn is_cn_wildcard(wc: &str) -> bool {
    wc == "*.cn" || wc.ends_with(".cn")
}

fn label_count(dom: &str) -> usize {
    dom.split('.').count()
}

/// Walks domain labels from broadest TLD suffix inward to `dom` itself, stopping at the broadest
/// matching suffix already inserted into `surviving_suffixes`.
fn find_broadest_suffix_ancestor<'a>(
    dom: &str,
    surviving_suffixes: &'a mut BTreeMap<String, bool>,
) -> Option<&'a mut bool> {
    let dot_positions: Vec<usize> = dom.match_indices('.').map(|(idx, _)| idx).collect();
    for idx in dot_positions.into_iter().rev() {
        let candidate = &dom[idx + 1..];
        if surviving_suffixes.contains_key(candidate) {
            return surviving_suffixes.get_mut(candidate);
        }
    }
    surviving_suffixes.get_mut(dom)
}

fn compress_and_render(
    target: RoutingTarget,
    rules: FxHashMap<RoutingRuleKey, CandidateRule>,
    active_sources: usize,
    total_sources: usize,
) -> (String, TargetStats) {
    let mut exact_domains: BTreeMap<String, bool> = BTreeMap::new();
    let mut suffix_domains: BTreeMap<String, bool> = BTreeMap::new();
    let mut keywords: BTreeMap<String, bool> = BTreeMap::new();
    let mut wildcards: BTreeMap<String, bool> = BTreeMap::new();
    let mut url_regexes: BTreeMap<String, bool> = BTreeMap::new();
    let mut user_agents: BTreeSet<String> = BTreeSet::new();
    let mut process_names: BTreeSet<String> = BTreeSet::new();
    let mut logical_ands: BTreeSet<String> = BTreeSet::new();
    let mut raw_v4: Vec<Ipv4Net> = Vec::new();
    let mut raw_v6: Vec<Ipv6Net> = Vec::new();
    let mut asns: BTreeSet<u32> = BTreeSet::new();

    let allow_ext = target != RoutingTarget::Direct;
    for (key, cand) in rules {
        let ext = allow_ext && cand.extended_matching && key.kind.supports_extended_matching();
        match key.kind {
            RoutingRuleKind::Domain => {
                exact_domains
                    .entry(key.value)
                    .and_modify(|prev| *prev |= ext)
                    .or_insert(ext);
            }
            RoutingRuleKind::DomainSuffix => {
                suffix_domains
                    .entry(key.value)
                    .and_modify(|prev| *prev |= ext)
                    .or_insert(ext);
            }
            RoutingRuleKind::DomainKeyword => {
                keywords
                    .entry(key.value)
                    .and_modify(|prev| *prev |= ext)
                    .or_insert(ext);
            }
            RoutingRuleKind::DomainWildcard => {
                wildcards
                    .entry(key.value)
                    .and_modify(|prev| *prev |= ext)
                    .or_insert(ext);
            }
            RoutingRuleKind::UrlRegex => {
                url_regexes
                    .entry(key.value)
                    .and_modify(|prev| *prev |= ext)
                    .or_insert(ext);
            }
            RoutingRuleKind::UserAgent => {
                user_agents.insert(key.value);
            }
            RoutingRuleKind::ProcessName => {
                process_names.insert(key.value);
            }
            RoutingRuleKind::And => {
                logical_ands.insert(key.value);
            }
            RoutingRuleKind::IpCidr => {
                if let Some(ipnet::IpNet::V4(v4)) = parse_canonical_cidr(&key.value) {
                    raw_v4.push(v4);
                }
            }
            RoutingRuleKind::IpCidr6 => {
                if let Some(ipnet::IpNet::V6(v6)) = parse_canonical_cidr(&key.value) {
                    raw_v6.push(v6);
                }
            }
            RoutingRuleKind::IpAsn => {
                if let Ok(asn) = key.value.parse::<u32>() {
                    asns.insert(asn);
                }
            }
        }
    }

    // 1. Compress DOMAIN-SUFFIX tree and propagate extended-matching flags upward to surviving ancestors.
    let mut sorted_suffixes: Vec<(String, bool)> = suffix_domains.into_iter().collect();
    sorted_suffixes.sort_by(|a, b| {
        label_count(&a.0)
            .cmp(&label_count(&b.0))
            .then(a.0.cmp(&b.0))
    });

    let mut trie = DomainTrie::default();
    let mut surviving_suffixes: BTreeMap<String, bool> = BTreeMap::new();
    let mut subsumed_by_trie = 0usize;

    for (dom, ext) in sorted_suffixes {
        if !trie.has_suffix_ancestor_or_eq(&dom) {
            trie.insert_suffix(&dom);
            surviving_suffixes.insert(dom, ext);
        } else {
            if let Some(anc_ext) = find_broadest_suffix_ancestor(&dom, &mut surviving_suffixes) {
                *anc_ext |= ext;
            }
            subsumed_by_trie += 1;
        }
    }

    // 2. Subsume exact DOMAIN entries already covered by a surviving DOMAIN-SUFFIX, preserving extended-matching.
    let mut surviving_exact: BTreeMap<String, bool> = BTreeMap::new();
    for (dom, ext) in exact_domains {
        if trie.matches_domain(&dom) {
            if let Some(anc_ext) = find_broadest_suffix_ancestor(&dom, &mut surviving_suffixes) {
                *anc_ext |= ext;
            }
            subsumed_by_trie += 1;
        } else {
            surviving_exact.insert(dom, ext);
        }
    }

    // 3. Subsume simple `*.tail` DOMAIN-WILDCARD entries covered by a surviving DOMAIN-SUFFIX ancestor.
    let mut surviving_wildcards: BTreeMap<String, bool> = BTreeMap::new();
    for (wc, ext) in wildcards {
        if let Some(tail) = wc.strip_prefix("*.")
            && !tail.contains('*')
            && !tail.contains('?')
            && trie.has_suffix_ancestor_or_eq(tail)
        {
            if let Some(anc_ext) = find_broadest_suffix_ancestor(tail, &mut surviving_suffixes) {
                *anc_ext |= ext;
            }
            subsumed_by_trie += 1;
        } else {
            surviving_wildcards.insert(wc, ext);
        }
    }

    // 4. Filter private/LAN/Fake-IP/Tailscale/Cloudflare-Mesh bogon CIDRs before aggregating.
    let before_ip = raw_v4.len() + raw_v6.len();
    raw_v4.retain(|net| !overlaps_reserved_v4(*net));
    raw_v6.retain(|net| !overlaps_reserved_v6(*net));
    let reserved_cidrs_dropped = before_ip - (raw_v4.len() + raw_v6.len());

    let coalesced_v4 = Ipv4Net::aggregate(&raw_v4);
    let coalesced_v6 = Ipv6Net::aggregate(&raw_v6);

    let mut stats = TargetStats {
        domain_count: surviving_exact.len(),
        domain_suffix_count: surviving_suffixes.len(),
        domain_keyword_count: keywords.len(),
        domain_wildcard_count: surviving_wildcards.len(),
        url_regex_count: url_regexes.len(),
        user_agent_count: user_agents.len(),
        process_name_count: process_names.len(),
        logical_and_count: logical_ands.len(),
        ip_cidr_count: coalesced_v4.len(),
        ip_cidr6_count: coalesced_v6.len(),
        ip_asn_count: asns.len(),
        subsumed_by_trie,
        reserved_cidrs_dropped,
        ..TargetStats::default()
    };

    let mut rendered_lines = Vec::with_capacity(
        stats.process_name_count
            + stats.user_agent_count
            + stats.logical_and_count
            + stats.domain_count
            + stats.domain_suffix_count
            + stats.domain_keyword_count
            + stats.domain_wildcard_count
            + stats.url_regex_count
            + stats.ip_cidr_count
            + stats.ip_cidr6_count
            + stats.ip_asn_count,
    );

    for proc_name in process_names {
        rendered_lines.push(format_routing_rule_line(&RoutingRule {
            key: RoutingRuleKey {
                kind: RoutingRuleKind::ProcessName,
                value: proc_name,
            },
            extended_matching: false,
        }));
    }
    for ua in user_agents {
        rendered_lines.push(format_routing_rule_line(&RoutingRule {
            key: RoutingRuleKey {
                kind: RoutingRuleKind::UserAgent,
                value: ua,
            },
            extended_matching: false,
        }));
    }
    for and_val in logical_ands {
        rendered_lines.push(format_routing_rule_line(&RoutingRule {
            key: RoutingRuleKey {
                kind: RoutingRuleKind::And,
                value: and_val,
            },
            extended_matching: false,
        }));
    }
    for (dom, ext) in surviving_exact {
        if ext {
            stats.extended_matching_count += 1;
        }
        rendered_lines.push(format_routing_rule_line(&RoutingRule {
            key: RoutingRuleKey {
                kind: RoutingRuleKind::Domain,
                value: dom,
            },
            extended_matching: ext,
        }));
    }
    for (dom, ext) in surviving_suffixes {
        if ext {
            stats.extended_matching_count += 1;
        }
        rendered_lines.push(format_routing_rule_line(&RoutingRule {
            key: RoutingRuleKey {
                kind: RoutingRuleKind::DomainSuffix,
                value: dom,
            },
            extended_matching: ext,
        }));
    }
    for (kw, ext) in keywords {
        if ext {
            stats.extended_matching_count += 1;
        }
        rendered_lines.push(format_routing_rule_line(&RoutingRule {
            key: RoutingRuleKey {
                kind: RoutingRuleKind::DomainKeyword,
                value: kw,
            },
            extended_matching: ext,
        }));
    }
    for (wc, ext) in surviving_wildcards {
        if ext {
            stats.extended_matching_count += 1;
        }
        rendered_lines.push(format_routing_rule_line(&RoutingRule {
            key: RoutingRuleKey {
                kind: RoutingRuleKind::DomainWildcard,
                value: wc,
            },
            extended_matching: ext,
        }));
    }
    for (re, ext) in url_regexes {
        if ext {
            stats.extended_matching_count += 1;
        }
        rendered_lines.push(format_routing_rule_line(&RoutingRule {
            key: RoutingRuleKey {
                kind: RoutingRuleKind::UrlRegex,
                value: re,
            },
            extended_matching: ext,
        }));
    }
    for v4 in coalesced_v4 {
        rendered_lines.push(format!("IP-CIDR,{},no-resolve", v4));
    }
    for v6 in coalesced_v6 {
        rendered_lines.push(format!("IP-CIDR6,{},no-resolve", v6));
    }
    for asn in asns {
        rendered_lines.push(format!("IP-ASN,{},no-resolve", asn));
    }

    stats.total_rules = rendered_lines.len();

    let mut out = String::with_capacity(stats.total_rules * 36 + 512);
    out.push_str(&format!(
        "# Surge External RULE-SET: {}\n",
        target.filename()
    ));
    out.push_str(&format!(
        "# Sources: {}/{} active | Total rules: {} | Extended-matching: {} | Subsumed: {} | Reserved CIDRs filtered: {}\n",
        active_sources,
        total_sources,
        stats.total_rules,
        stats.extended_matching_count,
        stats.subsumed_by_trie,
        stats.reserved_cidrs_dropped
    ));
    out.push_str(
        "# Format: policy-free external RULE-SET (IP-CIDR/IP-CIDR6/IP-ASN always carry no-resolve)\n",
    );
    out.push_str("# Repository: https://github.com/ding113/surge-rules\n\n");
    for line in rendered_lines {
        out.push_str(&line);
        out.push('\n');
    }

    (out, stats)
}
