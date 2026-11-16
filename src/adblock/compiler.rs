use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};
use regex::Regex;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::adblock::config::{
    AdblockCategory, AdblockOverrides, AdblockRuleTarget, AllowDomainMatchType,
    ModuleScriptOverride,
};
use crate::adblock::model::{
    AdguardTransformOp, AdguardTransformRule, BodyRewriteKind, BodyRewriteRule, HeaderAction,
    HeaderDirection, HeaderModException, HeaderModKind, HeaderModRule, HeaderRewriteRule,
    MapLocalDataType, MapLocalRule, ParsedAdblockSource, RemoveParamRule, ScriptRule, ScriptType,
    UrlRewriteMode, UrlRewriteRule,
};
use crate::adblock::regex_util::{
    canonical_url_pattern_key, extract_hosts_from_regex, is_valid_domain, is_valid_mitm_host,
    sample_urls_for_regex_subsumption,
};

#[derive(Default)]
struct DomainTrieNode {
    has_exact_mark: bool,
    has_suffix_mark: bool,
    children: HashMap<String, DomainTrieNode>,
}

/// Reverse-label trie supporting exact domain / suffix / ancestor / descendant queries in O(labels).
#[derive(Default)]
pub struct DomainTrie {
    root: DomainTrieNode,
}

impl DomainTrie {
    fn split_labels_rev(domain: &str) -> impl Iterator<Item = &str> {
        domain.trim_end_matches('.').rsplit('.')
    }

    pub fn insert_exact(&mut self, domain: &str) {
        let mut node = &mut self.root;
        for label in Self::split_labels_rev(domain) {
            node = node.children.entry(label.to_ascii_lowercase()).or_default();
        }
        node.has_exact_mark = true;
    }

    pub fn insert_suffix(&mut self, suffix: &str) {
        let mut node = &mut self.root;
        for label in Self::split_labels_rev(suffix) {
            node = node.children.entry(label.to_ascii_lowercase()).or_default();
        }
        node.has_suffix_mark = true;
    }

    /// Returns true if `domain` equals `x` or is a subdomain of `x` for any marked `x` using suffix semantics,
    /// OR if `domain` equals an exact mark at that terminal node.
    pub fn matches_domain(&self, domain: &str) -> bool {
        let mut node = &self.root;
        if node.has_suffix_mark {
            return true;
        }
        for label in Self::split_labels_rev(domain) {
            let Some(next) = node.children.get(&label.to_ascii_lowercase()) else {
                return false;
            };
            if next.has_suffix_mark {
                return true;
            }
            node = next;
        }
        node.has_exact_mark
    }

    /// Returns true if any strict or equal ancestor of `domain` (including `domain` itself) has a suffix mark.
    pub fn has_suffix_ancestor_or_eq(&self, domain: &str) -> bool {
        let mut node = &self.root;
        for label in Self::split_labels_rev(domain) {
            let Some(next) = node.children.get(&label.to_ascii_lowercase()) else {
                return false;
            };
            if next.has_suffix_mark {
                return true;
            }
            node = next;
        }
        false
    }

    /// Returns true if `domain` OR any descendant of `domain` has either an exact mark or a suffix mark.
    pub fn has_mark_at_or_below(&self, domain: &str) -> bool {
        let mut node = &self.root;
        for label in Self::split_labels_rev(domain) {
            let Some(next) = node.children.get(&label.to_ascii_lowercase()) else {
                return false;
            };
            node = next;
        }
        Self::subtree_has_any_mark(node)
    }

    fn subtree_has_any_mark(node: &DomainTrieNode) -> bool {
        if node.has_exact_mark || node.has_suffix_mark {
            return true;
        }
        node.children.values().any(Self::subtree_has_any_mark)
    }
}

#[derive(Clone, Debug)]
pub struct CompiledAdblockArtifacts {
    pub ruleset_text: String,
    pub privacy_ruleset_text: String,
    pub module_text: String,
    pub ruleset_counts: RulesetStats,
    pub privacy_ruleset_counts: RulesetStats,
    pub module_counts: ModuleStats,
}

#[derive(Clone, Default, Debug)]
pub struct RulesetStats {
    pub total_rules: usize,
    pub domain_count: usize,
    pub domain_suffix_count: usize,
    pub domain_keyword_count: usize,
    pub domain_wildcard_count: usize,
    pub ip_cidr_count: usize,
    pub ip_cidr6_count: usize,
    pub ip_asn_count: usize,
    pub user_agent_count: usize,
    pub process_name_count: usize,
    pub suppressed_by_protection: usize,
    pub subsumed_by_trie: usize,
}

#[derive(Clone, Default, Debug)]
pub struct ModuleStats {
    pub general_keys: usize,
    pub rules_count: usize,
    pub header_rewrite_count: usize,
    pub url_rewrite_count: usize,
    pub body_rewrite_count: usize,
    pub map_local_count: usize,
    pub script_count: usize,
    pub mitm_excluded_count: usize,
    pub mitm_included_count: usize,
}

pub const REMOVEPARAM_SCRIPT_URL: &str = "https://rule-set.ygxz.de/surge-removeparam.js";
pub const ADGUARD_SCRIPT_URL: &str = "https://rule-set.ygxz.de/surge-adguard.js";

#[derive(Default)]
struct AllowScope {
    exact_set: FxHashSet<String>,
    suffix_set: FxHashSet<String>,
    point_trie: DomainTrie,
    suffix_trie: DomainTrie,
}

impl AllowScope {
    fn from_sets(exact_set: FxHashSet<String>, suffix_set: FxHashSet<String>) -> Self {
        let mut point_trie = DomainTrie::default();
        for d in &exact_set {
            point_trie.insert_exact(d);
        }
        let mut suffix_trie = DomainTrie::default();
        for s in &suffix_set {
            suffix_trie.insert_suffix(s);
        }
        Self {
            exact_set,
            suffix_set,
            point_trie,
            suffix_trie,
        }
    }

    fn blocks_suffix(&self, s: &str) -> bool {
        self.suffix_trie.has_suffix_ancestor_or_eq(s)
            || self.suffix_trie.has_mark_at_or_below(s)
            || self.point_trie.has_mark_at_or_below(s)
    }

    fn blocks_domain(&self, d: &str) -> bool {
        self.suffix_trie.has_suffix_ancestor_or_eq(d) || self.exact_set.contains(d)
    }

    fn blocks_keyword(&self, kw: &str, trimmed: &str) -> bool {
        (trimmed.contains('.') && self.suffix_trie.has_suffix_ancestor_or_eq(trimmed))
            || self
                .exact_set
                .iter()
                .chain(self.suffix_set.iter())
                .any(|dom| dom.contains(kw))
    }

    fn blocks_wildcard(&self, wc: &str, static_tail: Option<&str>) -> bool {
        static_tail.is_some_and(|tail| self.suffix_trie.has_suffix_ancestor_or_eq(tail))
            || self
                .exact_set
                .iter()
                .chain(self.suffix_set.iter())
                .any(|dom| wildcard_matches_domain(wc, dom))
    }
}

const CLAIM_HAS_MIXED: u8 = 1 << 0;
const CLAIM_FORCED_AD: u8 = 1 << 1;
const CLAIM_FORCED_PRIV: u8 = 1 << 2;

#[derive(Clone, Copy, Default)]
struct RuleClaim {
    ad_mask: [u64; 4],
    priv_mask: [u64; 4],
    ad_max_w: u16,
    priv_max_w: u16,
    flags: u8,
}

impl RuleClaim {
    fn ingest(&mut self, category: AdblockCategory, lineage_idx: usize, weight: u16) {
        let effective_w = weight.max(1);
        match category {
            AdblockCategory::Ad | AdblockCategory::Both => {
                let word = lineage_idx / 64;
                if word < 4 {
                    self.ad_mask[word] |= 1u64 << (lineage_idx % 64);
                }
                self.ad_max_w = self.ad_max_w.max(effective_w);
            }
            AdblockCategory::Privacy => {
                let word = lineage_idx / 64;
                if word < 4 {
                    self.priv_mask[word] |= 1u64 << (lineage_idx % 64);
                }
                self.priv_max_w = self.priv_max_w.max(effective_w);
            }
            AdblockCategory::AdMixed => {
                self.flags |= CLAIM_HAS_MIXED;
            }
        }
    }

    fn force(&mut self, target: AdblockRuleTarget) {
        match target {
            AdblockRuleTarget::Ad => self.flags |= CLAIM_FORCED_AD,
            AdblockRuleTarget::Privacy => self.flags |= CLAIM_FORCED_PRIV,
        }
    }

    fn merge_from(&mut self, other: &Self) {
        for i in 0..4 {
            self.ad_mask[i] |= other.ad_mask[i];
            self.priv_mask[i] |= other.priv_mask[i];
        }
        self.ad_max_w = self.ad_max_w.max(other.ad_max_w);
        self.priv_max_w = self.priv_max_w.max(other.priv_max_w);
        self.flags |= other.flags;
    }

    fn lineage_score(mask: &[u64; 4], max_w: u16) -> u16 {
        let count: u32 = mask.iter().map(|w| w.count_ones()).sum();
        let extra = (count.saturating_sub(1) as u16).saturating_mul(12);
        max_w.saturating_add(extra).min(200)
    }

    fn owner(&self) -> AdblockRuleTarget {
        if (self.flags & CLAIM_FORCED_PRIV) != 0 && (self.flags & CLAIM_FORCED_AD) == 0 {
            return AdblockRuleTarget::Privacy;
        }
        if (self.flags & CLAIM_FORCED_AD) != 0 {
            return AdblockRuleTarget::Ad;
        }
        let has_ad = self.ad_max_w > 0;
        let has_priv = self.priv_max_w > 0;
        match (has_ad, has_priv) {
            (false, true) => AdblockRuleTarget::Privacy,
            (true, false) => AdblockRuleTarget::Ad,
            (true, true) => {
                let priv_score = Self::lineage_score(&self.priv_mask, self.priv_max_w);
                let ad_score = Self::lineage_score(&self.ad_mask, self.ad_max_w);
                if priv_score > ad_score {
                    AdblockRuleTarget::Privacy
                } else {
                    AdblockRuleTarget::Ad
                }
            }
            (false, false) => AdblockRuleTarget::Ad,
        }
    }
}

/// Domain and suffix rules imported from clean-egress routing lists (`Telemetry.list`, `Payment.list`,
/// and `AI.list`) so that `Adblock.list` and `Privacy.list` never conflict with or reject clean-exit
/// risk-control, CAPTCHA, banking/payment, or AI endpoints.
#[derive(Clone, Default, Debug)]
pub struct TelemetryProtectionSet {
    pub exact_domains: FxHashSet<String>,
    pub suffix_domains: FxHashSet<String>,
}

impl TelemetryProtectionSet {
    pub fn from_ruleset_text(text: &str) -> Self {
        let mut out = Self::default();
        out.ingest_ruleset_text(text);
        out
    }

    pub fn ingest_ruleset_text(&mut self, text: &str) {
        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.is_empty()
                || line.starts_with('#')
                || line.starts_with("//")
                || line.starts_with(';')
            {
                continue;
            }
            let mut parts = line.split(',').map(str::trim);
            let Some(kind) = parts.next() else {
                continue;
            };
            let Some(val) = parts.next() else {
                continue;
            };
            let clean = val
                .trim_start_matches('.')
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if !is_valid_domain(&clean) {
                continue;
            }
            match kind {
                "DOMAIN" => {
                    self.exact_domains.insert(clean);
                }
                "DOMAIN-SUFFIX" => {
                    self.suffix_domains.insert(clean);
                }
                _ => {}
            }
        }
    }
}

/// Compiles parsed upstream feeds and TypeScript human overrides into `Adblock.list`, `Privacy.list`, and `Adblock.sgmodule`.
pub fn compile_adblock(
    sources: &[ParsedAdblockSource],
    overrides: &AdblockOverrides,
    active_sources: usize,
    total_sources: usize,
) -> CompiledAdblockArtifacts {
    compile_adblock_with_telemetry_guard(sources, overrides, None, active_sources, total_sources)
}

/// Compiles `Adblock.list`, `Privacy.list`, and `Adblock.sgmodule` while guaranteeing zero conflict
/// against an optional `Telemetry.list` protection set (`Telemetry.list ∩ (Adblock ∪ Privacy) = ∅`).
pub fn compile_adblock_with_telemetry_guard(
    sources: &[ParsedAdblockSource],
    overrides: &AdblockOverrides,
    telemetry_guard: Option<&TelemetryProtectionSet>,
    active_sources: usize,
    total_sources: usize,
) -> CompiledAdblockArtifacts {
    // 1. Assemble 4-tier protection / scoped allowlist sets:
    //    P0a: Human allowDomains, protectedApexDomains, and Telemetry.list clean-exit guard
    //    P0b: Human forceRuleSetEntries (beat upstream allowlists and complex_protected_hosts; target = ad | privacy)
    //    P1/P2: Category-scoped upstream allowlists (`both` / `ad` / `privacy`) & complex_protected_hosts
    //    P3: Upstream blocklists (`ad` / `privacy` / `ad_mixed`)
    let mut human_allow_exact_set: FxHashSet<String> = FxHashSet::default();
    let mut human_allow_suffix_set: FxHashSet<String> = FxHashSet::default();
    let mut ad_allow_exact_set: FxHashSet<String> = FxHashSet::default();
    let mut ad_allow_suffix_set: FxHashSet<String> = FxHashSet::default();
    let mut priv_allow_exact_set: FxHashSet<String> = FxHashSet::default();
    let mut priv_allow_suffix_set: FxHashSet<String> = FxHashSet::default();
    let mut upstream_allow_exact_set: FxHashSet<String> = FxHashSet::default();
    let mut upstream_allow_suffix_set: FxHashSet<String> = FxHashSet::default();
    let mut protected_apex_set: FxHashSet<String> = FxHashSet::default();
    let mut complex_host_set: FxHashSet<String> = FxHashSet::default();

    for entry in &overrides.allow_domains {
        let dom = entry
            .domain
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        match entry.match_type {
            AllowDomainMatchType::Exact => {
                human_allow_exact_set.insert(dom);
            }
            AllowDomainMatchType::Suffix => {
                human_allow_suffix_set.insert(dom);
            }
        }
    }
    if let Some(tguard) = telemetry_guard {
        let forced_domain_vals: FxHashSet<String> = overrides
            .force_rule_set_entries
            .iter()
            .map(|f| {
                f.value
                    .trim()
                    .trim_start_matches('.')
                    .trim_end_matches('.')
                    .to_ascii_lowercase()
            })
            .collect();
        for d in &tguard.exact_domains {
            if !forced_domain_vals.contains(d) {
                human_allow_exact_set.insert(d.clone());
            }
        }
        for s in &tguard.suffix_domains {
            if !forced_domain_vals.contains(s) {
                human_allow_suffix_set.insert(s.clone());
            }
        }
    }
    for apex in &overrides.protected_apex_domains {
        protected_apex_set.insert(
            apex.domain
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase(),
        );
    }
    for src in sources {
        upstream_allow_exact_set.extend(src.allow_exact_domains.iter().cloned());
        upstream_allow_suffix_set.extend(src.allow_suffix_domains.iter().cloned());
        match src.category {
            AdblockCategory::Both => {
                ad_allow_exact_set.extend(src.allow_exact_domains.iter().cloned());
                ad_allow_suffix_set.extend(src.allow_suffix_domains.iter().cloned());
                priv_allow_exact_set.extend(src.allow_exact_domains.iter().cloned());
                priv_allow_suffix_set.extend(src.allow_suffix_domains.iter().cloned());
            }
            AdblockCategory::Ad => {
                ad_allow_exact_set.extend(src.allow_exact_domains.iter().cloned());
                ad_allow_suffix_set.extend(src.allow_suffix_domains.iter().cloned());
            }
            AdblockCategory::Privacy => {
                priv_allow_exact_set.extend(src.allow_exact_domains.iter().cloned());
                priv_allow_suffix_set.extend(src.allow_suffix_domains.iter().cloned());
            }
            AdblockCategory::AdMixed => {}
        }
        complex_host_set.extend(src.complex_protected_hosts.iter().cloned());
    }

    // 2. Collect ComplexFirst module sections, MITM exclusions, and human module overrides (weight 200)
    let mut mitm_exclusions: BTreeSet<String> = BTreeSet::new();
    for ex in &overrides.mitm_excluded_hosts {
        let p = ex.pattern.trim().to_ascii_lowercase();
        if is_valid_mitm_host(&p) {
            mitm_exclusions.insert(p);
        }
    }
    let mitm_exclusion_set = mitm_exclusions.clone();

    let mut general_hosts: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut module_rule_map: BTreeMap<String, u16> = BTreeMap::new();
    let mut header_map: BTreeMap<
        (HeaderDirection, String, HeaderAction, String),
        HeaderRewriteRule,
    > = BTreeMap::new();
    let mut url_map: BTreeMap<(String, UrlRewriteMode), UrlRewriteRule> = BTreeMap::new();
    let mut map_local_map: BTreeMap<String, MapLocalRule> = BTreeMap::new();
    let mut body_map: BTreeMap<(BodyRewriteKind, String, String), BodyRewriteRule> =
        BTreeMap::new();
    let mut adguard_transforms: Vec<AdguardTransformRule> = Vec::new();
    let mut script_candidates: Vec<ScriptRule> = Vec::new();
    let mut remove_params: Vec<RemoveParamRule> = Vec::new();
    let mut removeparam_exceptions: Vec<(String, String)> = Vec::new();
    let mut header_mods: Vec<HeaderModRule> = Vec::new();
    let mut header_mod_exceptions: Vec<HeaderModException> = Vec::new();
    let mut removeheader_exceptions: Vec<(HeaderDirection, String, String)> = Vec::new();
    let mut mitm_positive: BTreeSet<String> = BTreeSet::new();

    for src in sources {
        for g in &src.module_general_hosts {
            general_hosts
                .entry(g.key.clone())
                .or_default()
                .insert(g.host.clone());
        }
        for r in &src.module_rules {
            if is_pattern_disabled(&r.line, &overrides.disabled_url_patterns) {
                continue;
            }
            let entry = module_rule_map.entry(r.line.clone()).or_insert(0);
            *entry = (*entry).max(r.weight);
        }
        for h in &src.header_rewrites {
            if is_pattern_disabled(&h.pattern, &overrides.disabled_url_patterns) {
                continue;
            }
            insert_weighted(&mut header_map, h.dedup_key(), h.clone(), |x| x.weight);
        }
        for u in &src.url_rewrites {
            if is_pattern_disabled(&u.pattern, &overrides.disabled_url_patterns) {
                continue;
            }
            insert_weighted(&mut url_map, u.dedup_key(), u.clone(), |x| x.weight);
        }
        for ml in &src.map_locals {
            if is_pattern_disabled(&ml.pattern, &overrides.disabled_url_patterns) {
                continue;
            }
            insert_weighted(&mut map_local_map, ml.dedup_key(), ml.clone(), |x| x.weight);
        }
        for br in &src.body_rewrites {
            if is_pattern_disabled(&br.pattern, &overrides.disabled_url_patterns) {
                continue;
            }
            insert_weighted(&mut body_map, br.dedup_key(), br.clone(), |x| x.weight);
        }
        for ag in &src.adguard_transforms {
            if !is_pattern_disabled(&ag.pattern, &overrides.disabled_url_patterns) {
                adguard_transforms.push(ag.clone());
            }
        }
        for s in &src.scripts {
            if !is_pattern_disabled(&s.pattern, &overrides.disabled_url_patterns) {
                script_candidates.push(s.clone());
            }
        }
        remove_params.extend(src.remove_params.iter().cloned());
        removeparam_exceptions.extend(src.removeparam_exceptions.iter().cloned());
        header_mods.extend(src.header_mods.iter().cloned());
        header_mod_exceptions.extend(src.header_mod_exceptions.iter().cloned());
        removeheader_exceptions.extend(src.removeheader_exceptions.iter().cloned());
        for mh in &src.mitm_hosts {
            let clean = mh.trim().to_ascii_lowercase();
            if is_valid_mitm_host(&clean) {
                mitm_positive.insert(clean);
            }
        }
    }

    // Apply human module overrides at top weight (200) — may also register complex_host_set entries
    apply_module_overrides(
        overrides,
        &mut complex_host_set,
        &mut mitm_positive,
        &mut header_map,
        &mut url_map,
        &mut map_local_map,
        &mut body_map,
        &mut script_candidates,
    );

    // 3. Compile disjoint fallback RULE-SETs (`Adblock.list` + `Privacy.list`) with 4-tier domain
    //    precedence, category-scoped allowlists, unified trie compression, and CIDR aggregation.
    let human_allow_scope = AllowScope::from_sets(
        human_allow_exact_set.clone(),
        human_allow_suffix_set.clone(),
    );
    let ad_allow_scope = AllowScope::from_sets(ad_allow_exact_set, ad_allow_suffix_set);
    let priv_allow_scope = AllowScope::from_sets(priv_allow_exact_set, priv_allow_suffix_set);
    let all_upstream_allow_scope =
        AllowScope::from_sets(upstream_allow_exact_set, upstream_allow_suffix_set);

    let mut complex_point_trie = DomainTrie::default();
    for d in &complex_host_set {
        complex_point_trie.insert_exact(d);
    }

    let mut lineage_index: FxHashMap<String, usize> = FxHashMap::default();
    let mut next_lineage_idx = 0usize;
    let mut get_lineage_idx = |lin: &str| -> usize {
        let key = if lin.is_empty() { "default" } else { lin };
        if let Some(&idx) = lineage_index.get(key) {
            idx
        } else {
            let idx = next_lineage_idx;
            next_lineage_idx += 1;
            lineage_index.insert(key.to_string(), idx);
            idx
        }
    };

    let mut raw_seen_domains: FxHashSet<String> = FxHashSet::default();
    let mut raw_seen_suffixes: FxHashSet<String> = FxHashSet::default();
    let mut domain_claims: FxHashMap<String, RuleClaim> = FxHashMap::default();
    let mut suffix_claims: FxHashMap<String, RuleClaim> = FxHashMap::default();
    let mut keyword_claims: BTreeMap<String, RuleClaim> = BTreeMap::new();
    let mut wildcard_claims: BTreeMap<String, RuleClaim> = BTreeMap::new();
    let mut v4_claims: FxHashMap<Ipv4Net, RuleClaim> = FxHashMap::default();
    let mut v6_claims: FxHashMap<Ipv6Net, RuleClaim> = FxHashMap::default();
    let mut asn_claims: BTreeMap<u32, RuleClaim> = BTreeMap::new();
    let mut ua_claims: BTreeMap<String, RuleClaim> = BTreeMap::new();
    let mut proc_claims: BTreeMap<String, RuleClaim> = BTreeMap::new();

    for src in sources {
        let lin_idx = get_lineage_idx(&src.lineage);
        let scope = match src.category {
            AdblockCategory::Ad | AdblockCategory::Both => &ad_allow_scope,
            AdblockCategory::Privacy => &priv_allow_scope,
            AdblockCategory::AdMixed => &all_upstream_allow_scope,
        };

        for s in &src.ruleset_suffixes {
            raw_seen_suffixes.insert(s.clone());
            let blocked = human_allow_scope.blocks_suffix(s)
                || protected_apex_set.contains(s)
                || complex_point_trie.has_mark_at_or_below(s)
                || scope.blocks_suffix(s);
            if !blocked {
                suffix_claims.entry(s.clone()).or_default().ingest(
                    src.category,
                    lin_idx,
                    src.weight,
                );
            }
        }

        for d in &src.ruleset_domains {
            raw_seen_domains.insert(d.clone());
            let blocked = human_allow_scope.blocks_domain(d)
                || protected_apex_set.contains(d)
                || complex_host_set.contains(d)
                || scope.blocks_domain(d);
            if !blocked {
                domain_claims.entry(d.clone()).or_default().ingest(
                    src.category,
                    lin_idx,
                    src.weight,
                );
            }
        }

        for kw in &src.ruleset_keywords {
            if kw.contains("made_by_") || kw.contains("7h1s_rul3") {
                continue;
            }
            let trimmed = kw.trim_matches(|c: char| !c.is_ascii_alphanumeric());
            let blocked = human_allow_scope.blocks_keyword(kw, trimmed)
                || scope.blocks_keyword(kw, trimmed)
                || protected_apex_set
                    .iter()
                    .chain(complex_host_set.iter())
                    .any(|dom| dom.contains(kw.as_str()));
            if !blocked {
                keyword_claims.entry(kw.clone()).or_default().ingest(
                    src.category,
                    lin_idx,
                    src.weight,
                );
            }
        }

        for wc in &src.ruleset_wildcards {
            let static_tail = wildcard_static_suffix(wc);
            let blocked = human_allow_scope.blocks_wildcard(wc, static_tail)
                || scope.blocks_wildcard(wc, static_tail)
                || complex_host_set
                    .iter()
                    .any(|dom| wildcard_matches_domain(wc, dom));
            if !blocked {
                wildcard_claims.entry(wc.clone()).or_default().ingest(
                    src.category,
                    lin_idx,
                    src.weight,
                );
            }
        }

        for &net in &src.ruleset_cidrs_v4 {
            if !overlaps_reserved_v4(net) && !overlaps_shared_cdn_or_dns_v4(net) {
                v4_claims
                    .entry(net)
                    .or_default()
                    .ingest(src.category, lin_idx, src.weight);
            }
        }
        for &net in &src.ruleset_cidrs_v6 {
            if !overlaps_reserved_v6(net) && !overlaps_shared_cdn_or_dns_v6(net) {
                v6_claims
                    .entry(net)
                    .or_default()
                    .ingest(src.category, lin_idx, src.weight);
            }
        }
        for &asn in &src.ruleset_asns {
            asn_claims
                .entry(asn)
                .or_default()
                .ingest(src.category, lin_idx, src.weight);
        }
        for ua in &src.ruleset_user_agents {
            ua_claims
                .entry(ua.clone())
                .or_default()
                .ingest(src.category, lin_idx, src.weight);
        }
        for p in &src.ruleset_process_names {
            proc_claims
                .entry(p.clone())
                .or_default()
                .ingest(src.category, lin_idx, src.weight);
        }
    }

    let mut forced_domains: FxHashSet<String> = FxHashSet::default();
    let mut forced_suffixes: FxHashSet<String> = FxHashSet::default();
    for f in &overrides.force_rule_set_entries {
        let v = f.value.trim();
        match f.kind.as_str() {
            "DOMAIN" => {
                let d = v.trim_end_matches('.').to_ascii_lowercase();
                if is_valid_domain(&d) {
                    raw_seen_domains.insert(d.clone());
                    forced_domains.insert(d.clone());
                    if !(human_allow_scope.blocks_domain(&d) || protected_apex_set.contains(&d)) {
                        domain_claims.entry(d).or_default().force(f.target);
                    }
                }
            }
            "DOMAIN-SUFFIX" => {
                let s = v
                    .trim_start_matches('.')
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                if is_valid_domain(&s) {
                    raw_seen_suffixes.insert(s.clone());
                    forced_suffixes.insert(s.clone());
                    if !(human_allow_scope.blocks_suffix(&s) || protected_apex_set.contains(&s)) {
                        suffix_claims.entry(s).or_default().force(f.target);
                    }
                }
            }
            "DOMAIN-KEYWORD" => {
                let kw = v.to_ascii_lowercase();
                let trimmed = kw.trim_matches(|c: char| !c.is_ascii_alphanumeric());
                if !(human_allow_scope.blocks_keyword(&kw, trimmed)
                    || protected_apex_set.iter().any(|dom| dom.contains(&kw)))
                {
                    keyword_claims.entry(kw).or_default().force(f.target);
                }
            }
            "DOMAIN-WILDCARD" => {
                let wc = v.to_ascii_lowercase();
                let static_tail = wildcard_static_suffix(&wc);
                if !human_allow_scope.blocks_wildcard(&wc, static_tail) {
                    wildcard_claims.entry(wc).or_default().force(f.target);
                }
            }
            "IP-CIDR" => {
                if let Ok(raw_net) = v.parse::<Ipv4Net>() {
                    let net = raw_net.trunc();
                    if !overlaps_reserved_v4(net) && !overlaps_shared_cdn_or_dns_v4(net) {
                        v4_claims.entry(net).or_default().force(f.target);
                    }
                }
            }
            "IP-CIDR6" => {
                if let Ok(raw_net) = v.parse::<Ipv6Net>() {
                    let net = raw_net.trunc();
                    if !overlaps_reserved_v6(net) && !overlaps_shared_cdn_or_dns_v6(net) {
                        v6_claims.entry(net).or_default().force(f.target);
                    }
                }
            }
            "IP-ASN" => {
                if let Ok(asn) = v.parse::<u32>() {
                    asn_claims.entry(asn).or_default().force(f.target);
                }
            }
            "USER-AGENT" => {
                ua_claims.entry(v.to_string()).or_default().force(f.target);
            }
            "PROCESS-NAME" => {
                proc_claims
                    .entry(v.to_string())
                    .or_default()
                    .force(f.target);
            }
            _ => {}
        }
    }

    // Propagate exact DOMAIN force flags onto matching DOMAIN-SUFFIX entries so an unforced suffix
    // at the same hostname always honors the human-forced target before subsuming the exact DOMAIN.
    for (d, d_claim) in &domain_claims {
        let force_bits = d_claim.flags & (CLAIM_FORCED_AD | CLAIM_FORCED_PRIV);
        if force_bits != 0
            && let Some(s_claim) = suffix_claims.get_mut(d)
        {
            s_claim.flags |= force_bits;
        }
    }

    let suppressed_by_protection = raw_seen_suffixes.len().saturating_sub(suffix_claims.len())
        + raw_seen_domains.len().saturating_sub(domain_claims.len());

    // Build unified suffix trie and partition into mutually disjoint Ad vs Privacy suffix sets
    let mut surviving_suffixes: Vec<(String, RuleClaim)> = suffix_claims.into_iter().collect();
    surviving_suffixes.sort_by(|a, b| {
        a.0.split('.')
            .count()
            .cmp(&b.0.split('.').count())
            .then_with(|| a.0.cmp(&b.0))
    });
    let mut final_suffix_trie = DomainTrie::default();
    let mut ad_suffixes: BTreeSet<String> = BTreeSet::new();
    let mut priv_suffixes: BTreeSet<String> = BTreeSet::new();
    let mut subsumed_by_trie = 0usize;

    for (s, claim) in surviving_suffixes {
        if final_suffix_trie.has_suffix_ancestor_or_eq(&s) {
            subsumed_by_trie += 1;
            continue;
        }
        final_suffix_trie.insert_suffix(&s);
        match claim.owner() {
            AdblockRuleTarget::Ad => {
                ad_suffixes.insert(s);
            }
            AdblockRuleTarget::Privacy => {
                priv_suffixes.insert(s);
            }
        }
    }

    let mut compressed_domains: BTreeSet<String> = BTreeSet::new();
    let mut ad_domains: BTreeSet<String> = BTreeSet::new();
    let mut priv_domains: BTreeSet<String> = BTreeSet::new();
    for (d, claim) in domain_claims {
        if final_suffix_trie.has_suffix_ancestor_or_eq(&d) {
            subsumed_by_trie += 1;
            continue;
        }
        compressed_domains.insert(d.clone());
        match claim.owner() {
            AdblockRuleTarget::Ad => {
                ad_domains.insert(d);
            }
            AdblockRuleTarget::Privacy => {
                priv_domains.insert(d);
            }
        }
    }

    let mut ad_keywords: BTreeSet<String> = BTreeSet::new();
    let mut priv_keywords: BTreeSet<String> = BTreeSet::new();
    for (kw, claim) in keyword_claims {
        match claim.owner() {
            AdblockRuleTarget::Ad => {
                ad_keywords.insert(kw);
            }
            AdblockRuleTarget::Privacy => {
                priv_keywords.insert(kw);
            }
        }
    }

    let mut ad_wildcards: BTreeSet<String> = BTreeSet::new();
    let mut priv_wildcards: BTreeSet<String> = BTreeSet::new();
    for (wc, claim) in wildcard_claims {
        match claim.owner() {
            AdblockRuleTarget::Ad => {
                ad_wildcards.insert(wc);
            }
            AdblockRuleTarget::Privacy => {
                priv_wildcards.insert(wc);
            }
        }
    }

    let mut ad_asns: BTreeSet<u32> = BTreeSet::new();
    let mut priv_asns: BTreeSet<u32> = BTreeSet::new();
    for (asn, claim) in asn_claims {
        match claim.owner() {
            AdblockRuleTarget::Ad => {
                ad_asns.insert(asn);
            }
            AdblockRuleTarget::Privacy => {
                priv_asns.insert(asn);
            }
        }
    }

    let mut ad_uas: BTreeSet<String> = BTreeSet::new();
    let mut priv_uas: BTreeSet<String> = BTreeSet::new();
    for (ua, claim) in ua_claims {
        match claim.owner() {
            AdblockRuleTarget::Ad => {
                ad_uas.insert(ua);
            }
            AdblockRuleTarget::Privacy => {
                priv_uas.insert(ua);
            }
        }
    }

    let mut ad_procs: BTreeSet<String> = BTreeSet::new();
    let mut priv_procs: BTreeSet<String> = BTreeSet::new();
    for (proc_name, claim) in proc_claims {
        match claim.owner() {
            AdblockRuleTarget::Ad => {
                ad_procs.insert(proc_name);
            }
            AdblockRuleTarget::Privacy => {
                priv_procs.insert(proc_name);
            }
        }
    }

    // Enforce 4-tier domain precedence and reserved/shared-CDN CIDR guards on module `[Rule]` REJECT entries too
    module_rule_map.retain(|line, _| {
        let parts: Vec<&str> = line.split(',').map(str::trim).collect();
        let is_reject = parts
            .iter()
            .any(|p| p.to_ascii_uppercase().starts_with("REJECT"));
        if !is_reject || parts.len() < 2 {
            return true;
        }
        match parts[0].to_ascii_uppercase().as_str() {
            "DOMAIN" => {
                let d = parts[1].trim_end_matches('.').to_ascii_lowercase();
                let is_forced = forced_domains.contains(&d);
                let blocked_by_human =
                    human_allow_scope.blocks_domain(&d) || protected_apex_set.contains(&d);
                let blocked_by_upstream = !is_forced
                    && (all_upstream_allow_scope.blocks_domain(&d)
                        || complex_host_set.contains(&d));
                !(blocked_by_human || blocked_by_upstream)
            }
            "DOMAIN-SUFFIX" => {
                let s = parts[1]
                    .trim_start_matches('.')
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                let is_forced = forced_suffixes.contains(&s);
                let blocked_by_human =
                    human_allow_scope.blocks_suffix(&s) || protected_apex_set.contains(&s);
                let blocked_by_upstream = !is_forced
                    && (all_upstream_allow_scope.blocks_suffix(&s)
                        || complex_point_trie.has_mark_at_or_below(&s));
                !(blocked_by_human || blocked_by_upstream)
            }
            "IP-CIDR" => parts[1]
                .parse::<Ipv4Net>()
                .map(|n| {
                    let net = n.trunc();
                    !overlaps_reserved_v4(net) && !overlaps_shared_cdn_or_dns_v4(net)
                })
                .unwrap_or(false),
            "IP-CIDR6" => parts[1]
                .parse::<Ipv6Net>()
                .map(|n| {
                    let net = n.trunc();
                    !overlaps_reserved_v6(net) && !overlaps_shared_cdn_or_dns_v6(net)
                })
                .unwrap_or(false),
            _ => true,
        }
    });

    // Coalesce IPv4 and IPv6 CIDRs globally first, then partition aggregated blocks disjointly
    let raw_v4_keys: Vec<Ipv4Net> = v4_claims.keys().copied().collect();
    let coalesced_v4 = Ipv4Net::aggregate(&raw_v4_keys);
    let mut sorted_v4: Vec<(u32, u32, RuleClaim)> = v4_claims
        .into_iter()
        .map(|(n, c)| (u32::from(n.network()), u32::from(n.broadcast()), c))
        .collect();
    sorted_v4.sort_by_key(|x| (x.0, x.1));

    let mut ad_v4: Vec<Ipv4Net> = Vec::new();
    let mut priv_v4: Vec<Ipv4Net> = Vec::new();
    for agg in coalesced_v4 {
        let a_start = u32::from(agg.network());
        let a_end = u32::from(agg.broadcast());
        let idx = sorted_v4.partition_point(|x| x.0 < a_start);
        let mut merged = RuleClaim::default();
        for &(s, e, ref c) in &sorted_v4[idx..] {
            if s > a_end {
                break;
            }
            if e <= a_end {
                merged.merge_from(c);
            }
        }
        match merged.owner() {
            AdblockRuleTarget::Ad => ad_v4.push(agg),
            AdblockRuleTarget::Privacy => priv_v4.push(agg),
        }
    }

    let raw_v6_keys: Vec<Ipv6Net> = v6_claims.keys().copied().collect();
    let coalesced_v6 = Ipv6Net::aggregate(&raw_v6_keys);
    let mut sorted_v6: Vec<(u128, u128, RuleClaim)> = v6_claims
        .into_iter()
        .map(|(n, c)| (u128::from(n.network()), u128::from(n.broadcast()), c))
        .collect();
    sorted_v6.sort_by_key(|x| (x.0, x.1));

    let mut ad_v6: Vec<Ipv6Net> = Vec::new();
    let mut priv_v6: Vec<Ipv6Net> = Vec::new();
    for agg in coalesced_v6 {
        let a_start = u128::from(agg.network());
        let a_end = u128::from(agg.broadcast());
        let idx = sorted_v6.partition_point(|x| x.0 < a_start);
        let mut merged = RuleClaim::default();
        for &(s, e, ref c) in &sorted_v6[idx..] {
            if s > a_end {
                break;
            }
            if e <= a_end {
                merged.merge_from(c);
            }
        }
        match merged.owner() {
            AdblockRuleTarget::Ad => ad_v6.push(agg),
            AdblockRuleTarget::Privacy => priv_v6.push(agg),
        }
    }

    let (ruleset_text, mut ruleset_counts) = render_ruleset(
        "Adblock",
        &ad_domains,
        &ad_suffixes,
        &ad_keywords,
        &ad_wildcards,
        &ad_v4,
        &ad_v6,
        &ad_asns,
        &ad_uas,
        &ad_procs,
        active_sources,
        total_sources,
    );
    ruleset_counts.suppressed_by_protection = suppressed_by_protection;
    ruleset_counts.subsumed_by_trie = subsumed_by_trie;

    let (privacy_ruleset_text, privacy_ruleset_counts) = render_ruleset(
        "Privacy",
        &priv_domains,
        &priv_suffixes,
        &priv_keywords,
        &priv_wildcards,
        &priv_v4,
        &priv_v6,
        &priv_asns,
        &priv_uas,
        &priv_procs,
        active_sources,
        total_sources,
    );

    // 4. Promote surgical rules from RulesetFallback feeds ONLY when their target hosts are NOT already
    //    blocked in Adblock.list and NOT excluded from MITM.
    for src in sources {
        for h in &src.fallback_header_rewrites {
            if let Some(mitm_hosts) = fallback_rule_targets_survive(
                &h.pattern,
                &overrides.disabled_url_patterns,
                &mitm_exclusion_set,
                &final_suffix_trie,
                &compressed_domains,
            ) {
                mitm_positive.extend(mitm_hosts);
                insert_weighted(&mut header_map, h.dedup_key(), h.clone(), |x| x.weight);
            }
        }
        for ml in &src.fallback_map_locals {
            if let Some(mitm_hosts) = fallback_rule_targets_survive(
                &ml.pattern,
                &overrides.disabled_url_patterns,
                &mitm_exclusion_set,
                &final_suffix_trie,
                &compressed_domains,
            ) {
                mitm_positive.extend(mitm_hosts);
                insert_weighted(&mut map_local_map, ml.dedup_key(), ml.clone(), |x| x.weight);
            }
        }
        for br in &src.fallback_body_rewrites {
            if let Some(mitm_hosts) = fallback_rule_targets_survive(
                &br.pattern,
                &overrides.disabled_url_patterns,
                &mitm_exclusion_set,
                &final_suffix_trie,
                &compressed_domains,
            ) {
                mitm_positive.extend(mitm_hosts);
                insert_weighted(&mut body_map, br.dedup_key(), br.clone(), |x| x.weight);
            }
        }
        for ag in &src.fallback_adguard_transforms {
            if let Some(mitm_hosts) = fallback_rule_targets_survive(
                &ag.pattern,
                &overrides.disabled_url_patterns,
                &mitm_exclusion_set,
                &final_suffix_trie,
                &compressed_domains,
            ) {
                mitm_positive.extend(mitm_hosts);
                adguard_transforms.push(ag.clone());
            }
        }
    }

    // 5. Compile AdGuard runtime transforms ($replace, $hls, $xmlprune, $jsonprune) into `surge-adguard-*` scripts
    //    BEFORE resolving script conflicts so higher-weight app scripts cleanly win on exact trigger collisions.
    adguard_transforms
        .retain(|ag| !pattern_targets_excluded_https_only(&ag.pattern, &mitm_exclusion_set));
    script_candidates.extend(build_adguard_transform_scripts(adguard_transforms));

    // 6. Deduplicate scripts while enforcing Surge's 1-script-per-(type, pattern) precedence
    //    and pruning shadowed scripts already short-circuited by [Map Local] / [URL Rewrite] or broader higher-weight scripts.
    let mut short_circuit_response_keys: HashMap<String, u16> = HashMap::new();
    for ml in map_local_map.values() {
        let entry = short_circuit_response_keys
            .entry(canonical_url_pattern_key(&ml.pattern))
            .or_insert(0);
        *entry = (*entry).max(ml.weight);
    }
    for ur in url_map.values() {
        if ur.mode != UrlRewriteMode::Header {
            let entry = short_circuit_response_keys
                .entry(canonical_url_pattern_key(&ur.pattern))
                .or_insert(0);
            *entry = (*entry).max(ur.weight);
        }
    }
    let mut final_scripts =
        resolve_script_conflicts(script_candidates, &short_circuit_response_keys);

    // 7. Filter MITM hosts against `-` exclusions and prune HTTPS-only module rules targeting excluded hosts
    mitm_positive.retain(|h| !mitm_host_is_excluded(h, &mitm_exclusion_set));
    header_map.retain(|_, r| {
        if pattern_targets_excluded_https_only(&r.pattern, &mitm_exclusion_set) {
            return false;
        }
        !removeheader_exceptions.iter().any(|(dir, scope, field)| {
            *dir == r.direction
                && r.field.eq_ignore_ascii_case(field)
                && r.pattern
                    .to_ascii_lowercase()
                    .contains(&scope.to_ascii_lowercase())
        })
    });
    url_map.retain(|_, r| !pattern_targets_excluded_https_only(&r.pattern, &mitm_exclusion_set));
    map_local_map
        .retain(|_, r| !pattern_targets_excluded_https_only(&r.pattern, &mitm_exclusion_set));
    body_map.retain(|_, r| !pattern_targets_excluded_https_only(&r.pattern, &mitm_exclusion_set));
    final_scripts.retain(|s| !pattern_targets_excluded_https_only(&s.pattern, &mitm_exclusion_set));

    // 8. Append `$removeparam` and advanced header modifier (`$cookie`, `$csp`, `$permissions`) scripts last
    //    so app-specific scripts and body transforms take precedence without unbounded body buffering.
    final_scripts.extend(build_removeparam_scripts(
        &remove_params,
        &removeparam_exceptions,
        &mut mitm_positive,
        &mitm_exclusion_set,
        &final_suffix_trie,
        &compressed_domains,
    ));
    let new_hdr_scripts = build_header_modifier_scripts(
        &header_mods,
        &header_mod_exceptions,
        &protected_apex_set,
        &mut mitm_positive,
        &mitm_exclusion_set,
        &final_suffix_trie,
        &compressed_domains,
    );
    let mut existing_triggers: FxHashSet<(ScriptType, String)> = final_scripts
        .iter()
        .map(|s| (s.script_type, s.pattern.clone()))
        .collect();
    for s in new_hdr_scripts {
        if existing_triggers.insert((s.script_type, s.pattern.clone())) {
            final_scripts.push(s);
        }
    }
    for s in &mut final_scripts {
        s.normalize_runtime_bounds();
    }

    // Enforce `-` exclusions again in case small-scale removeparam rules introduced MITM hosts
    mitm_positive.retain(|h| !mitm_host_is_excluded(h, &mitm_exclusion_set));

    let (module_text, module_counts) = render_module(
        &general_hosts,
        &module_rule_map,
        &header_map,
        &url_map,
        &map_local_map,
        &body_map,
        &final_scripts,
        &mitm_exclusions,
        &mitm_positive,
        active_sources,
        total_sources,
    );

    CompiledAdblockArtifacts {
        ruleset_text,
        privacy_ruleset_text,
        module_text,
        ruleset_counts,
        privacy_ruleset_counts,
        module_counts,
    }
}

fn is_pattern_disabled(pattern: &str, disabled: &[String]) -> bool {
    disabled
        .iter()
        .any(|d| !d.is_empty() && pattern.contains(d))
}

fn insert_weighted<K, V, F>(map: &mut BTreeMap<K, V>, key: K, val: V, weight_fn: F)
where
    K: Ord,
    F: Fn(&V) -> u16,
{
    match map.get_mut(&key) {
        Some(existing) => {
            if weight_fn(&val) >= weight_fn(existing) {
                *existing = val;
            }
        }
        None => {
            map.insert(key, val);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_module_overrides(
    overrides: &AdblockOverrides,
    complex_host_set: &mut FxHashSet<String>,
    mitm_positive: &mut BTreeSet<String>,
    header_map: &mut BTreeMap<(HeaderDirection, String, HeaderAction, String), HeaderRewriteRule>,
    url_map: &mut BTreeMap<(String, UrlRewriteMode), UrlRewriteRule>,
    map_local_map: &mut BTreeMap<String, MapLocalRule>,
    body_map: &mut BTreeMap<(BodyRewriteKind, String, String), BodyRewriteRule>,
    script_candidates: &mut Vec<ScriptRule>,
) {
    for h in &overrides.mitm_added_hosts {
        let p = h.pattern.trim().to_ascii_lowercase();
        if is_valid_mitm_host(&p) {
            mitm_positive.insert(p);
        }
    }

    for r in &overrides.url_rewrites {
        let mode = match r.mode.as_str() {
            "header" => UrlRewriteMode::Header,
            "302" => UrlRewriteMode::Redirect302,
            "307" => UrlRewriteMode::Redirect307,
            _ => UrlRewriteMode::Reject,
        };
        let info = extract_hosts_from_regex(&r.pattern);
        mitm_positive.extend(info.mitm_patterns);
        complex_host_set.extend(info.concrete_hosts);
        let rule = UrlRewriteRule {
            pattern: r.pattern.clone(),
            replacement: r.replacement.clone(),
            mode,
            weight: 200,
        };
        url_map.insert(rule.dedup_key(), rule);
    }

    for r in &overrides.map_locals {
        let data_type = match r.data_type.as_str() {
            "tiny-gif" => MapLocalDataType::TinyGif,
            "base64" => MapLocalDataType::Base64,
            _ => MapLocalDataType::Text,
        };
        let info = extract_hosts_from_regex(&r.pattern);
        mitm_positive.extend(info.mitm_patterns);
        complex_host_set.extend(info.concrete_hosts);
        let rule = MapLocalRule {
            pattern: r.pattern.clone(),
            data_type,
            data: r.data.clone(),
            status_code: r.status_code,
            header: r.header.clone(),
            weight: 200,
        };
        map_local_map.insert(rule.dedup_key(), rule);
    }

    for r in &overrides.header_rewrites {
        if r.field.eq_ignore_ascii_case("content-length")
            || r.field.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        let dir = if r.direction == "http-response" {
            HeaderDirection::HttpResponse
        } else {
            HeaderDirection::HttpRequest
        };
        let action = match r.action.as_str() {
            "header-add" => HeaderAction::HeaderAdd,
            "header-replace" => HeaderAction::HeaderReplace,
            "header-replace-regex" => HeaderAction::HeaderReplaceRegex,
            _ => HeaderAction::HeaderDel,
        };
        let info = extract_hosts_from_regex(&r.pattern);
        mitm_positive.extend(info.mitm_patterns);
        complex_host_set.extend(info.concrete_hosts);
        let rule = HeaderRewriteRule {
            direction: dir,
            pattern: r.pattern.clone(),
            action,
            field: r.field.clone(),
            value: r.value.clone(),
            replace_regex: r.replace_regex.clone(),
            weight: 200,
        };
        header_map.insert(rule.dedup_key(), rule);
    }

    for r in &overrides.body_rewrites {
        let kind = match r.kind.as_str() {
            "http-request" => BodyRewriteKind::HttpRequest,
            "http-response" => BodyRewriteKind::HttpResponse,
            "http-request-jq" => BodyRewriteKind::HttpRequestJq,
            _ => BodyRewriteKind::HttpResponseJq,
        };
        let info = extract_hosts_from_regex(&r.pattern);
        mitm_positive.extend(info.mitm_patterns);
        complex_host_set.extend(info.concrete_hosts);
        let rule = BodyRewriteRule {
            kind,
            pattern: r.pattern.clone(),
            expression: r.expression.clone(),
            replacement: r.replacement.clone(),
            weight: 200,
        };
        body_map.insert(rule.dedup_key(), rule);
    }

    for s in &overrides.scripts {
        script_candidates.push(script_override_to_rule(s));
        let info = extract_hosts_from_regex(&s.pattern);
        mitm_positive.extend(info.mitm_patterns);
        complex_host_set.extend(info.concrete_hosts);
    }
}

fn script_override_to_rule(s: &ModuleScriptOverride) -> ScriptRule {
    let st = if s.script_type == "http-request" {
        ScriptType::HttpRequest
    } else {
        ScriptType::HttpResponse
    };
    ScriptRule {
        name: s.name.clone(),
        script_type: st,
        pattern: s.pattern.clone(),
        script_path: s.script_path.clone(),
        requires_body: s.requires_body,
        binary_body_mode: s.binary_body_mode,
        full_header_mode: false,
        max_size: s.max_size,
        timeout: None,
        argument: s.argument.clone(),
        engine: None,
        weight: 200,
    }
}

fn fallback_rule_targets_survive(
    pattern: &str,
    disabled: &[String],
    mitm_exclusions: &BTreeSet<String>,
    final_suffix_trie: &DomainTrie,
    compressed_domains: &BTreeSet<String>,
) -> Option<Vec<String>> {
    if is_pattern_disabled(pattern, disabled) {
        return None;
    }
    if pattern_targets_excluded_https_only(pattern, mitm_exclusions) {
        return None;
    }
    let info = extract_hosts_from_regex(pattern);
    if info.mitm_patterns.is_empty() {
        return None;
    }
    let check_hosts: Vec<&str> = if !info.concrete_hosts.is_empty() {
        info.concrete_hosts.iter().map(String::as_str).collect()
    } else {
        info.mitm_patterns
            .iter()
            .map(|h| h.trim_start_matches("*."))
            .collect()
    };
    let all_blocked = !check_hosts.is_empty()
        && check_hosts
            .iter()
            .all(|h| final_suffix_trie.matches_domain(h) || compressed_domains.contains(*h));
    if all_blocked {
        return None;
    }
    let surviving_mitm: Vec<String> = info
        .mitm_patterns
        .into_iter()
        .map(|m| m.to_ascii_lowercase())
        .filter(|m| is_valid_mitm_host(m) && !mitm_host_is_excluded(m, mitm_exclusions))
        .collect();
    if surviving_mitm.is_empty() && !pattern.trim_start_matches('^').starts_with("http://") {
        return None;
    }
    Some(surviving_mitm)
}

fn percent_encode_uri_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 32);
    for b in raw.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn build_adguard_transform_scripts(mut rules: Vec<AdguardTransformRule>) -> Vec<ScriptRule> {
    if rules.is_empty() {
        return Vec::new();
    }

    // Higher-weight rules come first within each URL pattern while preserving stable op order
    rules.sort_by(|a, b| {
        a.pattern
            .cmp(&b.pattern)
            .then_with(|| b.weight.cmp(&a.weight))
    });

    let mut grouped: BTreeMap<String, (u16, Vec<AdguardTransformOp>)> = BTreeMap::new();
    for r in rules {
        let entry = grouped
            .entry(r.pattern)
            .or_insert_with(|| (r.weight, Vec::new()));
        entry.0 = entry.0.max(r.weight);
        if !entry.1.contains(&r.op) {
            entry.1.push(r.op);
        }
    }

    let mut out = Vec::with_capacity(grouped.len());
    for (idx, (pattern, (weight, mut ops))) in grouped.into_iter().enumerate() {
        let mut encoded_arg = None;
        while !ops.is_empty() {
            if let Ok(json) = serde_json::to_string(&ops) {
                let candidate = format!("u:{}", percent_encode_uri_component(&json));
                if candidate.len() <= 3800 || (ops.len() == 1 && candidate.len() <= 7600) {
                    encoded_arg = Some(candidate);
                    break;
                }
            }
            ops.pop();
        }
        let Some(argument) = encoded_arg else {
            continue;
        };
        out.push(ScriptRule {
            name: format!("surge-adguard-{}", idx + 1),
            script_type: ScriptType::HttpResponse,
            pattern,
            script_path: ADGUARD_SCRIPT_URL.to_string(),
            requires_body: true,
            binary_body_mode: false,
            full_header_mode: false,
            max_size: Some(524_288),
            timeout: Some(5),
            argument: Some(argument),
            engine: Some("jsc".to_string()),
            weight,
        });
    }

    out
}

fn resolve_script_conflicts(
    mut candidates: Vec<ScriptRule>,
    short_circuit_response_keys: &HashMap<String, u16>,
) -> Vec<ScriptRule> {
    for c in &mut candidates {
        c.normalize_runtime_bounds();
    }

    candidates.sort_by(|a, b| {
        b.weight
            .cmp(&a.weight)
            .then_with(|| a.script_type.cmp(&b.script_type))
            .then_with(|| a.pattern.cmp(&b.pattern))
            .then_with(|| a.name.cmp(&b.name))
    });

    let mut seen_triggers: HashMap<(ScriptType, String), usize> = HashMap::new();
    let mut accepted_req_regexes: Vec<Regex> = Vec::new();
    let mut accepted_resp_regexes: Vec<Regex> = Vec::new();
    let mut kept: Vec<ScriptRule> = Vec::new();

    for s in candidates {
        let tkey = s.trigger_key();
        if s.script_type == ScriptType::HttpResponse
            && short_circuit_response_keys
                .get(&tkey.1)
                .is_some_and(|&sc_w| sc_w >= s.weight)
        {
            continue;
        }
        if let Some(&winner_idx) = seen_triggers.get(&tkey) {
            if s.pattern.starts_with("^https?://")
                && let Some(rest) = kept[winner_idx].pattern.strip_prefix("^https://")
            {
                kept[winner_idx].pattern = format!("^https?://{}", rest);
            }
            continue;
        }

        let prior_regexes = match s.script_type {
            ScriptType::HttpRequest => &accepted_req_regexes,
            ScriptType::HttpResponse => &accepted_resp_regexes,
        };
        let samples = sample_urls_for_regex_subsumption(&s.pattern);
        if !samples.is_empty()
            && !prior_regexes.is_empty()
            && samples
                .iter()
                .all(|url| prior_regexes.iter().any(|re| re.is_match(url)))
        {
            continue;
        }

        let probe = s.pattern.replace("(?>", "(?:");
        if let Ok(re) = Regex::new(&probe) {
            match s.script_type {
                ScriptType::HttpRequest => accepted_req_regexes.push(re),
                ScriptType::HttpResponse => accepted_resp_regexes.push(re),
            }
        }
        seen_triggers.insert(tkey, kept.len());
        kept.push(s);
    }

    // Sort output stably by (weight desc, name, pattern) so higher-authority scripts evaluate first
    kept.sort_by_key(|s| {
        (
            Reverse(s.weight),
            s.script_type,
            s.pattern.clone(),
            s.name.clone(),
        )
    });

    let mut used_names: FxHashSet<String> = FxHashSet::default();
    for s in &mut kept {
        let base = if s.name.starts_with("surge-removeparam") {
            format!("{}_custom", s.name)
        } else {
            s.name.clone()
        };
        let mut candidate = base.clone();
        let mut idx = 2usize;
        while !used_names.insert(candidate.clone()) {
            candidate = format!("{}_{}", base, idx);
            idx += 1;
        }
        s.name = candidate;
    }

    kept
}

fn pattern_targets_excluded_https_only(pattern: &str, exclusions: &BTreeSet<String>) -> bool {
    let bare = pattern.trim_start_matches('^');
    if bare.starts_with("http://") {
        return false;
    }
    let info = extract_hosts_from_regex(pattern);
    !info.mitm_patterns.is_empty()
        && info
            .mitm_patterns
            .iter()
            .all(|h| mitm_host_is_excluded(h, exclusions))
}

fn is_safe_global_tracking_param(param: &str) -> bool {
    let trimmed = param.trim();
    if trimmed.is_empty() || trimmed == "*" {
        return false;
    }
    if let Some(rest) = trimmed.strip_prefix('~') {
        let Some((_flags, encoded)) = rest.split_once(':') else {
            return false;
        };
        let lower = encoded.to_ascii_lowercase();
        return lower.starts_with("%5eutm_")
            || lower.starts_with("%5emtm_")
            || lower.starts_with("%5epk_")
            || lower.starts_with("%5ehsa_")
            || lower.starts_with("%5ematomo_");
    }
    let p = trimmed.to_ascii_lowercase();
    const SAFE_PREFIXES: &[&str] = &[
        "utm_", "stm_", "hsa_", "mtm_", "pk_", "piwik_", "matomo_", "mc_", "oly_", "_ga", "__utm",
        "__hs", "spm_", "scm_",
    ];
    if SAFE_PREFIXES.iter().any(|pre| p.starts_with(pre)) {
        return true;
    }
    matches!(
        p.as_str(),
        "fbclid"
            | "gclid"
            | "gbraid"
            | "wbraid"
            | "dclid"
            | "msclkid"
            | "ttclid"
            | "twclid"
            | "tgclid"
            | "li_fat_id"
            | "yclid"
            | "ymclid"
            | "_openstat"
            | "igshid"
            | "igsh"
            | "wickedid"
            | "vero_conv"
            | "vero_id"
            | "nr_email_referer"
            | "mkt_tok"
            | "rb_clickid"
            | "s_kwcid"
            | "ef_id"
            | "epik"
            | "irclickid"
            | "guce_referrer"
            | "guce_referrer_sig"
            | "vd_source"
            | "srsltid"
            | "share_source"
            | "share_medium"
            | "share_plat"
            | "share_session_id"
            | "share_tag"
            | "_hsenc"
            | "_hsmi"
            | "_bta_tid"
            | "_bta_c"
            | "_ke"
            | "_kx"
    )
}

fn global_param_trigger_atom(token: &str) -> String {
    if let Some(rest) = token.strip_prefix('~')
        && let Some((_flags, encoded)) = rest.split_once(':')
    {
        let lower = encoded.to_ascii_lowercase();
        if lower.starts_with("%5eutm_") {
            return "(?:utm|UTM)_[^=&#]*".to_string();
        }
        if lower.starts_with("%5emtm_") {
            return "(?:mtm|MTM)_[^=&#]*".to_string();
        }
        if lower.starts_with("%5epk_") {
            return "(?:pk|PK)_[^=&#]*".to_string();
        }
        if lower.starts_with("%5ehsa_") {
            return "(?:hsa|HSA)_[^=&#]*".to_string();
        }
        if lower.starts_with("%5ematomo_") {
            return "(?:matomo|MATOMO)_[^=&#]*".to_string();
        }
    }
    crate::adblock::regex_util::escape_literal_regex(token)
}

fn host_scope_to_regex(host: &str) -> String {
    if let Some(suf) = host.strip_prefix("*.") {
        format!(
            "[^/?#]+\\.{}",
            crate::adblock::regex_util::escape_literal_regex(suf)
        )
    } else {
        format!(
            "(?:[^/?#]+\\.)?{}",
            crate::adblock::regex_util::escape_literal_regex(host)
        )
    }
}

fn normalize_removeparam_token(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed == "*" || trimmed.starts_with('~') {
        trimmed.to_string()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

fn build_removeparam_scripts(
    rules: &[RemoveParamRule],
    exceptions: &[(String, String)],
    mitm_positive: &mut BTreeSet<String>,
    mitm_exclusion_set: &BTreeSet<String>,
    final_suffix_trie: &DomainTrie,
    compressed_domains: &BTreeSet<String>,
) -> Vec<ScriptRule> {
    if rules.is_empty() {
        return Vec::new();
    }

    let mut exempt_map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (raw_host, raw_tok) in exceptions {
        let host = raw_host.trim().trim_end_matches('.').to_ascii_lowercase();
        let tok = normalize_removeparam_token(raw_tok);
        if tok.is_empty()
            || !is_valid_mitm_host(&host)
            || final_suffix_trie.matches_domain(&host)
            || compressed_domains.contains(&host)
        {
            continue;
        }
        exempt_map.entry(host).or_default().insert(tok);
    }

    let mut global_params: BTreeMap<String, u16> = BTreeMap::new();
    let mut scope_params: BTreeMap<String, (u16, BTreeSet<String>)> = BTreeMap::new();

    for r in rules {
        let param_clean = normalize_removeparam_token(&r.param);
        if param_clean.is_empty() {
            continue;
        }
        let host = r.host_scope.trim().to_ascii_lowercase();
        if host == "*" {
            if is_safe_global_tracking_param(&param_clean) {
                let entry = global_params.entry(param_clean).or_insert(r.weight);
                *entry = (*entry).max(r.weight);
            }
            continue;
        }
        if !is_valid_mitm_host(&host)
            || mitm_host_is_excluded(&host, mitm_exclusion_set)
            || final_suffix_trie.matches_domain(&host)
            || compressed_domains.contains(&host)
        {
            continue;
        }
        if let Some(ex_set) = exempt_map.get(&host)
            && (ex_set.contains("*") || ex_set.contains(&param_clean))
        {
            continue;
        }
        let entry = scope_params
            .entry(host)
            .or_insert_with(|| (r.weight, BTreeSet::new()));
        entry.0 = entry.0.max(r.weight);
        entry.1.insert(param_clean);
    }

    let mut scripts = Vec::new();

    if !global_params.is_empty() {
        let mut ranked_global: Vec<(String, u16)> = global_params.into_iter().collect();
        ranked_global.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        let mut selected_global = Vec::new();
        let mut arg_len = 2usize; // `*=`
        for (p, _) in ranked_global {
            let add_len = if selected_global.is_empty() {
                p.len()
            } else {
                p.len() + 1
            };
            if selected_global.len() >= 120 || arg_len + add_len > 2800 {
                break;
            }
            arg_len += add_len;
            selected_global.push(p);
        }

        if !selected_global.is_empty() {
            selected_global.sort();
            let has_global_regex = selected_global.iter().any(|t| t.starts_with('~'));
            let selected_set: BTreeSet<&str> = selected_global.iter().map(String::as_str).collect();

            let mut arg_parts = vec![format!("*={}", selected_global.join("|"))];
            let mut cur_len = arg_parts[0].len();
            for (ex_host, ex_toks) in &exempt_map {
                let relevant: Vec<&str> = if ex_toks.contains("*") {
                    vec!["*"]
                } else {
                    ex_toks
                        .iter()
                        .map(String::as_str)
                        .filter(|t| selected_set.contains(t) || has_global_regex)
                        .collect()
                };
                if relevant.is_empty() {
                    continue;
                }
                let ex_chunk = format!("-{}={}", ex_host, relevant.join("|"));
                if cur_len + 1 + ex_chunk.len() > 3500 {
                    break;
                }
                cur_len += 1 + ex_chunk.len();
                arg_parts.push(ex_chunk);
            }

            let mut trigger_atoms: Vec<String> = selected_global
                .iter()
                .map(|k| global_param_trigger_atom(k))
                .collect();
            trigger_atoms.sort();
            trigger_atoms.dedup();
            let pattern = format!(
                "^https?://[^?#]+\\?(?:[^#]*&)?(?:{})=",
                trigger_atoms.join("|")
            );
            scripts.push(ScriptRule {
                name: "surge-removeparam".to_string(),
                script_type: ScriptType::HttpRequest,
                pattern,
                script_path: REMOVEPARAM_SCRIPT_URL.to_string(),
                requires_body: false,
                binary_body_mode: false,
                full_header_mode: false,
                max_size: None,
                timeout: Some(5),
                argument: Some(arg_parts.join(";")),
                engine: Some("jsc".to_string()),
                weight: 1,
            });
        }
    }

    if !scope_params.is_empty() {
        let bulk_mode = scope_params.len() > 32;
        let mut all_ranked: Vec<(String, u16, BTreeSet<String>)> = scope_params
            .into_iter()
            .map(|(host, (w, params))| (host, w, params))
            .collect();
        all_ranked.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| b.2.len().cmp(&a.2.len()))
                .then_with(|| a.0.cmp(&b.0))
        });

        let mut extra_mitm_budget = 24usize;
        let mut ranked_scopes: Vec<(String, u16, BTreeSet<String>, bool)> = Vec::new();
        for (host, w, params) in all_ranked {
            if !bulk_mode {
                ranked_scopes.push((host, w, params, true));
            } else if mitm_host_is_excluded(&host, mitm_positive) {
                ranked_scopes.push((host, w, params, false));
            } else if w >= 130 && extra_mitm_budget > 0 {
                extra_mitm_budget -= 1;
                ranked_scopes.push((host, w, params, true));
            }
        }

        let mut cursor = 0usize;
        for shard_idx in 0..3usize {
            if cursor >= ranked_scopes.len() {
                break;
            }
            let mut arg_chunks: Vec<String> = Vec::new();
            let mut total_arg_len = 0usize;
            let mut active_hosts: BTreeSet<String> = BTreeSet::new();
            let mut active_literals: BTreeSet<String> = BTreeSet::new();
            let mut has_wildcard_or_regex_param = false;

            while cursor < ranked_scopes.len() {
                let (ref host, _, ref params, add_mitm) = ranked_scopes[cursor];
                let param_list: Vec<String> = if params.contains("*") {
                    vec!["*".to_string()]
                } else {
                    params.iter().take(24).cloned().collect()
                };
                let new_literals: Vec<&String> = param_list
                    .iter()
                    .filter(|p| *p != "*" && !p.starts_with('~'))
                    .collect();
                if active_literals.len() + new_literals.len() > 120 && !active_hosts.is_empty() {
                    break;
                }
                let chunk = format!("{}={}", host, param_list.join("|"));
                if total_arg_len + chunk.len() + 1 > 3200 && !arg_chunks.is_empty() {
                    break;
                }
                if add_mitm {
                    mitm_positive.insert(host.clone());
                }
                if param_list.iter().any(|p| p == "*" || p.starts_with('~')) {
                    has_wildcard_or_regex_param = true;
                }
                for lit in new_literals {
                    active_literals.insert(lit.clone());
                }
                total_arg_len += chunk.len() + 1;
                active_hosts.insert(host.clone());
                arg_chunks.push(chunk);
                cursor += 1;
            }

            if arg_chunks.is_empty() || active_hosts.is_empty() {
                break;
            }

            // Attach host-level exemptions matching any host in this shard
            for (ex_host, ex_toks) in &exempt_map {
                if mitm_host_is_excluded(ex_host, &active_hosts) {
                    let ex_list: Vec<&str> = ex_toks.iter().map(String::as_str).collect();
                    let ex_chunk = format!("-{}={}", ex_host, ex_list.join("|"));
                    if total_arg_len + ex_chunk.len() < 3500 {
                        total_arg_len += ex_chunk.len() + 1;
                        arg_chunks.push(ex_chunk);
                    }
                }
            }

            let host_atoms: Vec<String> = active_hosts
                .iter()
                .map(|h| host_scope_to_regex(h))
                .collect();
            let pattern = if has_wildcard_or_regex_param || active_literals.is_empty() {
                format!(
                    "^https?://(?:{})(?::\\d+)?(?:/[^?#]*)?\\?[^#]+",
                    host_atoms.join("|")
                )
            } else {
                let escaped_keys: Vec<String> = active_literals
                    .iter()
                    .map(|k| crate::adblock::regex_util::escape_literal_regex(k))
                    .collect();
                format!(
                    "^https?://(?:{})(?::\\d+)?(?:/[^?#]*)?\\?(?:[^#]*&)?(?:{})=",
                    host_atoms.join("|"),
                    escaped_keys.join("|")
                )
            };
            let script_name = if shard_idx == 0 {
                "surge-removeparam-scoped".to_string()
            } else {
                format!("surge-removeparam-scoped-{}", shard_idx + 1)
            };
            scripts.push(ScriptRule {
                name: script_name,
                script_type: ScriptType::HttpRequest,
                pattern,
                script_path: REMOVEPARAM_SCRIPT_URL.to_string(),
                requires_body: false,
                binary_body_mode: false,
                full_header_mode: false,
                max_size: None,
                timeout: Some(5),
                argument: Some(arg_chunks.join(";")),
                engine: Some("jsc".to_string()),
                weight: 1,
            });
        }
    }

    scripts
}

#[derive(serde::Serialize)]
struct HeaderRuntimeOp {
    op: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    exact: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    regexes: Vec<(String, String)>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    all: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    policies: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hosts: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    exc: BTreeMap<String, Vec<String>>,
}

fn split_cookie_token_for_runtime(tok: &str) -> Option<Result<String, (String, String)>> {
    if let Some(rest) = tok.strip_prefix('~') {
        let (flags, pat) = rest.split_once(':')?;
        if pat.is_empty() {
            return None;
        }
        Some(Err((pat.to_string(), flags.to_string())))
    } else if !tok.is_empty() && tok != "*" {
        Some(Ok(tok.to_string()))
    } else {
        None
    }
}

fn is_exempted_by_host_map(
    host: &str,
    spec: &str,
    exc_map: &BTreeMap<String, BTreeSet<String>>,
) -> bool {
    let mut cur = host;
    while !cur.is_empty() {
        if let Some(set) = exc_map.get(cur)
            && (set.contains("*") || set.contains(spec))
        {
            return true;
        }
        match cur.find('.') {
            Some(idx) => cur = &cur[idx + 1..],
            None => break,
        }
    }
    false
}

fn collect_relevant_exceptions(
    exc_map: &BTreeMap<String, BTreeSet<String>>,
    active_hosts: Option<&BTreeSet<String>>,
    max_entries: usize,
) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (scope, specs) in exc_map {
        if out.len() >= max_entries {
            break;
        }
        let include = match active_hosts {
            None => true,
            Some(hosts) => {
                if scope.starts_with('^') {
                    let info = extract_hosts_from_regex(scope);
                    info.concrete_hosts
                        .iter()
                        .any(|ch| mitm_host_is_excluded(ch, hosts))
                } else {
                    mitm_host_is_excluded(scope, hosts)
                }
            }
        };
        if include {
            let list: Vec<String> = if specs.contains("*") {
                vec!["*".to_string()]
            } else {
                specs.iter().take(12).cloned().collect()
            };
            if !list.is_empty() {
                out.insert(scope.clone(), list);
            }
        }
    }
    out
}

fn encode_header_ops_arg(ops: &[HeaderRuntimeOp]) -> Option<String> {
    if ops.is_empty() {
        return None;
    }
    let json = serde_json::to_string(ops).ok()?;
    let encoded = format!("u:{}", percent_encode_uri_component(&json));
    if encoded.len() <= 7600 {
        Some(encoded)
    } else {
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn build_header_modifier_scripts(
    rules: &[HeaderModRule],
    exceptions: &[HeaderModException],
    protected_apex_set: &FxHashSet<String>,
    mitm_positive: &mut BTreeSet<String>,
    mitm_exclusion_set: &BTreeSet<String>,
    final_suffix_trie: &DomainTrie,
    compressed_domains: &BTreeSet<String>,
) -> Vec<ScriptRule> {
    if rules.is_empty() {
        return Vec::new();
    }

    let mut cookie_exc: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut csp_exc: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut perm_exc: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for ex in exceptions {
        let key = if ex.scope_key.starts_with('^') {
            ex.scope_key.clone()
        } else {
            ex.scope_key
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase()
        };
        if key.is_empty() || ex.spec.is_empty() {
            continue;
        }
        match ex.kind {
            HeaderModKind::Cookie => {
                cookie_exc.entry(key).or_default().insert(ex.spec.clone());
            }
            HeaderModKind::Csp => {
                csp_exc.entry(key).or_default().insert(ex.spec.clone());
            }
            HeaderModKind::Permissions => {
                perm_exc.entry(key).or_default().insert(ex.spec.clone());
            }
        }
    }

    let mut global_cookies: BTreeMap<String, u16> = BTreeMap::new();
    let mut global_perms: BTreeSet<String> = BTreeSet::new();
    let mut scoped_cookies: BTreeMap<String, (u16, BTreeSet<String>)> = BTreeMap::new();
    let mut scoped_csp: BTreeMap<String, (u16, BTreeSet<String>)> = BTreeMap::new();
    let mut scoped_perms: BTreeMap<String, (u16, BTreeSet<String>)> = BTreeMap::new();

    for r in rules {
        let host = r
            .host_scope
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if host == "*" {
            match r.kind {
                HeaderModKind::Cookie
                    if r.spec != "*"
                        && !matches!(r.spec.as_str(), "DSID" | "actppresence" | "SID" | "HSID") =>
                {
                    let e = global_cookies.entry(r.spec.clone()).or_insert(r.weight);
                    *e = (*e).max(r.weight);
                }
                HeaderModKind::Permissions => {
                    global_perms.insert(r.spec.clone());
                }
                _ => {}
            }
            continue;
        }

        if !is_valid_mitm_host(&host)
            || mitm_host_is_excluded(&host, mitm_exclusion_set)
            || final_suffix_trie.matches_domain(&host)
            || compressed_domains.contains(&host)
        {
            continue;
        }

        match r.kind {
            HeaderModKind::Cookie => {
                if !is_exempted_by_host_map(&host, &r.spec, &cookie_exc) {
                    let entry = scoped_cookies
                        .entry(host)
                        .or_insert_with(|| (r.weight, BTreeSet::new()));
                    entry.0 = entry.0.max(r.weight);
                    entry.1.insert(r.spec.clone());
                }
            }
            HeaderModKind::Csp => {
                if !is_exempted_by_host_map(&host, &r.spec, &csp_exc) {
                    let entry = scoped_csp
                        .entry(host)
                        .or_insert_with(|| (r.weight, BTreeSet::new()));
                    entry.0 = entry.0.max(r.weight);
                    entry.1.insert(r.spec.clone());
                }
            }
            HeaderModKind::Permissions => {
                if !is_exempted_by_host_map(&host, &r.spec, &perm_exc) {
                    let entry = scoped_perms
                        .entry(host)
                        .or_insert_with(|| (r.weight, BTreeSet::new()));
                    entry.0 = entry.0.max(r.weight);
                    entry.1.insert(r.spec.clone());
                }
            }
        }
    }

    let mut scripts: Vec<ScriptRule> = Vec::new();
    let mut mitm_budget = 160usize;

    // 1. Host-scoped `$cookie` request shards (`http-request` only, header-only `requires-body=false`)
    if !scoped_cookies.is_empty() {
        let mut ranked: Vec<(String, u16, BTreeSet<String>)> = scoped_cookies
            .iter()
            .map(|(h, (w, specs))| (h.clone(), *w, specs.clone()))
            .collect();
        ranked.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| b.2.len().cmp(&a.2.len()))
                .then_with(|| a.0.cmp(&b.0))
        });

        let mut cursor = 0usize;
        for shard_idx in 0..8usize {
            if cursor >= ranked.len() {
                break;
            }
            let mut ops: Vec<HeaderRuntimeOp> = Vec::new();
            let mut active_hosts: BTreeSet<String> = BTreeSet::new();
            let mut est_json_bytes = 2usize;

            while cursor < ranked.len() && active_hosts.len() < 32 {
                let (ref host, _, ref specs) = ranked[cursor];
                let all = specs.contains("*");
                let mut exact = Vec::new();
                let mut regexes = Vec::new();
                if !all {
                    for s in specs.iter().take(16) {
                        if let Some(parsed) = split_cookie_token_for_runtime(s) {
                            match parsed {
                                Ok(lit) => exact.push(lit),
                                Err(re_pair) => regexes.push(re_pair),
                            }
                        }
                    }
                }
                if !all && exact.is_empty() && regexes.is_empty() {
                    cursor += 1;
                    continue;
                }
                let mut host_btree = BTreeSet::new();
                host_btree.insert(host.clone());
                let exc = collect_relevant_exceptions(&cookie_exc, Some(&host_btree), 8);
                let op = HeaderRuntimeOp {
                    op: "cookie",
                    exact,
                    regexes,
                    all,
                    policies: Vec::new(),
                    hosts: vec![host.clone()],
                    exc,
                };
                let op_len = serde_json::to_string(&op).map(|s| s.len()).unwrap_or(9999);
                if est_json_bytes + op_len * 2 > 5400 && !ops.is_empty() {
                    break;
                }
                est_json_bytes += op_len * 2;
                if !protected_apex_set.contains(host)
                    && mitm_budget > 0
                    && mitm_positive.insert(host.clone())
                {
                    mitm_budget -= 1;
                }
                active_hosts.insert(host.clone());
                ops.push(op);
                cursor += 1;
            }

            if let Some(arg) = encode_header_ops_arg(&ops)
                && !active_hosts.is_empty()
            {
                let host_atoms: Vec<String> = active_hosts
                    .iter()
                    .map(|h| host_scope_to_regex(h))
                    .collect();
                let pattern = format!("^https?://(?:{})(?::\\d+)?(?:/|$)", host_atoms.join("|"));
                scripts.push(ScriptRule {
                    name: format!("surge-adguard-cookie-req-{}", shard_idx + 1),
                    script_type: ScriptType::HttpRequest,
                    pattern,
                    script_path: ADGUARD_SCRIPT_URL.to_string(),
                    requires_body: false,
                    binary_body_mode: false,
                    full_header_mode: true,
                    max_size: None,
                    timeout: Some(5),
                    argument: Some(arg),
                    engine: Some("jsc".to_string()),
                    weight: 2,
                });
            }
        }
    }

    // 2. Unified host-scoped `$cookie` + `$csp` + `$permissions` response shards (`http-response`, header-only `requires-body=false`)
    //    Combining all response header ops per host avoids first-match shadowing and duplicate trigger patterns.
    let mut all_resp_hosts: BTreeSet<String> = scoped_cookies.keys().cloned().collect();
    all_resp_hosts.extend(scoped_csp.keys().cloned());
    all_resp_hosts.extend(scoped_perms.keys().cloned());
    if !all_resp_hosts.is_empty() {
        let mut ranked_hosts: Vec<(String, u16)> = all_resp_hosts
            .into_iter()
            .map(|h| {
                let w0 = scoped_cookies.get(&h).map(|x| x.0).unwrap_or(0);
                let w1 = scoped_csp.get(&h).map(|x| x.0).unwrap_or(0);
                let w2 = scoped_perms.get(&h).map(|x| x.0).unwrap_or(0);
                (h, w0.max(w1).max(w2))
            })
            .collect();
        ranked_hosts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        let mut cursor = 0usize;
        for shard_idx in 0..12usize {
            if cursor >= ranked_hosts.len() {
                break;
            }
            let mut ops: Vec<HeaderRuntimeOp> = Vec::new();
            let mut active_hosts: BTreeSet<String> = BTreeSet::new();
            let mut est_json_bytes = 2usize;

            while cursor < ranked_hosts.len() && active_hosts.len() < 28 {
                let (ref host, _) = ranked_hosts[cursor];
                let mut host_set = BTreeSet::new();
                host_set.insert(host.clone());
                let mut host_ops = Vec::new();

                if let Some((_, specs)) = scoped_cookies.get(host) {
                    let all = specs.contains("*");
                    let mut exact = Vec::new();
                    let mut regexes = Vec::new();
                    if !all {
                        for s in specs.iter().take(16) {
                            if let Some(parsed) = split_cookie_token_for_runtime(s) {
                                match parsed {
                                    Ok(lit) => exact.push(lit),
                                    Err(re_pair) => regexes.push(re_pair),
                                }
                            }
                        }
                    }
                    if all || !exact.is_empty() || !regexes.is_empty() {
                        host_ops.push(HeaderRuntimeOp {
                            op: "cookie",
                            exact,
                            regexes,
                            all,
                            policies: Vec::new(),
                            hosts: vec![host.clone()],
                            exc: collect_relevant_exceptions(&cookie_exc, Some(&host_set), 8),
                        });
                    }
                }
                if let Some((_, csp_set)) = scoped_csp.get(host) {
                    host_ops.push(HeaderRuntimeOp {
                        op: "csp",
                        exact: Vec::new(),
                        regexes: Vec::new(),
                        all: false,
                        policies: csp_set.iter().take(4).cloned().collect(),
                        hosts: vec![host.clone()],
                        exc: collect_relevant_exceptions(&csp_exc, Some(&host_set), 6),
                    });
                }
                if let Some((_, perm_set)) = scoped_perms.get(host) {
                    host_ops.push(HeaderRuntimeOp {
                        op: "permissions",
                        exact: Vec::new(),
                        regexes: Vec::new(),
                        all: false,
                        policies: perm_set.iter().take(6).cloned().collect(),
                        hosts: vec![host.clone()],
                        exc: collect_relevant_exceptions(&perm_exc, Some(&host_set), 6),
                    });
                }

                if host_ops.is_empty() {
                    cursor += 1;
                    continue;
                }
                let add_bytes: usize = host_ops
                    .iter()
                    .map(|o| {
                        serde_json::to_string(o)
                            .map(|s| s.len() * 2)
                            .unwrap_or(9999)
                    })
                    .sum();
                if est_json_bytes + add_bytes > 5200 && !ops.is_empty() {
                    break;
                }
                est_json_bytes += add_bytes;
                if !protected_apex_set.contains(host)
                    && mitm_budget > 0
                    && mitm_positive.insert(host.clone())
                {
                    mitm_budget -= 1;
                }
                active_hosts.insert(host.clone());
                ops.extend(host_ops);
                cursor += 1;
            }

            if let Some(arg) = encode_header_ops_arg(&ops)
                && !active_hosts.is_empty()
            {
                let host_atoms: Vec<String> = active_hosts
                    .iter()
                    .map(|h| host_scope_to_regex(h))
                    .collect();
                let pattern = format!("^https?://(?:{})(?::\\d+)?(?:/|$)", host_atoms.join("|"));
                scripts.push(ScriptRule {
                    name: format!("surge-adguard-policy-resp-{}", shard_idx + 1),
                    script_type: ScriptType::HttpResponse,
                    pattern,
                    script_path: ADGUARD_SCRIPT_URL.to_string(),
                    requires_body: false,
                    binary_body_mode: false,
                    full_header_mode: true,
                    max_size: None,
                    timeout: Some(5),
                    argument: Some(arg),
                    engine: Some("jsc".to_string()),
                    weight: 2,
                });
            }
        }
    }

    // 3. Global tracking `$cookie` & privacy `$permissions` fallback header scripts (`requires-body=false`)
    let mut global_exact = Vec::new();
    let mut global_regexes = Vec::new();
    let mut ranked_gc: Vec<(String, u16)> = global_cookies.into_iter().collect();
    ranked_gc.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (tok, _) in ranked_gc.into_iter().take(160) {
        if let Some(parsed) = split_cookie_token_for_runtime(&tok) {
            match parsed {
                Ok(lit) => global_exact.push(lit),
                Err(re_pair) => global_regexes.push(re_pair),
            }
        }
    }

    let global_cookie_exc = collect_relevant_exceptions(&cookie_exc, None, 48);
    let global_perm_exc = collect_relevant_exceptions(&perm_exc, None, 24);

    if !global_exact.is_empty() || !global_regexes.is_empty() {
        let req_op = HeaderRuntimeOp {
            op: "cookie",
            exact: global_exact.clone(),
            regexes: global_regexes.clone(),
            all: false,
            policies: Vec::new(),
            hosts: Vec::new(),
            exc: global_cookie_exc.clone(),
        };
        if let Some(arg) = encode_header_ops_arg(&[req_op]) {
            scripts.push(ScriptRule {
                name: "surge-adguard-global-req-headers".to_string(),
                script_type: ScriptType::HttpRequest,
                pattern: "^https?://.+".to_string(),
                script_path: ADGUARD_SCRIPT_URL.to_string(),
                requires_body: false,
                binary_body_mode: false,
                full_header_mode: true,
                max_size: None,
                timeout: Some(5),
                argument: Some(arg),
                engine: Some("jsc".to_string()),
                weight: 1,
            });
        }
    }

    let mut resp_global_ops = Vec::new();
    if !global_exact.is_empty() || !global_regexes.is_empty() {
        resp_global_ops.push(HeaderRuntimeOp {
            op: "cookie",
            exact: global_exact,
            regexes: global_regexes,
            all: false,
            policies: Vec::new(),
            hosts: Vec::new(),
            exc: global_cookie_exc,
        });
    }
    if !global_perms.is_empty() {
        resp_global_ops.push(HeaderRuntimeOp {
            op: "permissions",
            exact: Vec::new(),
            regexes: Vec::new(),
            all: false,
            policies: global_perms.into_iter().take(16).collect(),
            hosts: Vec::new(),
            exc: global_perm_exc,
        });
    }
    if let Some(arg) = encode_header_ops_arg(&resp_global_ops) {
        scripts.push(ScriptRule {
            name: "surge-adguard-global-resp-headers".to_string(),
            script_type: ScriptType::HttpResponse,
            pattern: "^https?://.+".to_string(),
            script_path: ADGUARD_SCRIPT_URL.to_string(),
            requires_body: false,
            binary_body_mode: false,
            full_header_mode: true,
            max_size: None,
            timeout: Some(5),
            argument: Some(arg),
            engine: Some("jsc".to_string()),
            weight: 1,
        });
    }

    scripts
}

fn mitm_host_is_excluded(host: &str, exclusions: &BTreeSet<String>) -> bool {
    let bare = host
        .split(':')
        .next()
        .unwrap_or(host)
        .trim_start_matches("*.")
        .trim_end_matches(".*");
    for ex in exclusions {
        if ex == host || ex == bare {
            return true;
        }
        if let Some(ex_suffix) = ex.strip_prefix("*.")
            && (bare == ex_suffix || bare.ends_with(&format!(".{}", ex_suffix)))
        {
            return true;
        }
    }
    false
}

pub fn wildcard_matches_domain(wildcard: &str, domain: &str) -> bool {
    if !wildcard.contains('*') && !wildcard.contains('?') {
        return wildcard == domain;
    }
    let w: Vec<u8> = wildcard.bytes().collect();
    let d: Vec<u8> = domain.bytes().collect();
    let (mut wi, mut di) = (0usize, 0usize);
    let (mut star_w, mut match_d) = (None, 0usize);

    while di < d.len() {
        if wi < w.len() && (w[wi] == b'?' || w[wi] == d[di]) {
            wi += 1;
            di += 1;
        } else if wi < w.len() && w[wi] == b'*' {
            star_w = Some(wi);
            match_d = di;
            wi += 1;
        } else if let Some(sw) = star_w {
            wi = sw + 1;
            match_d += 1;
            di = match_d;
        } else {
            return false;
        }
    }
    while wi < w.len() && w[wi] == b'*' {
        wi += 1;
    }
    wi == w.len()
}

pub fn overlaps_reserved_v4(net: Ipv4Net) -> bool {
    const RESERVED_V4: &[(u32, u8)] = &[
        (0x0000_0000, 8),  // 0.0.0.0/8
        (0x0A00_0000, 8),  // 10.0.0.0/8
        (0x6440_0000, 10), // 100.64.0.0/10 (CGNAT + Tailscale + Cloudflare Mesh)
        (0x7F00_0000, 8),  // 127.0.0.0/8
        (0xA9FE_0000, 16), // 169.254.0.0/16
        (0xAC10_0000, 12), // 172.16.0.0/12
        (0xC000_0000, 24), // 192.0.0.0/24
        (0xC000_0200, 24), // 192.0.2.0/24
        (0xC0A8_0000, 16), // 192.168.0.0/16
        (0xC612_0000, 15), // 198.18.0.0/15 (Benchmarking / Surge Fake-IP)
        (0xC633_6400, 24), // 198.51.100.0/24
        (0xCB00_7100, 24), // 203.0.113.0/24
        (0xE000_0000, 4),  // 224.0.0.0/4
        (0xF000_0000, 4),  // 240.0.0.0/4
    ];
    let s1 = u32::from(net.network());
    let e1 = u32::from(net.broadcast());
    RESERVED_V4.iter().any(|&(base, pfx)| {
        let mask = if pfx == 0 { 0 } else { u32::MAX << (32 - pfx) };
        let s2 = base & mask;
        let e2 = s2 | !mask;
        s1 <= e2 && s2 <= e1
    })
}

pub fn overlaps_reserved_v6(net: Ipv6Net) -> bool {
    const RESERVED_V6: &[(u128, u8)] = &[
        (0, 128),                                        // ::/128
        (1, 128),                                        // ::1/128
        (0x0000_ffff_0000_0000, 96),                     // ::ffff:0:0/96
        (0x2001_0db8_0000_0000_0000_0000_0000_0000, 32), // 2001:db8::/32
        (0xfc00_0000_0000_0000_0000_0000_0000_0000, 7), // fc00::/7 (ULA / Tailscale / ZeroTier / CF Mesh)
        (0xfe80_0000_0000_0000_0000_0000_0000_0000, 10), // fe80::/10
        (0xff00_0000_0000_0000_0000_0000_0000_0000, 8), // ff00::/8
    ];
    let s1 = u128::from(net.network());
    let e1 = u128::from(net.broadcast());
    RESERVED_V6.iter().any(|&(base, pfx)| {
        let mask = if pfx == 0 {
            0
        } else {
            u128::MAX << (128 - pfx)
        };
        let s2 = base & mask;
        let e2 = s2 | !mask;
        s1 <= e2 && s2 <= e1
    })
}

/// Prevents shared Anycast CDNs, public DNS resolvers, and core OS infrastructure from being
/// whole-prefix blocked in `Adblock.list` if a noisy threat IP feed includes a shared edge IP.
pub fn overlaps_shared_cdn_or_dns_v4(net: Ipv4Net) -> bool {
    const PROTECTED_V4: &[([u8; 4], u8)] = &[
        ([1, 0, 0, 0], 24),       // Cloudflare DNS
        ([1, 1, 1, 0], 24),       // Cloudflare DNS
        ([8, 8, 4, 0], 24),       // Google Public DNS
        ([8, 8, 8, 0], 24),       // Google Public DNS
        ([9, 9, 9, 0], 24),       // Quad9 DNS
        ([17, 0, 0, 0], 8),       // Apple Inc.
        ([103, 21, 244, 0], 22),  // Cloudflare Anycast
        ([103, 22, 200, 0], 22),  // Cloudflare Anycast
        ([103, 31, 4, 0], 22),    // Cloudflare Anycast
        ([104, 16, 0, 0], 12),    // Cloudflare Anycast (104.16.0.0 - 104.31.255.255)
        ([108, 162, 192, 0], 18), // Cloudflare Anycast
        ([119, 29, 29, 0], 24),   // Tencent DNSPod
        ([131, 0, 72, 0], 22),    // Cloudflare Anycast
        ([140, 82, 112, 0], 20),  // GitHub
        ([141, 101, 64, 0], 18),  // Cloudflare Anycast
        ([151, 101, 0, 0], 16),   // Fastly CDN
        ([162, 158, 0, 0], 15),   // Cloudflare Anycast
        ([172, 64, 0, 0], 13),    // Cloudflare Anycast
        ([173, 245, 48, 0], 20),  // Cloudflare Anycast
        ([185, 199, 108, 0], 22), // GitHub Pages / raw.githubusercontent.com
        ([188, 114, 96, 0], 20),  // Cloudflare Anycast
        ([190, 93, 240, 0], 20),  // Cloudflare Anycast
        ([197, 234, 240, 0], 22), // Cloudflare Anycast
        ([198, 41, 128, 0], 17),  // Cloudflare Anycast
        ([223, 5, 5, 0], 24),     // Alibaba Public DNS
        ([223, 6, 6, 0], 24),     // Alibaba Public DNS
    ];
    let s1 = u32::from(net.network());
    let e1 = u32::from(net.broadcast());
    PROTECTED_V4.iter().any(|&(octets, pfx)| {
        let base = u32::from_be_bytes(octets);
        let mask = if pfx == 0 { 0 } else { u32::MAX << (32 - pfx) };
        let s2 = base & mask;
        let e2 = s2 | !mask;
        s1 <= e2 && s2 <= e1
    })
}

pub fn overlaps_shared_cdn_or_dns_v6(net: Ipv6Net) -> bool {
    const PROTECTED_V6: &[(u128, u8)] = &[
        (0x2001_4860_4860_0000_0000_0000_0000_0000, 48), // Google Public DNS
        (0x2400_cb00_0000_0000_0000_0000_0000_0000, 32), // Cloudflare Anycast
        (0x2400_3200_0000_0000_0000_0000_0000_0000, 32), // Alibaba Public DNS / Cloud
        (0x2606_4700_0000_0000_0000_0000_0000_0000, 32), // Cloudflare Anycast + 1.1.1.1
        (0x2a04_4e40_0000_0000_0000_0000_0000_0000, 32), // Fastly CDN
    ];
    let s1 = u128::from(net.network());
    let e1 = u128::from(net.broadcast());
    PROTECTED_V6.iter().any(|&(base, pfx)| {
        let mask = if pfx == 0 {
            0
        } else {
            u128::MAX << (128 - pfx)
        };
        let s2 = base & mask;
        let e2 = s2 | !mask;
        s1 <= e2 && s2 <= e1
    })
}

/// Checks if a single IP address is inside any reserved / private / virtual-mesh range.
pub fn is_reserved_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => Ipv4Net::new(v4, 32).is_ok_and(overlaps_reserved_v4),
        IpAddr::V6(v6) => Ipv6Net::new(v6, 128).is_ok_and(overlaps_reserved_v6),
    }
}

/// Converts a single Ipv4Addr helper to keep unused import clean if needed
fn _ip_unused_check(_: Ipv4Addr, _: Ipv6Addr) {}

#[allow(clippy::too_many_arguments)]
fn render_module(
    general_hosts: &BTreeMap<String, BTreeSet<String>>,
    module_rule_map: &BTreeMap<String, u16>,
    header_map: &BTreeMap<(HeaderDirection, String, HeaderAction, String), HeaderRewriteRule>,
    url_map: &BTreeMap<(String, UrlRewriteMode), UrlRewriteRule>,
    map_local_map: &BTreeMap<String, MapLocalRule>,
    body_map: &BTreeMap<(BodyRewriteKind, String, String), BodyRewriteRule>,
    final_scripts: &[ScriptRule],
    mitm_exclusions: &BTreeSet<String>,
    mitm_positive: &BTreeSet<String>,
    active_sources: usize,
    total_sources: usize,
) -> (String, ModuleStats) {
    let mut out = String::with_capacity(64 * 1024);
    out.push_str("#!name=surge-rules Adblock & Privacy\n");
    out.push_str(&format!(
        "#!desc=Multi-source HTTP rewrite, JQ body cleanup, Map Local, HTTPDNS guard, and tracking sanitization ({}/{} active feeds)\n",
        active_sources, total_sources
    ));
    out.push_str("#!author=ding113\n");
    out.push_str("#!homepage=https://github.com/ding113/surge-rules\n");
    out.push_str("#!category=Adblock\n");
    out.push_str("#!requirement=CORE_VERSION>=20\n\n");

    let mut stats = ModuleStats {
        mitm_excluded_count: mitm_exclusions.len(),
        mitm_included_count: mitm_positive.len(),
        ..Default::default()
    };

    if !general_hosts.is_empty() {
        out.push_str("[General]\n");
        for (key, vals) in general_hosts {
            if vals.is_empty() {
                continue;
            }
            let ordered = order_host_list(vals);
            let directive = if ordered.iter().any(|v| v.starts_with('-')) {
                "%INSERT%"
            } else {
                "%APPEND%"
            };
            out.push_str(&format!("{} = {} {}\n", key, directive, ordered.join(", ")));
            stats.general_keys += 1;
        }
        out.push('\n');
    }

    if !module_rule_map.is_empty() {
        out.push_str("[Rule]\n");
        let mut sorted_rules: Vec<(&String, u16)> =
            module_rule_map.iter().map(|(l, w)| (l, *w)).collect();
        sorted_rules.sort_by(|a, b| {
            let a_direct = a.0.ends_with(",DIRECT");
            let b_direct = b.0.ends_with(",DIRECT");
            b_direct
                .cmp(&a_direct)
                .then_with(|| b.1.cmp(&a.1))
                .then_with(|| a.0.cmp(b.0))
        });
        for (line, _) in sorted_rules {
            out.push_str(line);
            out.push('\n');
            stats.rules_count += 1;
        }
        out.push('\n');
    }

    if !header_map.is_empty() {
        out.push_str("[Header Rewrite]\n");
        let mut items: Vec<&HeaderRewriteRule> = header_map.values().collect();
        items.sort_by_key(|r| {
            (
                Reverse(r.weight),
                r.direction,
                r.pattern.clone(),
                r.field.clone(),
            )
        });
        for r in items {
            out.push_str(&r.to_surge_line());
            out.push('\n');
            stats.header_rewrite_count += 1;
        }
        out.push('\n');
    }

    if !url_map.is_empty() {
        out.push_str("[URL Rewrite]\n");
        let mut items: Vec<&UrlRewriteRule> = url_map.values().collect();
        items.sort_by_key(|r| (Reverse(r.weight), r.mode, r.pattern.clone()));
        for r in items {
            out.push_str(&r.to_surge_line());
            out.push('\n');
            stats.url_rewrite_count += 1;
        }
        out.push('\n');
    }

    if !body_map.is_empty() {
        out.push_str("[Body Rewrite]\n");
        let mut items: Vec<&BodyRewriteRule> = body_map.values().collect();
        items.sort_by_key(|r| {
            (
                Reverse(r.weight),
                r.kind,
                r.pattern.clone(),
                r.expression.clone(),
            )
        });
        for r in items {
            out.push_str(&r.to_surge_line());
            out.push('\n');
            stats.body_rewrite_count += 1;
        }
        out.push('\n');
    }

    if !map_local_map.is_empty() {
        out.push_str("[Map Local]\n");
        let mut items: Vec<&MapLocalRule> = map_local_map.values().collect();
        items.sort_by_key(|r| (Reverse(r.weight), r.pattern.clone()));
        for r in items {
            out.push_str(&r.to_surge_line());
            out.push('\n');
            stats.map_local_count += 1;
        }
        out.push('\n');
    }

    if !final_scripts.is_empty() {
        out.push_str("[Script]\n");
        for s in final_scripts {
            out.push_str(&s.to_surge_line(&s.name));
            out.push('\n');
            stats.script_count += 1;
        }
        out.push('\n');
    }

    out.push_str("[MITM]\n");
    let mut mitm_list: Vec<String> = mitm_exclusions.iter().map(|h| format!("-{}", h)).collect();
    mitm_list.extend(mitm_positive.iter().cloned());
    out.push_str(&format!("hostname = %INSERT% {}\n", mitm_list.join(", ")));

    (out, stats)
}

fn order_host_list(vals: &BTreeSet<String>) -> Vec<String> {
    let mut neg: Vec<String> = Vec::new();
    let mut pos: Vec<String> = Vec::new();
    for v in vals {
        if v.starts_with('-') {
            neg.push(v.clone());
        } else {
            pos.push(v.clone());
        }
    }
    neg.extend(pos);
    neg
}

fn wildcard_static_suffix(wc: &str) -> Option<&str> {
    let labels: Vec<&str> = wc.split('.').collect();
    let mut first_static = labels.len();
    while first_static > 0 {
        let lbl = labels[first_static - 1];
        if lbl.is_empty() || lbl.contains('*') || lbl.contains('?') {
            break;
        }
        first_static -= 1;
    }
    if labels.len().saturating_sub(first_static) < 2 {
        return None;
    }
    let byte_offset: usize = labels[..first_static].iter().map(|l| l.len() + 1).sum();
    wc.get(byte_offset..)
}

#[allow(clippy::too_many_arguments)]
fn render_ruleset(
    header_title: &str,
    domains: &BTreeSet<String>,
    suffixes: &BTreeSet<String>,
    keywords: &BTreeSet<String>,
    wildcards: &BTreeSet<String>,
    cidrs_v4: &[Ipv4Net],
    cidrs_v6: &[Ipv6Net],
    asns: &BTreeSet<u32>,
    user_agents: &BTreeSet<String>,
    process_names: &BTreeSet<String>,
    active_sources: usize,
    total_sources: usize,
) -> (String, RulesetStats) {
    let total_rules = domains.len()
        + suffixes.len()
        + keywords.len()
        + wildcards.len()
        + cidrs_v4.len()
        + cidrs_v6.len()
        + asns.len()
        + user_agents.len()
        + process_names.len();

    let mut out = String::with_capacity(total_rules * 34 + 256);
    out.push_str(&format!(
        "# surge-rules {} RULE-SET (iOS / tvOS / macOS)\n",
        header_title
    ));
    out.push_str(&format!(
        "# Active upstream feeds: {}/{} | Total rules: {}\n\n",
        active_sources, total_sources, total_rules
    ));

    for d in domains {
        out.push_str("DOMAIN,");
        out.push_str(d);
        out.push('\n');
    }
    for s in suffixes {
        out.push_str("DOMAIN-SUFFIX,");
        out.push_str(s);
        out.push('\n');
    }
    for k in keywords {
        out.push_str("DOMAIN-KEYWORD,");
        out.push_str(k);
        out.push('\n');
    }
    for w in wildcards {
        out.push_str("DOMAIN-WILDCARD,");
        out.push_str(w);
        out.push('\n');
    }
    for c4 in cidrs_v4 {
        out.push_str(&format!("IP-CIDR,{},no-resolve\n", c4));
    }
    for c6 in cidrs_v6 {
        out.push_str(&format!("IP-CIDR6,{},no-resolve\n", c6));
    }
    for asn in asns {
        out.push_str(&format!("IP-ASN,{},no-resolve\n", asn));
    }
    for ua in user_agents {
        out.push_str("USER-AGENT,");
        out.push_str(ua);
        out.push('\n');
    }
    for proc_name in process_names {
        out.push_str("PROCESS-NAME,");
        out.push_str(proc_name);
        out.push('\n');
    }

    let stats = RulesetStats {
        total_rules,
        domain_count: domains.len(),
        domain_suffix_count: suffixes.len(),
        domain_keyword_count: keywords.len(),
        domain_wildcard_count: wildcards.len(),
        ip_cidr_count: cidrs_v4.len(),
        ip_cidr6_count: cidrs_v6.len(),
        ip_asn_count: asns.len(),
        user_agent_count: user_agents.len(),
        process_name_count: process_names.len(),
        suppressed_by_protection: 0,
        subsumed_by_trie: 0,
    };

    (out, stats)
}
