use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};
use rustc_hash::FxHashSet;

use crate::adblock::config::AllowDomainMatchType;
use crate::adblock::config::{AdblockOverrides, ModuleScriptOverride};
use crate::adblock::model::{
    BodyRewriteKind, BodyRewriteRule, HeaderAction, HeaderDirection, HeaderRewriteRule,
    MapLocalDataType, MapLocalRule, ParsedAdblockSource, RemoveParamRule, ScriptRule, ScriptType,
    UrlRewriteMode, UrlRewriteRule,
};
use crate::adblock::regex_util::{extract_hosts_from_regex, is_valid_domain, is_valid_mitm_host};

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
    pub module_text: String,
    pub ruleset_counts: RulesetStats,
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

pub const REMOVEPARAM_SCRIPT_URL: &str =
    "https://raw.githubusercontent.com/ding113/surge-rules/main/scripts/surge-removeparam.js";

/// Compiles parsed upstream feeds and TypeScript human overrides into `Adblock.list` and `Adblock.sgmodule`.
pub fn compile_adblock(
    sources: &[ParsedAdblockSource],
    overrides: &AdblockOverrides,
    active_sources: usize,
    total_sources: usize,
) -> CompiledAdblockArtifacts {
    // 1. Assemble protection / allowlist tries first
    let mut allow_exact_set: FxHashSet<String> = FxHashSet::default();
    let mut allow_suffix_set: FxHashSet<String> = FxHashSet::default();
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
                allow_exact_set.insert(dom);
            }
            AllowDomainMatchType::Suffix => {
                allow_suffix_set.insert(dom);
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
        allow_exact_set.extend(src.allow_exact_domains.iter().cloned());
        allow_suffix_set.extend(src.allow_suffix_domains.iter().cloned());
        complex_host_set.extend(src.complex_protected_hosts.iter().cloned());
    }

    // 2. Collect module sections (overrides get weight 200) and disabled pattern filters
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
    let mut script_candidates: Vec<ScriptRule> = Vec::new();
    let mut remove_params: Vec<RemoveParamRule> = Vec::new();
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
        for s in &src.scripts {
            if !is_pattern_disabled(&s.pattern, &overrides.disabled_url_patterns) {
                script_candidates.push(s.clone());
            }
        }
        remove_params.extend(src.remove_params.iter().cloned());
        for mh in &src.mitm_hosts {
            let clean = mh.trim().to_ascii_lowercase();
            if is_valid_mitm_host(&clean) {
                mitm_positive.insert(clean);
            }
        }
    }

    // Apply human module overrides at top weight (200)
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

    // 3. Deduplicate scripts while enforcing Surge's 1-script-per-(type, pattern) precedence
    let mut final_scripts = resolve_script_conflicts(script_candidates);

    // 4. Filter MITM hosts against `-` exclusions before checking `$removeparam` host coverage
    let mut mitm_exclusions: BTreeSet<String> = BTreeSet::new();
    for ex in &overrides.mitm_excluded_hosts {
        let p = ex.pattern.trim().to_ascii_lowercase();
        if is_valid_mitm_host(&p) {
            mitm_exclusions.insert(p);
        }
    }
    let mitm_exclusion_set = mitm_exclusions.clone();
    mitm_positive.retain(|h| !mitm_host_is_excluded(h, &mitm_exclusion_set));

    // Prune HTTPS module rules whose target hosts are all excluded from MITM (after complex_host_set registration)
    header_map.retain(|_, r| !pattern_targets_excluded_https_only(&r.pattern, &mitm_exclusion_set));
    url_map.retain(|_, r| !pattern_targets_excluded_https_only(&r.pattern, &mitm_exclusion_set));
    map_local_map
        .retain(|_, r| !pattern_targets_excluded_https_only(&r.pattern, &mitm_exclusion_set));
    body_map.retain(|_, r| !pattern_targets_excluded_https_only(&r.pattern, &mitm_exclusion_set));
    final_scripts.retain(|s| !pattern_targets_excluded_https_only(&s.pattern, &mitm_exclusion_set));

    // 5. Compile fallback RULE-SET with complex-over-host protection and domain trie compression
    let mut allow_suffix_trie = DomainTrie::default();
    for s in &allow_suffix_set {
        allow_suffix_trie.insert_suffix(s);
    }

    let mut allow_point_trie = DomainTrie::default();
    for d in &allow_exact_set {
        allow_point_trie.insert_exact(d);
    }

    let mut complex_point_trie = DomainTrie::default();
    for d in &complex_host_set {
        complex_point_trie.insert_exact(d);
    }

    let mut candidate_domains: FxHashSet<String> = FxHashSet::default();
    let mut candidate_suffixes: FxHashSet<String> = FxHashSet::default();
    let mut candidate_keywords: BTreeSet<String> = BTreeSet::new();
    let mut candidate_wildcards: BTreeSet<String> = BTreeSet::new();
    let mut raw_v4: Vec<Ipv4Net> = Vec::new();
    let mut raw_v6: Vec<Ipv6Net> = Vec::new();
    let mut candidate_asns: BTreeSet<u32> = BTreeSet::new();
    let mut candidate_uas: BTreeSet<String> = BTreeSet::new();
    let mut candidate_procs: BTreeSet<String> = BTreeSet::new();

    for src in sources {
        candidate_domains.extend(src.ruleset_domains.iter().cloned());
        candidate_suffixes.extend(src.ruleset_suffixes.iter().cloned());
        candidate_keywords.extend(src.ruleset_keywords.iter().cloned());
        candidate_wildcards.extend(src.ruleset_wildcards.iter().cloned());
        raw_v4.extend(src.ruleset_cidrs_v4.iter().copied());
        raw_v6.extend(src.ruleset_cidrs_v6.iter().copied());
        candidate_asns.extend(src.ruleset_asns.iter().copied());
        candidate_uas.extend(src.ruleset_user_agents.iter().cloned());
        candidate_procs.extend(src.ruleset_process_names.iter().cloned());
    }

    let mut forced_domains: FxHashSet<String> = FxHashSet::default();
    let mut forced_suffixes: FxHashSet<String> = FxHashSet::default();
    for f in &overrides.force_rule_set_entries {
        let v = f.value.trim();
        match f.kind.as_str() {
            "DOMAIN" => {
                let d = v.trim_end_matches('.').to_ascii_lowercase();
                if is_valid_domain(&d) {
                    candidate_domains.insert(d.clone());
                    forced_domains.insert(d);
                }
            }
            "DOMAIN-SUFFIX" => {
                let s = v
                    .trim_start_matches('.')
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                if is_valid_domain(&s) {
                    candidate_suffixes.insert(s.clone());
                    forced_suffixes.insert(s);
                }
            }
            "DOMAIN-KEYWORD" => {
                candidate_keywords.insert(v.to_ascii_lowercase());
            }
            "DOMAIN-WILDCARD" => {
                candidate_wildcards.insert(v.to_ascii_lowercase());
            }
            "IP-CIDR" => {
                if let Ok(net) = v.parse::<Ipv4Net>() {
                    raw_v4.push(net.trunc());
                }
            }
            "IP-CIDR6" => {
                if let Ok(net) = v.parse::<Ipv6Net>() {
                    raw_v6.push(net.trunc());
                }
            }
            "IP-ASN" => {
                if let Ok(asn) = v.parse::<u32>() {
                    candidate_asns.insert(asn);
                }
            }
            "USER-AGENT" => {
                candidate_uas.insert(v.to_string());
            }
            "PROCESS-NAME" => {
                candidate_procs.insert(v.to_string());
            }
            _ => {}
        }
    }

    let mut suppressed_by_protection = 0usize;
    let mut surviving_suffixes: Vec<String> = Vec::new();
    for s in candidate_suffixes {
        let is_forced = forced_suffixes.contains(&s);
        let blocked_by_allow = allow_suffix_trie.has_suffix_ancestor_or_eq(&s)
            || allow_suffix_trie.has_mark_at_or_below(&s)
            || allow_point_trie.has_mark_at_or_below(&s);
        let blocked_by_complex = !is_forced
            && (protected_apex_set.contains(&s) || complex_point_trie.has_mark_at_or_below(&s));
        if blocked_by_allow || blocked_by_complex {
            suppressed_by_protection += 1;
        } else {
            surviving_suffixes.push(s);
        }
    }

    // Build suffix trie and compress redundant descendant suffixes first
    surviving_suffixes.sort_by(|a, b| {
        a.split('.')
            .count()
            .cmp(&b.split('.').count())
            .then_with(|| a.cmp(b))
    });
    let mut final_suffix_trie = DomainTrie::default();
    let mut compressed_suffixes: BTreeSet<String> = BTreeSet::new();
    let mut subsumed_by_trie = 0usize;

    for s in surviving_suffixes {
        if final_suffix_trie.has_suffix_ancestor_or_eq(&s) {
            subsumed_by_trie += 1;
            continue;
        }
        final_suffix_trie.insert_suffix(&s);
        compressed_suffixes.insert(s);
    }

    let mut compressed_domains: BTreeSet<String> = BTreeSet::new();
    for d in candidate_domains {
        let is_forced = forced_domains.contains(&d);
        let blocked_by_allow = allow_suffix_trie.has_suffix_ancestor_or_eq(&d)
            || allow_exact_set.contains(&d)
            || (!is_forced && complex_host_set.contains(&d));
        if blocked_by_allow {
            suppressed_by_protection += 1;
            continue;
        }
        if final_suffix_trie.has_suffix_ancestor_or_eq(&d) {
            subsumed_by_trie += 1;
            continue;
        }
        compressed_domains.insert(d);
    }

    // Drop unsafe domain-keywords or wildcards that collide with protected/allowed domains
    candidate_keywords.retain(|kw| {
        !allow_exact_set
            .iter()
            .chain(allow_suffix_set.iter())
            .chain(protected_apex_set.iter())
            .chain(complex_host_set.iter())
            .any(|dom| dom.contains(kw.as_str()))
    });
    candidate_wildcards.retain(|wc| {
        !allow_exact_set
            .iter()
            .chain(allow_suffix_set.iter())
            .chain(complex_host_set.iter())
            .any(|dom| wildcard_matches_domain(wc, dom))
    });

    // Exclude RFC 6890 private / LAN / Surge Fake-IP / CGNAT / Tailscale / Cloudflare Mesh / bogons before aggregating CIDRs
    raw_v4.retain(|net| !overlaps_reserved_v4(*net));
    raw_v6.retain(|net| !overlaps_reserved_v6(*net));
    let coalesced_v4 = Ipv4Net::aggregate(&raw_v4);
    let coalesced_v6 = Ipv6Net::aggregate(&raw_v6);

    let (ruleset_text, mut ruleset_counts) = render_ruleset(
        &compressed_domains,
        &compressed_suffixes,
        &candidate_keywords,
        &candidate_wildcards,
        &coalesced_v4,
        &coalesced_v6,
        &candidate_asns,
        &candidate_uas,
        &candidate_procs,
        active_sources,
        total_sources,
    );
    ruleset_counts.suppressed_by_protection = suppressed_by_protection;
    ruleset_counts.subsumed_by_trie = subsumed_by_trie;

    // Append `$removeparam` scripts last (global + host-scoped) so app-specific http-request scripts run first
    final_scripts.extend(build_removeparam_scripts(
        &remove_params,
        &mut mitm_positive,
        &mitm_exclusion_set,
        &final_suffix_trie,
        &compressed_domains,
    ));

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
        module_text,
        ruleset_counts,
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
        max_size: s.max_size,
        timeout: None,
        argument: s.argument.clone(),
        engine: None,
        weight: 200,
    }
}

fn resolve_script_conflicts(mut candidates: Vec<ScriptRule>) -> Vec<ScriptRule> {
    candidates.sort_by(|a, b| {
        b.weight
            .cmp(&a.weight)
            .then_with(|| a.script_type.cmp(&b.script_type))
            .then_with(|| a.pattern.cmp(&b.pattern))
            .then_with(|| a.name.cmp(&b.name))
    });

    let mut seen_triggers: FxHashSet<(ScriptType, String)> = FxHashSet::default();
    let mut kept = Vec::new();
    for s in candidates {
        if seen_triggers.insert(s.trigger_key()) {
            kept.push(s);
        }
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
        let base = if s.name == "surge-removeparam" || s.name == "surge-removeparam-scoped" {
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
    let p = param.trim().to_ascii_lowercase();
    if p.is_empty() {
        return false;
    }
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
            | "_hsenc"
            | "_hsmi"
            | "_bta_tid"
            | "_bta_c"
            | "_ke"
            | "_kx"
    )
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

fn build_removeparam_scripts(
    rules: &[RemoveParamRule],
    mitm_positive: &mut BTreeSet<String>,
    mitm_exclusion_set: &BTreeSet<String>,
    final_suffix_trie: &DomainTrie,
    compressed_domains: &BTreeSet<String>,
) -> Vec<ScriptRule> {
    if rules.is_empty() {
        return Vec::new();
    }

    let mut global_params: BTreeMap<String, u16> = BTreeMap::new();
    let mut scope_params: BTreeMap<String, (u16, BTreeSet<String>)> = BTreeMap::new();

    for r in rules {
        let param_clean = r.param.trim().to_ascii_lowercase();
        if param_clean.is_empty() {
            continue;
        }
        let host = r.host_scope.as_str();
        if host == "*" {
            if is_safe_global_tracking_param(&param_clean) {
                let entry = global_params.entry(param_clean).or_insert(r.weight);
                *entry = (*entry).max(r.weight);
            }
            continue;
        }
        if !is_valid_mitm_host(host)
            || mitm_host_is_excluded(host, mitm_exclusion_set)
            || final_suffix_trie.matches_domain(host)
            || compressed_domains.contains(host)
        {
            continue;
        }
        let entry = scope_params
            .entry(r.host_scope.clone())
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
            if selected_global.len() >= 120 || arg_len + add_len > 3400 {
                break;
            }
            arg_len += add_len;
            selected_global.push(p);
        }

        if !selected_global.is_empty() {
            selected_global.sort();
            let escaped_keys: Vec<String> = selected_global
                .iter()
                .map(|k| crate::adblock::regex_util::escape_literal_regex(k))
                .collect();
            let pattern = format!(
                "^https?://[^?#]+\\?(?:[^#]*&)?(?:{})=",
                escaped_keys.join("|")
            );
            scripts.push(ScriptRule {
                name: "surge-removeparam".to_string(),
                script_type: ScriptType::HttpRequest,
                pattern,
                script_path: REMOVEPARAM_SCRIPT_URL.to_string(),
                requires_body: false,
                binary_body_mode: false,
                max_size: None,
                timeout: Some(5),
                argument: Some(format!("*={}", selected_global.join("|"))),
                engine: Some("webview".to_string()),
                weight: 1,
            });
        }
    }

    if !scope_params.is_empty() {
        let bulk_mode = scope_params.len() > 32;
        let mut ranked_scopes: Vec<(String, u16, BTreeSet<String>)> = scope_params
            .into_iter()
            .filter(|(host, _)| !bulk_mode || mitm_host_is_excluded(host, mitm_positive))
            .map(|(host, (w, params))| (host, w, params))
            .collect();
        ranked_scopes.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| b.2.len().cmp(&a.2.len()))
                .then_with(|| a.0.cmp(&b.0))
        });

        let mut arg_chunks: Vec<String> = Vec::new();
        let mut total_arg_len = 0usize;
        let mut active_hosts: BTreeSet<String> = BTreeSet::new();
        let mut active_param_tokens: BTreeSet<String> = BTreeSet::new();

        for (host, _, params) in ranked_scopes {
            let param_list: Vec<String> = params.iter().take(24).cloned().collect();
            let mut next_params = active_param_tokens.clone();
            next_params.extend(param_list.iter().cloned());
            if next_params.len() > 120 {
                continue;
            }
            let chunk = format!("{}={}", host, param_list.join("|"));
            if total_arg_len + chunk.len() + 1 > 3400 {
                break;
            }
            if !bulk_mode {
                mitm_positive.insert(host.clone());
            }
            total_arg_len += chunk.len() + 1;
            active_hosts.insert(host);
            active_param_tokens = next_params;
            arg_chunks.push(chunk);
        }

        if !arg_chunks.is_empty() && !active_hosts.is_empty() && !active_param_tokens.is_empty() {
            let host_atoms: Vec<String> = active_hosts
                .iter()
                .map(|h| host_scope_to_regex(h))
                .collect();
            let escaped_keys: Vec<String> = active_param_tokens
                .iter()
                .map(|k| crate::adblock::regex_util::escape_literal_regex(k))
                .collect();
            let pattern = format!(
                "^https?://(?:{})(?::\\d+)?(?:/[^?#]*)?\\?(?:[^#]*&)?(?:{})=",
                host_atoms.join("|"),
                escaped_keys.join("|")
            );
            scripts.push(ScriptRule {
                name: "surge-removeparam-scoped".to_string(),
                script_type: ScriptType::HttpRequest,
                pattern,
                script_path: REMOVEPARAM_SCRIPT_URL.to_string(),
                requires_body: false,
                binary_body_mode: false,
                max_size: None,
                timeout: Some(5),
                argument: Some(arg_chunks.join(";")),
                engine: Some("webview".to_string()),
                weight: 1,
            });
        }
    }

    scripts
}

fn mitm_host_is_excluded(host: &str, exclusions: &BTreeSet<String>) -> bool {
    let bare = host
        .split(':')
        .next()
        .unwrap_or(host)
        .trim_start_matches("*.");
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

#[allow(clippy::too_many_arguments)]
fn render_ruleset(
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
    out.push_str("# surge-rules Adblock & Privacy RULE-SET (iOS / tvOS / macOS)\n");
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
