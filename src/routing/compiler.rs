use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use anyhow::{Context, Result, bail};
use ipnet::{Ipv4Net, Ipv6Net};
use maxminddb::{Reader, geoip2};
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
    pub active_payment: usize,
    pub total_payment: usize,
    pub active_telemetry: usize,
    pub total_telemetry: usize,
    pub active_proxy: usize,
    pub total_proxy: usize,
}

#[derive(Clone, Debug)]
pub struct CompiledRoutingArtifacts {
    pub direct_text: String,
    pub ai_text: String,
    pub payment_text: String,
    pub telemetry_text: String,
    pub proxy_text: String,
    pub direct_stats: TargetStats,
    pub ai_stats: TargetStats,
    pub payment_stats: TargetStats,
    pub telemetry_stats: TargetStats,
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

    fn merge_from(&mut self, other: &Self) {
        for (lin, &w) in &other.lineage_weights {
            self.lineage_weights
                .entry(lin.clone())
                .and_modify(|prev| {
                    if w > *prev {
                        *prev = w;
                    }
                })
                .or_insert(w);
        }
        self.extended_matching |= other.extended_matching;
        self.forced |= other.forced;
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

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum CleanSlot {
    Ai = 0,
    Payment = 1,
    Telemetry = 2,
}

impl CleanSlot {
    const ALL_PRIORITY_DESC: [Self; 3] = [Self::Telemetry, Self::Payment, Self::Ai];

    fn from_target(target: RoutingTarget) -> Option<Self> {
        match target {
            RoutingTarget::Ai => Some(Self::Ai),
            RoutingTarget::Payment => Some(Self::Payment),
            RoutingTarget::Telemetry => Some(Self::Telemetry),
            RoutingTarget::Direct | RoutingTarget::Proxy => None,
        }
    }

    #[inline]
    const fn idx(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Debug, Default)]
struct CleanCandidate {
    claims: [Option<CandidateRule>; 3],
}

impl CleanCandidate {
    fn ingest(&mut self, slot: CleanSlot, lineage: &str, weight: u16, extended: bool) {
        self.claims[slot.idx()]
            .get_or_insert_with(CandidateRule::default)
            .ingest(lineage, weight, extended);
    }

    fn force(&mut self, slot: CleanSlot, extended: bool) {
        self.claims[slot.idx()]
            .get_or_insert_with(CandidateRule::default)
            .force(extended);
    }

    fn merge_from(&mut self, other: &Self) {
        for (dst, src) in self.claims.iter_mut().zip(&other.claims) {
            if let Some(s) = src {
                dst.get_or_insert_with(CandidateRule::default).merge_from(s);
            }
        }
    }

    fn has_any_claim(&self) -> bool {
        self.claims.iter().any(Option::is_some)
    }

    fn is_forced(&self) -> bool {
        self.claims.iter().flatten().any(|c| c.forced)
    }

    fn extended_matching(&self) -> bool {
        self.claims.iter().flatten().any(|c| c.extended_matching)
    }

    fn pooled_lineages(&self) -> FxHashMap<String, u16> {
        let mut merged: FxHashMap<String, u16> = FxHashMap::default();
        for claim in self.claims.iter().flatten() {
            for (lin, &w) in &claim.lineage_weights {
                merged
                    .entry(lin.clone())
                    .and_modify(|prev| {
                        if w > *prev {
                            *prev = w;
                        }
                    })
                    .or_insert(w);
            }
        }
        merged
    }

    fn pooled_score(&self) -> u16 {
        if self.is_forced() {
            return 250;
        }
        let merged = self.pooled_lineages();
        let max_w = merged.values().copied().max().unwrap_or(0);
        let extra = (merged.len().saturating_sub(1) as u16).saturating_mul(12);
        max_w.saturating_add(extra).min(200)
    }

    fn to_proxy_candidate(&self) -> CandidateRule {
        CandidateRule {
            lineage_weights: self.pooled_lineages(),
            extended_matching: self.extended_matching(),
            forced: self.is_forced(),
        }
    }

    /// Deterministically assigns a unique owner in `{Ai, Payment, Telemetry}`.
    /// Forced overrides take precedence; for unforced cross-feed overlaps (e.g. bundled AI feeds
    /// that also include Stripe/PayPal or CAPTCHA/telemetry domains), dedicated Telemetry and
    /// Payment catalogs take ownership so `AI.list` stays scoped strictly to AI applications.
    fn owner(&self) -> CleanSlot {
        for slot in CleanSlot::ALL_PRIORITY_DESC {
            if self.claims[slot.idx()].as_ref().is_some_and(|c| c.forced) {
                return slot;
            }
        }
        for slot in CleanSlot::ALL_PRIORITY_DESC {
            if self.claims[slot.idx()].is_some() {
                return slot;
            }
        }
        CleanSlot::Ai
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

#[derive(Clone, Debug, Default)]
pub struct CnCidrExclusionSet {
    v4_intervals: Vec<(u32, u32)>,
    v6_intervals: Vec<(u128, u128)>,
}

impl CnCidrExclusionSet {
    pub fn from_cidrs(v4: &[Ipv4Net], v6: &[Ipv6Net]) -> Self {
        let raw_v4: Vec<(u32, u32)> = v4
            .iter()
            .map(|n| {
                let c = n.trunc();
                (u32::from(c.network()), u32::from(c.broadcast()))
            })
            .collect();
        let raw_v6: Vec<(u128, u128)> = v6
            .iter()
            .map(|n| {
                let c = n.trunc();
                (u128::from(c.network()), u128::from(c.broadcast()))
            })
            .collect();
        Self {
            v4_intervals: coalesce_u32_intervals(raw_v4),
            v6_intervals: coalesce_u128_intervals(raw_v6),
        }
    }

    pub fn from_mmdb_path(path: &Path) -> Result<Self> {
        let bytes =
            fs::read(path).with_context(|| format!("failed to read CN MMDB {}", path.display()))?;
        Self::from_mmdb_bytes(&bytes)
            .with_context(|| format!("failed to extract CN CIDRs from {}", path.display()))
    }

    pub fn from_mmdb_bytes(bytes: &[u8]) -> Result<Self> {
        let reader = Reader::from_source(bytes).context("invalid MaxMind MMDB")?;
        let node_count = reader.metadata.node_count as usize;
        let record_size = reader.metadata.record_size as usize;
        let ip_version = reader.metadata.ip_version as u8;

        if !matches!(record_size, 24 | 28 | 32) {
            bail!("unsupported MMDB record_size {}", record_size);
        }
        if !matches!(ip_version, 4 | 6) {
            bail!("unsupported MMDB ip_version {}", ip_version);
        }

        let node_byte_size = (record_size * 2) / 8;
        let tree_byte_size = node_count
            .checked_mul(node_byte_size)
            .context("MMDB tree_byte_size overflow")?;
        if tree_byte_size > bytes.len() {
            bail!("corrupt MMDB: tree_byte_size exceeds file size");
        }

        let v4_zero_root = if ip_version == 6 {
            mmdb_walk_fixed_bits(bytes, node_count, record_size, 0, 96, false)
        } else {
            None
        };
        let v4_mapped_root = if ip_version == 6 {
            if let Some(after_80) =
                mmdb_walk_fixed_bits(bytes, node_count, record_size, 0, 80, false)
                && after_80 < node_count
            {
                mmdb_walk_fixed_bits(bytes, node_count, record_size, after_80, 16, true)
            } else {
                None
            }
        } else {
            None
        };
        let skip_mapped_subtree =
            ip_version == 6 && v4_zero_root.is_some() && v4_zero_root == v4_mapped_root;

        let max_depth: u8 = if ip_version == 4 { 32 } else { 128 };
        let mut stack: Vec<(usize, u8, u128)> = Vec::with_capacity(256);
        if node_count > 0 {
            stack.push((0, 0, 0));
        }

        let mut ptr_is_cn: FxHashMap<usize, bool> = FxHashMap::default();
        let mut raw_v4: Vec<(u32, u32)> = Vec::new();
        let mut raw_v6: Vec<(u128, u128)> = Vec::new();

        const V4_COMPAT_END: u128 = 0x0000_0000_FFFF_FFFF;
        const V4_MAPPED_START: u128 = 0x0000_FFFF_0000_0000;
        const V4_MAPPED_END: u128 = 0x0000_FFFF_FFFF_FFFF;

        while let Some((node_idx, depth, prefix)) = stack.pop() {
            if skip_mapped_subtree && depth == 96 && prefix == V4_MAPPED_START {
                continue;
            }
            let (left, right) = mmdb_read_node(bytes, node_idx, record_size);
            for (bit, rec) in [(1u128, right), (0u128, left)] {
                let next_depth = depth + 1;
                let shift = (max_depth - next_depth) as u32;
                let child_prefix = prefix | (bit << shift);

                if rec < node_count {
                    if next_depth < max_depth {
                        stack.push((rec, next_depth, child_prefix));
                    }
                } else if rec > node_count {
                    let host_bits = max_depth - next_depth;
                    let mask = if host_bits == 128 {
                        u128::MAX
                    } else if host_bits == 0 {
                        0
                    } else {
                        (1u128 << host_bits) - 1
                    };
                    let start = child_prefix;
                    let end = child_prefix | mask;

                    let sample_ip = if ip_version == 4 {
                        IpAddr::V4(Ipv4Addr::from(start as u32))
                    } else if end <= V4_COMPAT_END {
                        if start == 0 && end == V4_COMPAT_END {
                            continue;
                        }
                        IpAddr::V4(Ipv4Addr::from(start as u32))
                    } else if start >= V4_MAPPED_START && end <= V4_MAPPED_END {
                        IpAddr::V4(Ipv4Addr::from((start - V4_MAPPED_START) as u32))
                    } else {
                        let clipped = start.max(V4_MAPPED_END + 1);
                        if clipped > end {
                            continue;
                        }
                        IpAddr::V6(Ipv6Addr::from(clipped))
                    };

                    let is_cn = *ptr_is_cn.entry(rec).or_insert_with(|| {
                        reader
                            .lookup::<geoip2::Country>(sample_ip)
                            .ok()
                            .is_some_and(|doc| {
                                doc.country.and_then(|c| c.iso_code) == Some("CN")
                                    || doc.registered_country.and_then(|c| c.iso_code) == Some("CN")
                            })
                    });

                    if is_cn {
                        match sample_ip {
                            IpAddr::V4(_) => {
                                let (s4, e4) = if ip_version == 6 && start >= V4_MAPPED_START {
                                    (
                                        (start - V4_MAPPED_START) as u32,
                                        (end - V4_MAPPED_START) as u32,
                                    )
                                } else {
                                    (start as u32, end as u32)
                                };
                                raw_v4.push((s4, e4));
                            }
                            IpAddr::V6(v6) => {
                                raw_v6.push((u128::from(v6), end));
                            }
                        }
                    }
                }
            }
        }

        Ok(Self {
            v4_intervals: coalesce_u32_intervals(raw_v4),
            v6_intervals: coalesce_u128_intervals(raw_v6),
        })
    }

    pub fn v4_interval_count(&self) -> usize {
        self.v4_intervals.len()
    }

    pub fn v6_interval_count(&self) -> usize {
        self.v6_intervals.len()
    }

    pub fn overlaps_v4(&self, net: Ipv4Net) -> bool {
        let c = net.trunc();
        let q_start = u32::from(c.network());
        let q_end = u32::from(c.broadcast());
        let idx = self.v4_intervals.partition_point(|&(s, _)| s <= q_end);
        idx > 0 && self.v4_intervals[idx - 1].1 >= q_start
    }

    pub fn overlaps_v6(&self, net: Ipv6Net) -> bool {
        let c = net.trunc();
        let q_start = u128::from(c.network());
        let q_end = u128::from(c.broadcast());
        let idx = self.v6_intervals.partition_point(|&(s, _)| s <= q_end);
        idx > 0 && self.v6_intervals[idx - 1].1 >= q_start
    }

    fn merged_with_direct_map(
        &self,
        direct_map: &FxHashMap<RoutingRuleKey, CandidateRule>,
    ) -> Self {
        let mut raw_v4 = self.v4_intervals.clone();
        let mut raw_v6 = self.v6_intervals.clone();
        for dk in direct_map.keys() {
            match dk.kind {
                RoutingRuleKind::IpCidr => {
                    if let Ok(net) = dk.value.parse::<Ipv4Net>() {
                        let c = net.trunc();
                        raw_v4.push((u32::from(c.network()), u32::from(c.broadcast())));
                    }
                }
                RoutingRuleKind::IpCidr6 => {
                    if let Ok(net) = dk.value.parse::<Ipv6Net>() {
                        let c = net.trunc();
                        raw_v6.push((u128::from(c.network()), u128::from(c.broadcast())));
                    }
                }
                _ => {}
            }
        }
        Self {
            v4_intervals: coalesce_u32_intervals(raw_v4),
            v6_intervals: coalesce_u128_intervals(raw_v6),
        }
    }
}

fn coalesce_u32_intervals(mut raw: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    if raw.is_empty() {
        return raw;
    }
    raw.sort_unstable_by_key(|&(s, e)| (s, e));
    let mut out: Vec<(u32, u32)> = Vec::with_capacity(raw.len());
    for (s, e) in raw {
        if s > e {
            continue;
        }
        if let Some(last) = out.last_mut()
            && last.1.saturating_add(1) >= s
        {
            last.1 = last.1.max(e);
        } else {
            out.push((s, e));
        }
    }
    out
}

fn coalesce_u128_intervals(mut raw: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    if raw.is_empty() {
        return raw;
    }
    raw.sort_unstable_by_key(|&(s, e)| (s, e));
    let mut out: Vec<(u128, u128)> = Vec::with_capacity(raw.len());
    for (s, e) in raw {
        if s > e {
            continue;
        }
        if let Some(last) = out.last_mut()
            && last.1.saturating_add(1) >= s
        {
            last.1 = last.1.max(e);
        } else {
            out.push((s, e));
        }
    }
    out
}

#[inline]
fn mmdb_read_node(bytes: &[u8], node_idx: usize, record_size: usize) -> (usize, usize) {
    match record_size {
        24 => {
            let off = node_idx * 6;
            let left = ((bytes[off] as usize) << 16)
                | ((bytes[off + 1] as usize) << 8)
                | (bytes[off + 2] as usize);
            let right = ((bytes[off + 3] as usize) << 16)
                | ((bytes[off + 4] as usize) << 8)
                | (bytes[off + 5] as usize);
            (left, right)
        }
        28 => {
            let off = node_idx * 7;
            let mid = bytes[off + 3] as usize;
            let left = ((mid >> 4) << 24)
                | ((bytes[off] as usize) << 16)
                | ((bytes[off + 1] as usize) << 8)
                | (bytes[off + 2] as usize);
            let right = ((mid & 0x0f) << 24)
                | ((bytes[off + 4] as usize) << 16)
                | ((bytes[off + 5] as usize) << 8)
                | (bytes[off + 6] as usize);
            (left, right)
        }
        32 => {
            let off = node_idx * 8;
            let left =
                u32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
                    as usize;
            let right = u32::from_be_bytes([
                bytes[off + 4],
                bytes[off + 5],
                bytes[off + 6],
                bytes[off + 7],
            ]) as usize;
            (left, right)
        }
        _ => (0, 0),
    }
}

fn mmdb_walk_fixed_bits(
    bytes: &[u8],
    node_count: usize,
    record_size: usize,
    mut cur: usize,
    steps: usize,
    bit_one: bool,
) -> Option<usize> {
    for _ in 0..steps {
        if cur >= node_count {
            return Some(cur);
        }
        let (l, r) = mmdb_read_node(bytes, cur, record_size);
        cur = if bit_one { r } else { l };
    }
    Some(cur)
}

pub fn compile_routing(
    sources: &[ParsedRoutingSource],
    overrides: &RoutingOverrides,
    adblock_overrides: &AdblockOverrides,
    source_counts: RoutingSourceCounts,
) -> CompiledRoutingArtifacts {
    compile_routing_with_cn_exclusions(
        sources,
        overrides,
        adblock_overrides,
        source_counts,
        &CnCidrExclusionSet::default(),
    )
}

pub fn compile_routing_with_cn_exclusions(
    sources: &[ParsedRoutingSource],
    overrides: &RoutingOverrides,
    adblock_overrides: &AdblockOverrides,
    source_counts: RoutingSourceCounts,
    external_cn_exclusions: &CnCidrExclusionSet,
) -> CompiledRoutingArtifacts {
    let mut direct_map: FxHashMap<RoutingRuleKey, CandidateRule> = FxHashMap::default();
    let mut clean_map: FxHashMap<RoutingRuleKey, CleanCandidate> = FxHashMap::default();
    let mut proxy_map: FxHashMap<RoutingRuleKey, CandidateRule> = FxHashMap::default();

    for src in sources {
        match src.target {
            RoutingTarget::Direct => {
                for rule in &src.rules {
                    direct_map.entry(rule.key.clone()).or_default().ingest(
                        &src.lineage,
                        src.weight,
                        rule.extended_matching,
                    );
                }
            }
            RoutingTarget::Proxy if !src.strict_cn_cidr_guard => {
                for rule in &src.rules {
                    proxy_map.entry(rule.key.clone()).or_default().ingest(
                        &src.lineage,
                        src.weight,
                        rule.extended_matching,
                    );
                }
            }
            target => {
                if let Some(slot) = CleanSlot::from_target(target) {
                    for rule in &src.rules {
                        clean_map.entry(rule.key.clone()).or_default().ingest(
                            slot,
                            &src.lineage,
                            src.weight,
                            rule.extended_matching,
                        );
                    }
                }
            }
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
            RoutingTarget::Proxy => {
                proxy_forced.insert_key(&key);
                proxy_map.entry(key).or_default().force(extended);
            }
            target => {
                if let Some(slot) = CleanSlot::from_target(target) {
                    clean_map.entry(key).or_default().force(slot, extended);
                }
            }
        }
    }

    // Strip known pure-ad/tracker domains unless explicitly forced by routing overrides.
    let ad_guard = AdGuard::from_overrides(adblock_overrides);
    let mut ad_domains_filtered = 0usize;
    for map in [&mut direct_map, &mut proxy_map] {
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
    {
        let before = clean_map.len();
        clean_map.retain(|key, cand| {
            if cand.is_forced() {
                return true;
            }
            match key.kind {
                RoutingRuleKind::Domain | RoutingRuleKind::DomainSuffix => {
                    !ad_guard.is_ad_domain(&key.value)
                }
                _ => true,
            }
        });
        ad_domains_filtered += before - clean_map.len();
    }

    // Protect shared cloud/auth/repo apexes across AI.list, Payment.list, and Telemetry.list.
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

    clean_map.retain(|key, cand| {
        let forced = cand.is_forced();
        match key.kind {
            RoutingRuleKind::Domain | RoutingRuleKind::DomainSuffix => {
                if shared_infra_set.contains(&key.value) || is_cn_or_generic_tld(&key.value) {
                    return false;
                }
                if !forced && direct_forced.matches_key(key) {
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
                if !forced && direct_forced.matches_key(key) {
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
                if !forced && direct_forced.matches_key(key) {
                    return false;
                }
            }
            _ => {
                if !forced && direct_forced.matches_key(key) {
                    return false;
                }
            }
        }
        true
    });

    // Apply target-specific explicit exclusions before cross-target reconciliation.
    let mut direct_exclude = RuleMatcher::default();
    let mut clean_excludes: [RuleMatcher; 3] = Default::default();
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
            RoutingTarget::Proxy => proxy_exclude.insert_key(&key),
            target => {
                if let Some(slot) = CleanSlot::from_target(target) {
                    clean_excludes[slot.idx()].insert_key(&key);
                }
            }
        }
    }
    direct_map.retain(|k, c| c.forced || !is_excluded(&direct_exclude, k));
    clean_map.retain(|k, cand| {
        for (slot, ex_matcher) in clean_excludes.iter().enumerate() {
            if cand.claims[slot].as_ref().is_some_and(|c| !c.forced) && is_excluded(ex_matcher, k) {
                cand.claims[slot] = None;
            }
        }
        cand.has_any_claim()
    });
    proxy_map.retain(|k, c| c.forced || !is_excluded(&proxy_exclude, k));

    // Ingest `strict_cn_cidr_guard` Proxy sources (e.g. `sstap_filtered_cidr`) while suppressing
    // ANY CIDR overlapping domestic CN CIDRs claimed by `Direct` sources or `Country-cn.mmdb`.
    let mut cn_cidrs_suppressed = 0usize;
    if sources
        .iter()
        .any(|s| s.target == RoutingTarget::Proxy && s.strict_cn_cidr_guard)
    {
        let cn_guard = external_cn_exclusions.merged_with_direct_map(&direct_map);
        for src in sources {
            if src.target != RoutingTarget::Proxy || !src.strict_cn_cidr_guard {
                continue;
            }
            for rule in &src.rules {
                if is_excluded(&proxy_exclude, &rule.key) {
                    continue;
                }
                match rule.key.kind {
                    RoutingRuleKind::IpCidr => {
                        if let Ok(net) = rule.key.value.parse::<Ipv4Net>()
                            && cn_guard.overlaps_v4(net)
                        {
                            cn_cidrs_suppressed += 1;
                            continue;
                        }
                    }
                    RoutingRuleKind::IpCidr6 => {
                        if let Ok(net) = rule.key.value.parse::<Ipv6Net>()
                            && cn_guard.overlaps_v6(net)
                        {
                            cn_cidrs_suppressed += 1;
                            continue;
                        }
                    }
                    RoutingRuleKind::Domain | RoutingRuleKind::DomainSuffix
                        if ad_guard.is_ad_domain(&rule.key.value) =>
                    {
                        ad_domains_filtered += 1;
                        continue;
                    }
                    _ => {}
                }
                proxy_map.entry(rule.key.clone()).or_default().ingest(
                    &src.lineage,
                    src.weight,
                    rule.extended_matching,
                );
            }
        }
    }

    // Resolve overlaps between Direct and Clean-Egress ({AI, Payment, Telemetry}):
    // 1. Non-forced clean-egress rules yield when Direct has strictly higher multi-lineage domestic consensus
    //    (e.g., global topical lists repurposed into Payment/Telemetry/AI that incidentally include CN domains).
    // 2. Surviving clean-egress rules take precedence over remaining non-forced Direct rules.
    let mut pre_direct_exact_scores: FxHashMap<String, u16> = FxHashMap::default();
    let mut pre_direct_suffix_scores: FxHashMap<String, u16> = FxHashMap::default();
    for (dk, dc) in &direct_map {
        let sc = dc.score();
        match dk.kind {
            RoutingRuleKind::Domain => {
                pre_direct_exact_scores
                    .entry(dk.value.clone())
                    .and_modify(|prev| *prev = (*prev).max(sc))
                    .or_insert(sc);
            }
            RoutingRuleKind::DomainSuffix => {
                pre_direct_suffix_scores
                    .entry(dk.value.clone())
                    .and_modify(|prev| *prev = (*prev).max(sc))
                    .or_insert(sc);
            }
            _ => {}
        }
    }

    let mut conflicts_resolved = cn_cidrs_suppressed;
    clean_map.retain(|k, c| {
        if c.is_forced() {
            return true;
        }
        let clean_score = c.pooled_score();
        let check_dom = match k.kind {
            RoutingRuleKind::Domain | RoutingRuleKind::DomainSuffix => Some(k.value.as_str()),
            RoutingRuleKind::DomainWildcard => k
                .value
                .strip_prefix("*.")
                .filter(|t| !t.contains('*') && !t.contains('?')),
            _ => None,
        };
        if let Some(dom) = check_dom {
            if let Some(&d_score) = pre_direct_exact_scores.get(dom)
                && k.kind == RoutingRuleKind::Domain
                && d_score > clean_score
            {
                conflicts_resolved += 1;
                return false;
            }
            if let Some(&d_score) = pre_direct_suffix_scores.get(dom)
                && d_score > clean_score
            {
                conflicts_resolved += 1;
                return false;
            }
            for (idx, _) in dom.match_indices('.') {
                let anc = &dom[idx + 1..];
                if let Some(&d_score) = pre_direct_suffix_scores.get(anc)
                    && d_score > clean_score
                {
                    conflicts_resolved += 1;
                    return false;
                }
            }
        }
        true
    });

    let mut clean_matcher = RuleMatcher::default();
    for key in clean_map.keys() {
        clean_matcher.insert_key(key);
    }
    direct_map.retain(|k, c| {
        if !c.forced && clean_matcher.matches_key(k) {
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

    // Enforce (AI.list ∪ Payment.list ∪ Telemetry.list) as a strict subset of Proxy.list BEFORE compression.
    let mut ai_merged_into_proxy = 0usize;
    for (key, clean_cand) in &clean_map {
        match proxy_map.get_mut(key) {
            Some(proxy_cand) => {
                proxy_cand.extended_matching |= clean_cand.extended_matching();
                proxy_cand.forced |= clean_cand.is_forced();
            }
            None => {
                proxy_map.insert(key.clone(), clean_cand.to_proxy_candidate());
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
    let [
        (ai_text, ai_stats),
        (payment_text, payment_stats),
        (telemetry_text, telemetry_stats),
    ] = compress_and_partition_clean(clean_map, source_counts);
    let (proxy_text, proxy_stats) = compress_and_render(
        RoutingTarget::Proxy,
        proxy_map,
        source_counts.active_proxy,
        source_counts.total_proxy,
    );

    CompiledRoutingArtifacts {
        direct_text,
        ai_text,
        payment_text,
        telemetry_text,
        proxy_text,
        direct_stats,
        ai_stats,
        payment_stats,
        telemetry_stats,
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
fn find_broadest_suffix_ancestor<'a, V>(
    dom: &str,
    surviving_suffixes: &'a mut BTreeMap<String, V>,
) -> Option<&'a mut V> {
    let dot_positions: Vec<usize> = dom.match_indices('.').map(|(idx, _)| idx).collect();
    for idx in dot_positions.into_iter().rev() {
        let candidate = &dom[idx + 1..];
        if surviving_suffixes.contains_key(candidate) {
            return surviving_suffixes.get_mut(candidate);
        }
    }
    surviving_suffixes.get_mut(dom)
}

/// Compresses the pooled clean-egress rules (`{Ai, Payment, Telemetry}`) using a single unified
/// `DomainTrie` and CIDR aggregation pass, then partitions the surviving rules into three strictly
/// disjoint rule sets (`AI.list`, `Payment.list`, `Telemetry.list`) whose union equals 100% of the
/// compressed clean-egress pool.
fn compress_and_partition_clean(
    rules: FxHashMap<RoutingRuleKey, CleanCandidate>,
    counts: RoutingSourceCounts,
) -> [(String, TargetStats); 3] {
    let mut exact_domains: BTreeMap<String, (CleanSlot, bool)> = BTreeMap::new();
    let mut suffix_domains: BTreeMap<String, (CleanSlot, bool)> = BTreeMap::new();
    let mut keywords: BTreeMap<String, (CleanSlot, bool)> = BTreeMap::new();
    let mut wildcards: BTreeMap<String, (CleanSlot, bool)> = BTreeMap::new();
    let mut url_regexes: BTreeMap<String, (CleanSlot, bool)> = BTreeMap::new();
    let mut user_agents: BTreeMap<String, CleanSlot> = BTreeMap::new();
    let mut process_names: BTreeMap<String, CleanSlot> = BTreeMap::new();
    let mut logical_ands: BTreeMap<String, CleanSlot> = BTreeMap::new();
    let mut raw_v4: Vec<(Ipv4Net, CleanCandidate)> = Vec::new();
    let mut raw_v6: Vec<(Ipv6Net, CleanCandidate)> = Vec::new();
    let mut asns: BTreeMap<u32, CleanSlot> = BTreeMap::new();

    for (key, cand) in rules {
        let owner = cand.owner();
        let ext = cand.extended_matching() && key.kind.supports_extended_matching();
        match key.kind {
            RoutingRuleKind::Domain => {
                exact_domains.insert(key.value, (owner, ext));
            }
            RoutingRuleKind::DomainSuffix => {
                suffix_domains.insert(key.value, (owner, ext));
            }
            RoutingRuleKind::DomainKeyword => {
                keywords.insert(key.value, (owner, ext));
            }
            RoutingRuleKind::DomainWildcard => {
                wildcards.insert(key.value, (owner, ext));
            }
            RoutingRuleKind::UrlRegex => {
                url_regexes.insert(key.value, (owner, ext));
            }
            RoutingRuleKind::UserAgent => {
                user_agents.insert(key.value, owner);
            }
            RoutingRuleKind::ProcessName => {
                process_names.insert(key.value, owner);
            }
            RoutingRuleKind::And => {
                logical_ands.insert(key.value, owner);
            }
            RoutingRuleKind::IpCidr => {
                if let Some(ipnet::IpNet::V4(v4)) = parse_canonical_cidr(&key.value) {
                    raw_v4.push((v4, cand));
                }
            }
            RoutingRuleKind::IpCidr6 => {
                if let Some(ipnet::IpNet::V6(v6)) = parse_canonical_cidr(&key.value) {
                    raw_v6.push((v6, cand));
                }
            }
            RoutingRuleKind::IpAsn => {
                if let Ok(asn) = key.value.parse::<u32>() {
                    asns.insert(asn, owner);
                }
            }
        }
    }

    let mut stats: [TargetStats; 3] = Default::default();

    // 1. Compress DOMAIN-SUFFIX tree and propagate extended-matching flags upward to surviving ancestors.
    let mut sorted_suffixes: Vec<(String, (CleanSlot, bool))> =
        suffix_domains.into_iter().collect();
    sorted_suffixes.sort_by(|a, b| {
        label_count(&a.0)
            .cmp(&label_count(&b.0))
            .then(a.0.cmp(&b.0))
    });

    let mut trie = DomainTrie::default();
    let mut surviving_suffixes: BTreeMap<String, (CleanSlot, bool)> = BTreeMap::new();

    for (dom, (owner, ext)) in sorted_suffixes {
        if !trie.has_suffix_ancestor_or_eq(&dom) {
            trie.insert_suffix(&dom);
            surviving_suffixes.insert(dom, (owner, ext));
        } else if let Some((anc_owner, anc_ext)) =
            find_broadest_suffix_ancestor(&dom, &mut surviving_suffixes)
        {
            *anc_ext |= ext;
            stats[anc_owner.idx()].subsumed_by_trie += 1;
        }
    }

    // 2. Subsume exact DOMAIN entries already covered by a surviving DOMAIN-SUFFIX, preserving extended-matching.
    let mut surviving_exact: BTreeMap<String, (CleanSlot, bool)> = BTreeMap::new();
    for (dom, (owner, ext)) in exact_domains {
        if trie.matches_domain(&dom) {
            if let Some((anc_owner, anc_ext)) =
                find_broadest_suffix_ancestor(&dom, &mut surviving_suffixes)
            {
                *anc_ext |= ext;
                stats[anc_owner.idx()].subsumed_by_trie += 1;
            }
        } else {
            surviving_exact.insert(dom, (owner, ext));
        }
    }

    // 3. Subsume simple `*.tail` DOMAIN-WILDCARD entries covered by a surviving DOMAIN-SUFFIX ancestor.
    let mut surviving_wildcards: BTreeMap<String, (CleanSlot, bool)> = BTreeMap::new();
    for (wc, (owner, ext)) in wildcards {
        if let Some(tail) = wc.strip_prefix("*.")
            && !tail.contains('*')
            && !tail.contains('?')
            && trie.has_suffix_ancestor_or_eq(tail)
        {
            if let Some((anc_owner, anc_ext)) =
                find_broadest_suffix_ancestor(tail, &mut surviving_suffixes)
            {
                *anc_ext |= ext;
                stats[anc_owner.idx()].subsumed_by_trie += 1;
            }
        } else {
            surviving_wildcards.insert(wc, (owner, ext));
        }
    }

    // 4. Filter private/LAN/Fake-IP/Tailscale/Cloudflare-Mesh bogon CIDRs before aggregating.
    raw_v4.retain(|(net, cand)| {
        if overlaps_reserved_v4(*net) {
            stats[cand.owner().idx()].reserved_cidrs_dropped += 1;
            false
        } else {
            true
        }
    });
    raw_v6.retain(|(net, cand)| {
        if overlaps_reserved_v6(*net) {
            stats[cand.owner().idx()].reserved_cidrs_dropped += 1;
            false
        } else {
            true
        }
    });

    let v4_nets: Vec<Ipv4Net> = raw_v4.iter().map(|(n, _)| *n).collect();
    let v6_nets: Vec<Ipv6Net> = raw_v6.iter().map(|(n, _)| *n).collect();
    let coalesced_v4 = Ipv4Net::aggregate(&v4_nets);
    let coalesced_v6 = Ipv6Net::aggregate(&v6_nets);

    let mut owned_v4: Vec<(Ipv4Net, CleanSlot)> = Vec::with_capacity(coalesced_v4.len());
    for agg in coalesced_v4 {
        let mut merged = CleanCandidate::default();
        for (net, cand) in &raw_v4 {
            if agg.prefix_len() <= net.prefix_len() && agg.contains(&net.network()) {
                merged.merge_from(cand);
            }
        }
        owned_v4.push((agg, merged.owner()));
    }

    let mut owned_v6: Vec<(Ipv6Net, CleanSlot)> = Vec::with_capacity(coalesced_v6.len());
    for agg in coalesced_v6 {
        let mut merged = CleanCandidate::default();
        for (net, cand) in &raw_v6 {
            if agg.prefix_len() <= net.prefix_len() && agg.contains(&net.network()) {
                merged.merge_from(cand);
            }
        }
        owned_v6.push((agg, merged.owner()));
    }

    let mut rendered_lines: [Vec<String>; 3] = Default::default();

    for (proc_name, owner) in process_names {
        let slot = owner.idx();
        stats[slot].process_name_count += 1;
        rendered_lines[slot].push(format_routing_rule_line(&RoutingRule {
            key: RoutingRuleKey {
                kind: RoutingRuleKind::ProcessName,
                value: proc_name,
            },
            extended_matching: false,
        }));
    }
    for (ua, owner) in user_agents {
        let slot = owner.idx();
        stats[slot].user_agent_count += 1;
        rendered_lines[slot].push(format_routing_rule_line(&RoutingRule {
            key: RoutingRuleKey {
                kind: RoutingRuleKind::UserAgent,
                value: ua,
            },
            extended_matching: false,
        }));
    }
    for (and_val, owner) in logical_ands {
        let slot = owner.idx();
        stats[slot].logical_and_count += 1;
        rendered_lines[slot].push(format_routing_rule_line(&RoutingRule {
            key: RoutingRuleKey {
                kind: RoutingRuleKind::And,
                value: and_val,
            },
            extended_matching: false,
        }));
    }
    for (dom, (owner, ext)) in surviving_exact {
        let slot = owner.idx();
        stats[slot].domain_count += 1;
        if ext {
            stats[slot].extended_matching_count += 1;
        }
        rendered_lines[slot].push(format_routing_rule_line(&RoutingRule {
            key: RoutingRuleKey {
                kind: RoutingRuleKind::Domain,
                value: dom,
            },
            extended_matching: ext,
        }));
    }
    for (dom, (owner, ext)) in surviving_suffixes {
        let slot = owner.idx();
        stats[slot].domain_suffix_count += 1;
        if ext {
            stats[slot].extended_matching_count += 1;
        }
        rendered_lines[slot].push(format_routing_rule_line(&RoutingRule {
            key: RoutingRuleKey {
                kind: RoutingRuleKind::DomainSuffix,
                value: dom,
            },
            extended_matching: ext,
        }));
    }
    for (kw, (owner, ext)) in keywords {
        let slot = owner.idx();
        stats[slot].domain_keyword_count += 1;
        if ext {
            stats[slot].extended_matching_count += 1;
        }
        rendered_lines[slot].push(format_routing_rule_line(&RoutingRule {
            key: RoutingRuleKey {
                kind: RoutingRuleKind::DomainKeyword,
                value: kw,
            },
            extended_matching: ext,
        }));
    }
    for (wc, (owner, ext)) in surviving_wildcards {
        let slot = owner.idx();
        stats[slot].domain_wildcard_count += 1;
        if ext {
            stats[slot].extended_matching_count += 1;
        }
        rendered_lines[slot].push(format_routing_rule_line(&RoutingRule {
            key: RoutingRuleKey {
                kind: RoutingRuleKind::DomainWildcard,
                value: wc,
            },
            extended_matching: ext,
        }));
    }
    for (re, (owner, ext)) in url_regexes {
        let slot = owner.idx();
        stats[slot].url_regex_count += 1;
        if ext {
            stats[slot].extended_matching_count += 1;
        }
        rendered_lines[slot].push(format_routing_rule_line(&RoutingRule {
            key: RoutingRuleKey {
                kind: RoutingRuleKind::UrlRegex,
                value: re,
            },
            extended_matching: ext,
        }));
    }
    for (v4, owner) in owned_v4 {
        let slot = owner.idx();
        stats[slot].ip_cidr_count += 1;
        rendered_lines[slot].push(format!("IP-CIDR,{},no-resolve", v4));
    }
    for (v6, owner) in owned_v6 {
        let slot = owner.idx();
        stats[slot].ip_cidr6_count += 1;
        rendered_lines[slot].push(format!("IP-CIDR6,{},no-resolve", v6));
    }
    for (asn, owner) in asns {
        let slot = owner.idx();
        stats[slot].ip_asn_count += 1;
        rendered_lines[slot].push(format!("IP-ASN,{},no-resolve", asn));
    }

    let src_pairs = [
        (counts.active_ai, counts.total_ai),
        (counts.active_payment, counts.total_payment),
        (counts.active_telemetry, counts.total_telemetry),
    ];

    let [lines0, lines1, lines2] = rendered_lines;
    let [mut st0, mut st1, mut st2] = stats;
    st0.total_rules = lines0.len();
    st1.total_rules = lines1.len();
    st2.total_rules = lines2.len();

    let text0 = format_ruleset_file(
        RoutingTarget::Ai,
        &lines0,
        &st0,
        src_pairs[0].0,
        src_pairs[0].1,
    );
    let text1 = format_ruleset_file(
        RoutingTarget::Payment,
        &lines1,
        &st1,
        src_pairs[1].0,
        src_pairs[1].1,
    );
    let text2 = format_ruleset_file(
        RoutingTarget::Telemetry,
        &lines2,
        &st2,
        src_pairs[2].0,
        src_pairs[2].1,
    );

    [(text0, st0), (text1, st1), (text2, st2)]
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
    let out = format_ruleset_file(
        target,
        &rendered_lines,
        &stats,
        active_sources,
        total_sources,
    );
    (out, stats)
}

fn format_ruleset_file(
    target: RoutingTarget,
    rendered_lines: &[String],
    stats: &TargetStats,
    active_sources: usize,
    total_sources: usize,
) -> String {
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
        out.push_str(line);
        out.push('\n');
    }
    out
}
