use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use ipnet::{Ipv4Net, Ipv6Net};
use regex::Regex;
use rustc_hash::FxHashSet;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::adblock::compiler::{
    CLEAN_EGRESS_FILES, DomainTrie, HumanForcedBlockMatcher, ROUTING_EXACT_ALLOWLIST_FILES,
    TelemetryProtectionSet, overlaps_reserved_v4, overlaps_reserved_v6,
    overlaps_shared_cdn_or_dns_v4, overlaps_shared_cdn_or_dns_v6, wildcard_matches_domain,
    wildcard_static_suffix,
};
use crate::adblock::config::{AdblockOverrides, AllowDomainMatchType};
use crate::adblock::model::{MAX_BINARY_SCRIPT_MAX_SIZE, MAX_SCRIPT_TIMEOUT_SECS};
use crate::adblock::parsers::surge_module::{split_surge_script_params, unquote_surge_value};
use crate::adblock::regex_util::{
    has_balanced_delimiters, is_valid_domain, is_valid_domain_wildcard, is_valid_mitm_host,
    is_valid_positive_mitm_host,
};

#[derive(Clone, Debug, Serialize)]
pub struct AdblockFileSummary {
    pub file_name: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub line_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct AdblockVerificationReport {
    pub ruleset: AdblockFileSummary,
    pub privacy_ruleset: AdblockFileSummary,
    pub module: AdblockFileSummary,
    pub canaries_checked: usize,
    pub ruleset_total: usize,
    pub privacy_ruleset_total: usize,
    pub module_scripts: usize,
    pub module_mitm_hosts: usize,
}

const PURE_AD_CANARIES: &[&str] = &[
    "doubleclick.net",
    "googlesyndication.com",
    "pangolin-sdk-toutiao.com",
    "mobads.baidu.com",
    "pos.baidu.com",
];

const PRIVACY_TRACKER_CANARIES: &[&str] = &[
    "app-measurement.com",
    "scorecardresearch.com",
    "hm.baidu.com",
];

const BENIGN_PROTECTED_CANARIES: &[&str] = &[
    "captive.apple.com",
    "icloud.com",
    "mzstatic.com",
    "alipay.com",
    "githubusercontent.com",
    "s.youtube.com",
    "youtubei.googleapis.com",
    "api.bilibili.com",
    "app.bilibili.com",
    "grpc.biliapi.net",
    "api.weibo.cn",
    "edith.xiaohongshu.com",
    "api.zhihu.com",
    "acs.m.taobao.com",
    "ad.12306.cn",
    "apple.com",
    "google.com",
    "youtube.com",
    "bilibili.com",
    "github.com",
    "weibo.com",
    "zhihu.com",
    "taobao.com",
    "jd.com",
    "qq.com",
];

struct VerifiedRuleset {
    trie: DomainTrie,
    total: usize,
    lines: FxHashSet<String>,
    domains: Vec<String>,
    exact_domains: Vec<String>,
    suffix_domains: Vec<String>,
    keywords: Vec<String>,
    wildcards: Vec<String>,
    cidrs_v4: Vec<Ipv4Net>,
    cidrs_v6: Vec<Ipv6Net>,
}

/// Verifies `Adblock.list`, `Privacy.list`, and `Adblock.sgmodule` against official Surge syntax,
/// strict mutual disjointness (`Adblock.list ∩ Privacy.list = ∅`), and 4-tier protection invariants.
pub fn verify_adblock_dir(
    dir: &Path,
    overrides: &AdblockOverrides,
    min_ruleset_lines: usize,
    min_privacy_lines: usize,
) -> Result<AdblockVerificationReport> {
    let ruleset_path = dir.join("Adblock.list");
    let privacy_path = dir.join("Privacy.list");
    let module_path = dir.join("Adblock.sgmodule");

    let ruleset_raw = fs::read_to_string(&ruleset_path)
        .with_context(|| format!("missing generated ruleset {}", ruleset_path.display()))?;
    let privacy_raw = fs::read_to_string(&privacy_path)
        .with_context(|| format!("missing generated ruleset {}", privacy_path.display()))?;
    let module_raw = fs::read_to_string(&module_path)
        .with_context(|| format!("missing generated module {}", module_path.display()))?;

    let ad_verified = verify_ruleset_text("Adblock.list", &ruleset_raw, min_ruleset_lines)?;
    let priv_verified = verify_ruleset_text("Privacy.list", &privacy_raw, min_privacy_lines)?;

    // Enforce strict mutual disjointness across lines, domain hierarchies, and IPv4/IPv6 CIDRs
    for line in &priv_verified.lines {
        if ad_verified.lines.contains(line) {
            bail!(
                "Adblock.list and Privacy.list must be strictly disjoint, found shared rule '{}'",
                line
            );
        }
    }
    for d in &priv_verified.domains {
        if ad_verified.trie.matches_domain(d) {
            bail!(
                "Privacy.list domain '{}' overlaps with Adblock.list domain/suffix rule",
                d
            );
        }
    }
    for d in &ad_verified.domains {
        if priv_verified.trie.matches_domain(d) {
            bail!(
                "Adblock.list domain '{}' overlaps with Privacy.list domain/suffix rule",
                d
            );
        }
    }
    verify_disjoint_cidrs_v4(&ad_verified.cidrs_v4, &priv_verified.cidrs_v4)?;
    verify_disjoint_cidrs_v6(&ad_verified.cidrs_v6, &priv_verified.cidrs_v6)?;

    // Enforce child-over-parent domain specificity across (Adblock.list ∪ Privacy.list):
    // no surviving DOMAIN-SUFFIX or unforced root DOMAIN may coexist with a strict child subdomain rule.
    let mut combined_emitted_trie = DomainTrie::default();
    for d in ad_verified
        .exact_domains
        .iter()
        .chain(&priv_verified.exact_domains)
    {
        combined_emitted_trie.insert_exact(d);
    }
    for s in ad_verified
        .suffix_domains
        .iter()
        .chain(&priv_verified.suffix_domains)
    {
        combined_emitted_trie.insert_suffix(s);
    }
    let forced_exact_domains: FxHashSet<String> = overrides
        .force_rule_set_entries
        .iter()
        .filter(|f| f.kind == "DOMAIN")
        .map(|f| f.value.trim().trim_end_matches('.').to_ascii_lowercase())
        .collect();
    for s in ad_verified
        .suffix_domains
        .iter()
        .chain(&priv_verified.suffix_domains)
    {
        if combined_emitted_trie.has_strict_descendant_mark(s) {
            bail!(
                "parent DOMAIN-SUFFIX '{}' coexists with a strict child subdomain rule in Adblock.list / Privacy.list",
                s
            );
        }
    }
    for d in ad_verified
        .exact_domains
        .iter()
        .chain(&priv_verified.exact_domains)
    {
        if !forced_exact_domains.contains(d) && combined_emitted_trie.has_strict_descendant_mark(d)
        {
            bail!(
                "unforced parent root DOMAIN '{}' coexists with a strict child subdomain rule in Adblock.list / Privacy.list",
                d
            );
        }
    }

    let (module_scripts, module_mitm_hosts, mitm_exclusions_seen, module_reject_trie) =
        verify_module_text_inner(&module_raw)?;

    let mut human_allow_trie = DomainTrie::default();
    for entry in &overrides.allow_domains {
        let dom = entry
            .domain
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        match entry.match_type {
            AllowDomainMatchType::Exact => human_allow_trie.insert_exact(&dom),
            AllowDomainMatchType::Suffix => human_allow_trie.insert_suffix(&dom),
        }
    }
    let protected_apex_set: FxHashSet<String> = overrides
        .protected_apex_domains
        .iter()
        .map(|a| a.domain.trim().trim_end_matches('.').to_ascii_lowercase())
        .collect();
    let forced_matcher = HumanForcedBlockMatcher::from_overrides(overrides);

    // 1) When clean-egress lists (Telemetry.list, Payment.list, AI.list) are present in the artifact
    //    directory, strictly enforce zero conflict (both DOMAIN and DOMAIN-SUFFIX) against Adblock.list
    //    and Privacy.list unless explicitly overridden by human forceRuleSetEntries.
    for clean_file in CLEAN_EGRESS_FILES {
        let clean_path = dir.join(clean_file);
        if clean_path.exists() {
            let clean_raw = fs::read_to_string(&clean_path).with_context(|| {
                format!("failed reading {} at {}", clean_file, clean_path.display())
            })?;
            let clean_set = TelemetryProtectionSet::from_ruleset_text(&clean_raw);
            let mut clean_trie = DomainTrie::default();
            let mut active_clean_domains = Vec::new();
            for d in &clean_set.exact_domains {
                if human_allow_trie.matches_domain(d)
                    || protected_apex_set.contains(d)
                    || !forced_matcher.conflicts_with_exact(d)
                {
                    clean_trie.insert_exact(d);
                    active_clean_domains.push(d.as_str());
                }
            }
            for s in &clean_set.suffix_domains {
                clean_trie.insert_suffix(s);
                if human_allow_trie.matches_domain(s)
                    || protected_apex_set.contains(s)
                    || !forced_matcher.conflicts_with_suffix(s)
                {
                    active_clean_domains.push(s.as_str());
                }
            }
            for d in active_clean_domains {
                if ad_verified.trie.matches_domain(d) {
                    bail!(
                        "{} domain '{}' is conflicted/blocked by Adblock.list",
                        clean_file,
                        d
                    );
                }
                if priv_verified.trie.matches_domain(d) {
                    bail!(
                        "{} domain '{}' is conflicted/blocked by Privacy.list",
                        clean_file,
                        d
                    );
                }
            }
            for d in &ad_verified.domains {
                let explicitly_forced = !human_allow_trie.matches_domain(d)
                    && !protected_apex_set.contains(d)
                    && forced_matcher.conflicts_with_exact(d);
                if !explicitly_forced && clean_trie.matches_domain(d) {
                    bail!("Adblock.list domain '{}' conflicts with {}", d, clean_file);
                }
            }
            for d in &priv_verified.domains {
                let explicitly_forced = !human_allow_trie.matches_domain(d)
                    && !protected_apex_set.contains(d)
                    && forced_matcher.conflicts_with_exact(d);
                if !explicitly_forced && clean_trie.matches_domain(d) {
                    bail!("Privacy.list domain '{}' conflicts with {}", d, clean_file);
                }
            }
        }
    }

    // 2) For ALL non-adblock/non-privacy routing rule sets (Direct.list, Proxy.list, AI.list,
    //    Payment.list, Telemetry.list), strictly enforce that every exact `DOMAIN` rule (excluding
    //    suffix, wildcard, and keyword rules) is allowlisted and never matched by Adblock.list,
    //    Privacy.list, or Adblock.sgmodule [Rule] REJECT entries (unless explicitly human-forced).
    for routing_file in ROUTING_EXACT_ALLOWLIST_FILES {
        let routing_path = dir.join(routing_file);
        if routing_path.exists() {
            let routing_raw = fs::read_to_string(&routing_path).with_context(|| {
                format!(
                    "failed reading {} at {}",
                    routing_file,
                    routing_path.display()
                )
            })?;
            let exact_set = TelemetryProtectionSet::from_exact_domains_ruleset_text(&routing_raw);
            let mut routing_exact_trie = DomainTrie::default();
            let mut protected_exacts: Vec<&str> = Vec::with_capacity(exact_set.exact_domains.len());
            for d in &exact_set.exact_domains {
                if human_allow_trie.matches_domain(d)
                    || protected_apex_set.contains(d)
                    || !forced_matcher.conflicts_with_exact(d)
                {
                    routing_exact_trie.insert_exact(d);
                    protected_exacts.push(d.as_str());
                }
            }

            for &d in &protected_exacts {
                if ad_verified.trie.matches_domain(d) {
                    bail!(
                        "{} exact DOMAIN '{}' is blocked by Adblock.list domain/suffix rule",
                        routing_file,
                        d
                    );
                }
                if priv_verified.trie.matches_domain(d) {
                    bail!(
                        "{} exact DOMAIN '{}' is blocked by Privacy.list domain/suffix rule",
                        routing_file,
                        d
                    );
                }
                if module_reject_trie.matches_domain(d) {
                    bail!(
                        "{} exact DOMAIN '{}' is blocked by Adblock.sgmodule [Rule] REJECT rule",
                        routing_file,
                        d
                    );
                }
                if let Some(kw) = ad_verified
                    .keywords
                    .iter()
                    .find(|kw| d.contains(kw.as_str()))
                {
                    bail!(
                        "{} exact DOMAIN '{}' is blocked by Adblock.list DOMAIN-KEYWORD '{}'",
                        routing_file,
                        d,
                        kw
                    );
                }
                if let Some(kw) = priv_verified
                    .keywords
                    .iter()
                    .find(|kw| d.contains(kw.as_str()))
                {
                    bail!(
                        "{} exact DOMAIN '{}' is blocked by Privacy.list DOMAIN-KEYWORD '{}'",
                        routing_file,
                        d,
                        kw
                    );
                }
            }

            for (label, wcs) in [
                ("Adblock.list", &ad_verified.wildcards),
                ("Privacy.list", &priv_verified.wildcards),
            ] {
                for wc in wcs {
                    let hit = if let Some(tail) = wildcard_static_suffix(wc) {
                        routing_exact_trie
                            .any_marked_domain_under(tail, |dom| wildcard_matches_domain(wc, dom))
                    } else {
                        protected_exacts
                            .iter()
                            .any(|dom| wildcard_matches_domain(wc, dom))
                    };
                    if hit {
                        bail!(
                            "{} DOMAIN-WILDCARD '{}' blocks a protected exact DOMAIN in {}",
                            label,
                            wc,
                            routing_file
                        );
                    }
                }
            }
        }
    }

    for ex in &overrides.mitm_excluded_hosts {
        let pat = ex.pattern.trim().to_ascii_lowercase();
        if is_valid_mitm_host(&pat) && !mitm_exclusions_seen.contains(&pat) {
            bail!(
                "Adblock.sgmodule [MITM] missing configured exclusion '-{}'",
                pat
            );
        }
    }

    let mut canaries_checked = 0usize;
    for ad in PURE_AD_CANARIES {
        if min_ruleset_lines > 0 && !ad_verified.trie.matches_domain(ad) {
            bail!(
                "expected pure ad canary '{}' to be blocked by Adblock.list",
                ad
            );
        }
        if priv_verified.trie.matches_domain(ad) {
            bail!(
                "pure ad canary '{}' must belong to Adblock.list, not Privacy.list",
                ad
            );
        }
        canaries_checked += 1;
    }

    for tracker in PRIVACY_TRACKER_CANARIES {
        if min_privacy_lines > 0 && !priv_verified.trie.matches_domain(tracker) {
            bail!(
                "expected privacy/tracker canary '{}' to be blocked by Privacy.list",
                tracker
            );
        }
        if ad_verified.trie.matches_domain(tracker) {
            bail!(
                "privacy/tracker canary '{}' must belong to Privacy.list, not Adblock.list",
                tracker
            );
        }
        canaries_checked += 1;
    }

    for benign in BENIGN_PROTECTED_CANARIES {
        if ad_verified.trie.matches_domain(benign) || priv_verified.trie.matches_domain(benign) {
            bail!(
                "protected / first-party functional domain '{}' must NEVER be blocked by Adblock.list or Privacy.list",
                benign
            );
        }
        canaries_checked += 1;
    }

    for allow in &overrides.allow_domains {
        let dom = allow
            .domain
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if ad_verified.trie.matches_domain(&dom) || priv_verified.trie.matches_domain(&dom) {
            bail!(
                "override allowDomain '{}' was unexpectedly matched by Adblock.list or Privacy.list",
                dom
            );
        }
        canaries_checked += 1;
    }

    for apex in &overrides.protected_apex_domains {
        let dom = apex
            .domain
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if ad_verified.trie.matches_domain(&dom) || priv_verified.trie.matches_domain(&dom) {
            bail!(
                "override protectedApexDomain '{}' was unexpectedly matched by Adblock.list or Privacy.list",
                dom
            );
        }
        canaries_checked += 1;
    }

    Ok(AdblockVerificationReport {
        ruleset: file_summary("Adblock.list", ruleset_raw.as_bytes(), ad_verified.total),
        privacy_ruleset: file_summary("Privacy.list", privacy_raw.as_bytes(), priv_verified.total),
        module: file_summary(
            "Adblock.sgmodule",
            module_raw.as_bytes(),
            module_raw.lines().count(),
        ),
        canaries_checked,
        ruleset_total: ad_verified.total,
        privacy_ruleset_total: priv_verified.total,
        module_scripts,
        module_mitm_hosts,
    })
}

fn verify_disjoint_cidrs_v4(ad_cidrs: &[Ipv4Net], priv_cidrs: &[Ipv4Net]) -> Result<()> {
    let mut intervals: Vec<(u32, u32, bool, Ipv4Net)> =
        Vec::with_capacity(ad_cidrs.len() + priv_cidrs.len());
    for &n in ad_cidrs {
        intervals.push((u32::from(n.network()), u32::from(n.broadcast()), false, n));
    }
    for &n in priv_cidrs {
        intervals.push((u32::from(n.network()), u32::from(n.broadcast()), true, n));
    }
    intervals.sort_by_key(|x| (x.0, std::cmp::Reverse(x.1)));
    let mut prev: Option<(u32, bool, Ipv4Net)> = None;
    for (start, end, is_priv, net) in intervals {
        if let Some((prev_end, prev_priv, prev_net)) = prev
            && start <= prev_end
            && is_priv != prev_priv
        {
            bail!(
                "IPv4 CIDR overlap between Adblock.list and Privacy.list: '{}' vs '{}'",
                prev_net,
                net
            );
        }
        if prev.is_none_or(|(pe, _, _)| end > pe) {
            prev = Some((end, is_priv, net));
        }
    }
    Ok(())
}

fn verify_disjoint_cidrs_v6(ad_cidrs: &[Ipv6Net], priv_cidrs: &[Ipv6Net]) -> Result<()> {
    let mut intervals: Vec<(u128, u128, bool, Ipv6Net)> =
        Vec::with_capacity(ad_cidrs.len() + priv_cidrs.len());
    for &n in ad_cidrs {
        intervals.push((u128::from(n.network()), u128::from(n.broadcast()), false, n));
    }
    for &n in priv_cidrs {
        intervals.push((u128::from(n.network()), u128::from(n.broadcast()), true, n));
    }
    intervals.sort_by_key(|x| (x.0, std::cmp::Reverse(x.1)));
    let mut prev: Option<(u128, bool, Ipv6Net)> = None;
    for (start, end, is_priv, net) in intervals {
        if let Some((prev_end, prev_priv, prev_net)) = prev
            && start <= prev_end
            && is_priv != prev_priv
        {
            bail!(
                "IPv6 CIDR overlap between Adblock.list and Privacy.list: '{}' vs '{}'",
                prev_net,
                net
            );
        }
        if prev.is_none_or(|(pe, _, _)| end > pe) {
            prev = Some((end, is_priv, net));
        }
    }
    Ok(())
}

fn verify_ruleset_text(
    file_label: &str,
    text: &str,
    min_ruleset_lines: usize,
) -> Result<VerifiedRuleset> {
    let mut trie = DomainTrie::default();
    let mut total = 0usize;
    let mut lines: FxHashSet<String> = FxHashSet::default();
    let mut domains: Vec<String> = Vec::new();
    let mut exact_domains: Vec<String> = Vec::new();
    let mut suffix_domains: Vec<String> = Vec::new();
    let mut keywords: Vec<String> = Vec::new();
    let mut wildcards: Vec<String> = Vec::new();
    let mut cidrs_v4: Vec<Ipv4Net> = Vec::new();
    let mut cidrs_v6: Vec<Ipv6Net> = Vec::new();

    for (line_no, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with("//")
            || line.starts_with(';')
        {
            continue;
        }
        for forbidden in [
            "##",
            "#@#",
            "#?#",
            "#%#",
            "#@%#",
            "#$#",
            "#@$#",
            "#+js(",
            "$$",
            "FINAL",
            "pre-matching",
            ",REJECT",
            ",DIRECT",
            ",PROXY",
        ] {
            if line.contains(forbidden) {
                bail!(
                    "{} line {} contains illegal token '{}': {}",
                    file_label,
                    line_no + 1,
                    forbidden,
                    line
                );
            }
        }
        if !lines.insert(line.to_string()) {
            bail!(
                "{} line {} duplicate rule '{}'",
                file_label,
                line_no + 1,
                line
            );
        }
        let parts: Vec<&str> = line.split(',').map(str::trim).collect();
        if parts.len() < 2 {
            bail!("{} line {} malformed: {}", file_label, line_no + 1, line);
        }
        let rtype = parts[0];
        let val = parts[1];
        match rtype {
            "DOMAIN" => {
                if !is_valid_domain(val) {
                    bail!(
                        "{} line {} invalid DOMAIN: {}",
                        file_label,
                        line_no + 1,
                        val
                    );
                }
                let low = val.to_ascii_lowercase();
                trie.insert_exact(&low);
                domains.push(low.clone());
                exact_domains.push(low);
            }
            "DOMAIN-SUFFIX" => {
                if !is_valid_domain(val) {
                    bail!(
                        "{} line {} invalid DOMAIN-SUFFIX: {}",
                        file_label,
                        line_no + 1,
                        val
                    );
                }
                let low = val.to_ascii_lowercase();
                trie.insert_suffix(&low);
                domains.push(low.clone());
                suffix_domains.push(low);
            }
            "DOMAIN-KEYWORD" => {
                if val.is_empty() || val.contains(char::is_whitespace) {
                    bail!(
                        "{} line {} invalid DOMAIN-KEYWORD: {}",
                        file_label,
                        line_no + 1,
                        val
                    );
                }
                keywords.push(val.to_ascii_lowercase());
            }
            "DOMAIN-WILDCARD" => {
                if !is_valid_domain_wildcard(val) {
                    bail!(
                        "{} line {} invalid DOMAIN-WILDCARD: {}",
                        file_label,
                        line_no + 1,
                        val
                    );
                }
                wildcards.push(val.to_ascii_lowercase());
            }
            "IP-CIDR" => {
                let net: Ipv4Net = val.parse().with_context(|| {
                    format!(
                        "{} line {} invalid IP-CIDR '{}'",
                        file_label,
                        line_no + 1,
                        val
                    )
                })?;
                if net.trunc() != net {
                    bail!(
                        "{} line {} non-canonical IP-CIDR '{}'",
                        file_label,
                        line_no + 1,
                        val
                    );
                }
                if overlaps_reserved_v4(net) || overlaps_shared_cdn_or_dns_v4(net) {
                    bail!(
                        "{} line {} overlaps reserved/private/shared-CDN/DNS range '{}'",
                        file_label,
                        line_no + 1,
                        val
                    );
                }
                if parts.get(2).copied() != Some("no-resolve") {
                    bail!(
                        "{} line {} IP-CIDR missing no-resolve: {}",
                        file_label,
                        line_no + 1,
                        line
                    );
                }
                cidrs_v4.push(net);
            }
            "IP-CIDR6" => {
                let net: Ipv6Net = val.parse().with_context(|| {
                    format!(
                        "{} line {} invalid IP-CIDR6 '{}'",
                        file_label,
                        line_no + 1,
                        val
                    )
                })?;
                if net.trunc() != net {
                    bail!(
                        "{} line {} non-canonical IP-CIDR6 '{}'",
                        file_label,
                        line_no + 1,
                        val
                    );
                }
                if overlaps_reserved_v6(net) || overlaps_shared_cdn_or_dns_v6(net) {
                    bail!(
                        "{} line {} overlaps reserved/private/shared-CDN/DNS range '{}'",
                        file_label,
                        line_no + 1,
                        val
                    );
                }
                if parts.get(2).copied() != Some("no-resolve") {
                    bail!(
                        "{} line {} IP-CIDR6 missing no-resolve: {}",
                        file_label,
                        line_no + 1,
                        line
                    );
                }
                cidrs_v6.push(net);
            }
            "IP-ASN" => {
                let asn: u32 = val.parse().with_context(|| {
                    format!(
                        "{} line {} invalid IP-ASN '{}'",
                        file_label,
                        line_no + 1,
                        val
                    )
                })?;
                if asn == 0 || parts.get(2).copied() != Some("no-resolve") {
                    bail!(
                        "{} line {} invalid IP-ASN line: {}",
                        file_label,
                        line_no + 1,
                        line
                    );
                }
            }
            "USER-AGENT" | "PROCESS-NAME" => {
                if val.is_empty() {
                    bail!("{} line {} empty {}", file_label, line_no + 1, rtype);
                }
            }
            other => {
                bail!(
                    "{} line {} unsupported rule type '{}'",
                    file_label,
                    line_no + 1,
                    other
                );
            }
        }
        total += 1;
    }

    if total < min_ruleset_lines {
        bail!(
            "{} contains only {} rules (minimum expected: {})",
            file_label,
            total,
            min_ruleset_lines
        );
    }

    Ok(VerifiedRuleset {
        trie,
        total,
        lines,
        domains,
        exact_domains,
        suffix_domains,
        keywords,
        wildcards,
        cidrs_v4,
        cidrs_v6,
    })
}

/// Validates an emitted `Adblock.sgmodule` strictly against Surge's official module specification.
pub fn verify_module_text(text: &str) -> Result<(usize, usize)> {
    let (scripts, hosts, _, _) = verify_module_text_inner(text)?;
    Ok((scripts, hosts))
}

fn verify_module_text_inner(text: &str) -> Result<(usize, usize, FxHashSet<String>, DomainTrie)> {
    if !text.contains("#!name=")
        || !text.contains("#!desc=")
        || !text.contains("#!requirement=CORE_VERSION>=20")
    {
        bail!("Adblock.sgmodule missing required module metadata headers");
    }
    if text.contains("{{{") || text.contains("}}}") {
        bail!("Adblock.sgmodule contains unresolved module argument placeholder");
    }

    let mut cur_section = "";
    let mut script_names: FxHashSet<String> = FxHashSet::default();
    let mut script_triggers: FxHashSet<(String, String)> = FxHashSet::default();
    let mut mitm_hosts_count = 0usize;
    let mut mitm_exclusions_seen: FxHashSet<String> = FxHashSet::default();
    let mut module_reject_trie = DomainTrie::default();
    let mut has_mitm_section = false;

    for (line_no, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with("//")
        {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            cur_section = line;
            if !matches!(
                cur_section,
                "[General]"
                    | "[Rule]"
                    | "[Header Rewrite]"
                    | "[URL Rewrite]"
                    | "[Body Rewrite]"
                    | "[Map Local]"
                    | "[Script]"
                    | "[MITM]"
            ) {
                bail!(
                    "Adblock.sgmodule line {} contains unexpected section {}",
                    line_no + 1,
                    cur_section
                );
            }
            if cur_section == "[MITM]" {
                has_mitm_section = true;
            }
            continue;
        }

        match cur_section {
            "[General]" => {
                let Some((_k, v)) = line.split_once('=') else {
                    bail!(
                        "Adblock.sgmodule line {} malformed [General] line: {}",
                        line_no + 1,
                        line
                    );
                };
                let trimmed_v = v.trim();
                let list_rest = if let Some(r) = trimmed_v.strip_prefix("%INSERT%") {
                    Some((true, r))
                } else {
                    trimmed_v.strip_prefix("%APPEND%").map(|r| (false, r))
                };
                if let Some((is_insert, rest)) = list_rest {
                    let mut seen_pos = false;
                    let mut has_neg = false;
                    for item in rest.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                        if item.starts_with('-') {
                            has_neg = true;
                            if seen_pos {
                                bail!(
                                    "Adblock.sgmodule line {} [General] exclusion '{}' appears after positive hosts",
                                    line_no + 1,
                                    item
                                );
                            }
                        } else {
                            seen_pos = true;
                        }
                    }
                    if has_neg && !is_insert {
                        bail!(
                            "Adblock.sgmodule line {} [General] exclusion-bearing list must use %INSERT%",
                            line_no + 1
                        );
                    }
                }
            }
            "[Header Rewrite]" => {
                let toks: Vec<&str> = line.split_whitespace().collect();
                if toks.len() < 4 || !matches!(toks[0], "http-request" | "http-response") {
                    bail!(
                        "Adblock.sgmodule line {} invalid [Header Rewrite]: {}",
                        line_no + 1,
                        line
                    );
                }
                let field = toks[3];
                if field.eq_ignore_ascii_case("content-length")
                    || field.eq_ignore_ascii_case("transfer-encoding")
                {
                    bail!(
                        "Adblock.sgmodule line {} mutates forbidden header '{}'",
                        line_no + 1,
                        field
                    );
                }
            }
            "[URL Rewrite]" => {
                let toks: Vec<&str> = line.split_whitespace().collect();
                if toks.len() != 3 || !matches!(toks[2], "header" | "302" | "307" | "reject") {
                    bail!(
                        "Adblock.sgmodule line {} invalid [URL Rewrite] mode: {}",
                        line_no + 1,
                        line
                    );
                }
            }
            "[Map Local]" => {
                if !line.contains("data-type=") {
                    bail!(
                        "Adblock.sgmodule line {} [Map Local] missing data-type: {}",
                        line_no + 1,
                        line
                    );
                }
                if line.contains("data-type=file")
                    && !(line.contains("data=\"https://") || line.contains("data=\"http://"))
                {
                    bail!(
                        "Adblock.sgmodule line {} [Map Local] must not rely on unresolved file path: {}",
                        line_no + 1,
                        line
                    );
                }
            }
            "[Body Rewrite]" => {
                let toks: Vec<&str> = line.split_whitespace().collect();
                let valid = match toks.first().copied() {
                    Some("http-request-jq" | "http-response-jq") => toks.len() >= 3,
                    Some("http-request" | "http-response") => toks.len() >= 4,
                    _ => false,
                };
                if !valid {
                    bail!(
                        "Adblock.sgmodule line {} invalid [Body Rewrite]: {}",
                        line_no + 1,
                        line
                    );
                }
            }
            "[Script]" => {
                let Some((name, rhs)) = line.split_once('=') else {
                    bail!(
                        "Adblock.sgmodule line {} malformed [Script] line: {}",
                        line_no + 1,
                        line
                    );
                };
                let clean_name = name.trim();
                if clean_name.is_empty() || !script_names.insert(clean_name.to_string()) {
                    bail!(
                        "Adblock.sgmodule line {} duplicate or empty script name '{}'",
                        line_no + 1,
                        clean_name
                    );
                }
                let params = split_surge_script_params(rhs)?;
                let mut stype = None;
                let mut spattern = None;
                let mut spath = None;
                let mut sengine = None;
                let mut srequires_body = false;
                let mut smax_size: Option<i64> = None;
                let mut stimeout: Option<u32> = None;
                for p in params {
                    let Some((k, raw_v)) = p.split_once('=') else {
                        bail!(
                            "Adblock.sgmodule line {} [Script] malformed parameter '{}'",
                            line_no + 1,
                            p
                        );
                    };
                    let val = unquote_surge_value(raw_v);
                    match k.trim() {
                        "type" => stype = Some(val),
                        "pattern" => spattern = Some(val),
                        "script-path" => spath = Some(val),
                        "engine" => sengine = Some(val),
                        "requires-body" => {
                            srequires_body = matches!(val.as_str(), "true" | "1");
                        }
                        "max-size" => {
                            let parsed = val.parse::<i64>().with_context(|| {
                                format!(
                                    "Adblock.sgmodule line {} [Script] invalid max-size '{}'",
                                    line_no + 1,
                                    val
                                )
                            })?;
                            smax_size = Some(parsed);
                        }
                        "timeout" => {
                            let parsed = val.parse::<u32>().with_context(|| {
                                format!(
                                    "Adblock.sgmodule line {} [Script] invalid timeout '{}'",
                                    line_no + 1,
                                    val
                                )
                            })?;
                            stimeout = Some(parsed);
                        }
                        _ => {}
                    }
                }
                let (Some(st), Some(sp), Some(url)) = (stype, spattern, spath) else {
                    bail!(
                        "Adblock.sgmodule line {} [Script] missing type/pattern/script-path: {}",
                        line_no + 1,
                        line
                    );
                };
                if sengine.as_deref() != Some("jsc") {
                    bail!(
                        "Adblock.sgmodule line {} [Script] '{}' must specify engine=jsc (got {:?}) to prevent WKWebView memory spikes",
                        line_no + 1,
                        clean_name,
                        sengine
                    );
                }
                if srequires_body {
                    match smax_size {
                        Some(sz) if (1..=MAX_BINARY_SCRIPT_MAX_SIZE).contains(&sz) => {}
                        other => bail!(
                            "Adblock.sgmodule line {} [Script] '{}' requires-body=true must have bounded positive max-size <= {} (got {:?})",
                            line_no + 1,
                            clean_name,
                            MAX_BINARY_SCRIPT_MAX_SIZE,
                            other
                        ),
                    }
                } else if let Some(sz) = smax_size
                    && !(1..=MAX_BINARY_SCRIPT_MAX_SIZE).contains(&sz)
                {
                    bail!(
                        "Adblock.sgmodule line {} [Script] '{}' invalid max-size={}",
                        line_no + 1,
                        clean_name,
                        sz
                    );
                }
                if let Some(t) = stimeout
                    && !(1..=MAX_SCRIPT_TIMEOUT_SECS).contains(&t)
                {
                    bail!(
                        "Adblock.sgmodule line {} [Script] '{}' timeout={} exceeds safe ceiling {}s",
                        line_no + 1,
                        clean_name,
                        t,
                        MAX_SCRIPT_TIMEOUT_SECS
                    );
                }
                if !matches!(st.as_str(), "http-request" | "http-response")
                    || !url.starts_with("https://")
                {
                    bail!(
                        "Adblock.sgmodule line {} invalid script type or URL: {}",
                        line_no + 1,
                        line
                    );
                }
                let rust_probe = sp.replace("(?>", "(?:");
                if sp.is_empty()
                    || !sp.is_ascii()
                    || !has_balanced_delimiters(&sp)
                    || (!sp.contains("(?=")
                        && !sp.contains("(?!")
                        && !sp.contains("(?<=")
                        && !sp.contains("(?<!")
                        && Regex::new(&rust_probe).is_err())
                {
                    bail!(
                        "Adblock.sgmodule line {} invalid script regex '{}'",
                        line_no + 1,
                        sp
                    );
                }
                if !script_triggers.insert((st.clone(), sp.clone())) {
                    bail!(
                        "Adblock.sgmodule line {} colliding [Script] trigger ({}, {})",
                        line_no + 1,
                        st,
                        sp
                    );
                }
            }
            "[MITM]" => {
                let Some((k, v)) = line.split_once('=') else {
                    bail!(
                        "Adblock.sgmodule line {} malformed [MITM] line: {}",
                        line_no + 1,
                        line
                    );
                };
                if k.trim() != "hostname" {
                    bail!(
                        "Adblock.sgmodule line {} unexpected [MITM] key '{}'",
                        line_no + 1,
                        k.trim()
                    );
                }
                let Some(rest) = v.trim().strip_prefix("%INSERT%") else {
                    bail!("Adblock.sgmodule [MITM] hostname must use %INSERT%");
                };
                let mut seen_positive = false;
                for item in rest.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    if let Some(excluded) = item.strip_prefix('-') {
                        if seen_positive {
                            bail!(
                                "Adblock.sgmodule [MITM] exclusion '{}' appears after positive hostnames",
                                item
                            );
                        }
                        if !is_valid_mitm_host(excluded) {
                            bail!("Adblock.sgmodule [MITM] invalid excluded host '{}'", item);
                        }
                        mitm_exclusions_seen.insert(excluded.to_ascii_lowercase());
                    } else {
                        seen_positive = true;
                        if !is_valid_positive_mitm_host(item) {
                            bail!(
                                "Adblock.sgmodule [MITM] invalid or wildcard positive host '{}' (only exact domains allowed)",
                                item
                            );
                        }
                        mitm_hosts_count += 1;
                    }
                }
            }
            "[Rule]" => {
                let parts: Vec<&str> = line.split(',').map(str::trim).collect();
                if parts.len() >= 3
                    && parts
                        .iter()
                        .any(|p| p.to_ascii_uppercase().starts_with("REJECT"))
                {
                    match parts[0].to_ascii_uppercase().as_str() {
                        "DOMAIN" => {
                            let d = parts[1].trim_end_matches('.').to_ascii_lowercase();
                            if is_valid_domain(&d) {
                                module_reject_trie.insert_exact(&d);
                            }
                        }
                        "DOMAIN-SUFFIX" => {
                            let s = parts[1]
                                .trim_start_matches('.')
                                .trim_end_matches('.')
                                .to_ascii_lowercase();
                            if is_valid_domain(&s) {
                                module_reject_trie.insert_suffix(&s);
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    if !has_mitm_section {
        bail!("Adblock.sgmodule missing [MITM] section");
    }

    Ok((
        script_names.len(),
        mitm_hosts_count,
        mitm_exclusions_seen,
        module_reject_trie,
    ))
}

pub fn file_summary(name: &str, bytes: &[u8], line_count: usize) -> AdblockFileSummary {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    AdblockFileSummary {
        file_name: name.to_string(),
        size_bytes: bytes.len() as u64,
        sha256: hex::encode(hasher.finalize()),
        line_count,
    }
}

pub fn render_adblock_release_notes(
    report: &AdblockVerificationReport,
    active_sources: usize,
    total_sources: usize,
    suppressed_by_protection: usize,
    subsumed_by_trie: usize,
) -> String {
    format!(
        "## Adblock & Privacy\n\
        - 活跃上游数据源：`{active} / {total}`（自动保护与作用域白名单过滤 `{suppr}` 条、统一前缀树 subsumption 去重 `{subsumed}` 条）\n\
        - `Adblock.list`（广告与安全威胁）：共 `{ad_rules}` 条 Surge RULE-SET 规则，大小 `{rbytes}` B，SHA-256 `{rsha}`\n\
        - `Privacy.list`（隐私跟踪与遥测）：共 `{priv_rules}` 条 Surge RULE-SET 规则，大小 `{pbytes}` B，SHA-256 `{psha}`\n\
        - `Adblock.sgmodule`：包含 `{scripts}` 条无冲突脚本规则与 `{mitm}` 个按需精确 MITM 解密域名（无通配符，`-` 固定证书域名均置顶排除），大小 `{mbytes}` B，SHA-256 `{msha}`\n\
        - 校验通过：`Adblock.list ∩ Privacy.list = ∅` 严格互不重合，且 `{canaries}` 项正反金丝雀断言与 Surge 模块格式校验全部通过\n\n\
        ```ini\n\
        [Rule]\n\
        RULE-SET,https://rule-set.ygxz.de/Adblock.list,REJECT,extended-matching\n\
        RULE-SET,https://rule-set.ygxz.de/Privacy.list,REJECT,extended-matching\n\
        ```\n\
        模块直链：`https://rule-set.ygxz.de/Adblock.sgmodule`\n",
        active = active_sources,
        total = total_sources,
        ad_rules = report.ruleset_total,
        priv_rules = report.privacy_ruleset_total,
        suppr = suppressed_by_protection,
        subsumed = subsumed_by_trie,
        rbytes = report.ruleset.size_bytes,
        rsha = report.ruleset.sha256,
        pbytes = report.privacy_ruleset.size_bytes,
        psha = report.privacy_ruleset.sha256,
        scripts = report.module_scripts,
        mitm = report.module_mitm_hosts,
        mbytes = report.module.size_bytes,
        msha = report.module.sha256,
        canaries = report.canaries_checked,
    )
}
