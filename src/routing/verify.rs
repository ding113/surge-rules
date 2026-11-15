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

#[derive(Clone, Debug)]
pub struct RoutingVerificationReport {
    pub direct: AdblockFileSummary,
    pub ai: AdblockFileSummary,
    pub proxy: AdblockFileSummary,
    pub direct_total: usize,
    pub ai_total: usize,
    pub proxy_total: usize,
    pub direct_extended_count: usize,
    pub ai_extended_count: usize,
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
    min_direct_lines: usize,
    min_ai_lines: usize,
    min_proxy_lines: usize,
    check_canaries: bool,
) -> Result<RoutingVerificationReport> {
    let direct_path = dir.join(RoutingTarget::Direct.filename());
    let ai_path = dir.join(RoutingTarget::Ai.filename());
    let proxy_path = dir.join(RoutingTarget::Proxy.filename());

    let direct_raw = fs::read_to_string(&direct_path)
        .with_context(|| format!("missing {}", direct_path.display()))?;
    let ai_raw =
        fs::read_to_string(&ai_path).with_context(|| format!("missing {}", ai_path.display()))?;
    let proxy_raw = fs::read_to_string(&proxy_path)
        .with_context(|| format!("missing {}", proxy_path.display()))?;

    let direct_idx = parse_and_validate_ruleset("Direct.list", &direct_raw, min_direct_lines)?;
    let ai_idx = parse_and_validate_ruleset("AI.list", &ai_raw, min_ai_lines)?;
    let proxy_idx = parse_and_validate_ruleset("Proxy.list", &proxy_raw, min_proxy_lines)?;

    if direct_idx.extended_count != 0 {
        bail!(
            "Direct.list must have 0 extended-matching rules (found {}); a single line enables extended-matching on the whole RULE-SET in Surge",
            direct_idx.extended_count
        );
    }

    verify_shared_infra_safety(&ai_idx, overrides)?;
    verify_ai_subset_of_proxy(&ai_idx, &proxy_idx)?;
    verify_reserved_ip_absence(&direct_idx, &ai_idx, &proxy_idx)?;

    let canaries_checked = if check_canaries {
        run_production_canaries(&direct_idx, &ai_idx, &proxy_idx)?
    } else {
        0
    };

    Ok(RoutingVerificationReport {
        direct: file_summary("Direct.list", direct_raw.as_bytes(), direct_idx.total_rules),
        ai: file_summary("AI.list", ai_raw.as_bytes(), ai_idx.total_rules),
        proxy: file_summary("Proxy.list", proxy_raw.as_bytes(), proxy_idx.total_rules),
        direct_total: direct_idx.total_rules,
        ai_total: ai_idx.total_rules,
        proxy_total: proxy_idx.total_rules,
        direct_extended_count: direct_idx.extended_count,
        ai_extended_count: ai_idx.extended_count,
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
    ai_idx: &ParsedListIndex,
    overrides: &RoutingOverrides,
) -> Result<()> {
    for entry in &overrides.shared_infra_roots {
        let root = entry
            .domain
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if ai_idx.exact_domains.contains_key(&root) || ai_idx.suffix_domains.contains_key(&root) {
            bail!(
                "AI.list unlawfully captures shared infrastructure apex '{}'",
                root
            );
        }
    }
    for non_ai_host in [
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
        "stripe.com",
    ] {
        if ai_idx.covers_domain(non_ai_host) {
            bail!(
                "AI.list false-positive captures shared non-AI host '{}'",
                non_ai_host
            );
        }
    }
    let shared_roots: FxHashSet<String> = overrides
        .shared_infra_roots
        .iter()
        .map(|e| e.domain.trim().trim_end_matches('.').to_ascii_lowercase())
        .collect();
    for and_val in &ai_idx.logical_ands {
        let Some(clauses) = parse_logical_and_clauses(and_val) else {
            bail!("AI.list contains unparseable AND rule '{}'", and_val);
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
                "AI.list AND rule '{}' references shared infrastructure without PROCESS-NAME/USER-AGENT",
                and_val
            );
        }
    }
    Ok(())
}

fn verify_ai_subset_of_proxy(ai_idx: &ParsedListIndex, proxy_idx: &ParsedListIndex) -> Result<()> {
    for (dom, &ext) in &ai_idx.exact_domains {
        if !proxy_idx.covers_domain_with_ext(dom, ext) {
            bail!(
                "Proxy.list is not a strict superset of AI.list: missing or weaker DOMAIN '{}' (extended={})",
                dom,
                ext
            );
        }
    }
    for (sfx, &ext) in &ai_idx.suffix_domains {
        if !proxy_idx.covers_suffix_with_ext(sfx, ext) {
            bail!(
                "Proxy.list is not a strict superset of AI.list: missing or weaker DOMAIN-SUFFIX '{}' (extended={})",
                sfx,
                ext
            );
        }
    }
    for (kw, &ext) in &ai_idx.keywords {
        match proxy_idx.keywords.get(kw) {
            Some(&p_ext) if !ext || p_ext => {}
            _ => bail!(
                "Proxy.list is not a strict superset of AI.list: missing DOMAIN-KEYWORD '{}'",
                kw
            ),
        }
    }
    for (wc, &ext) in &ai_idx.wildcards {
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
                "Proxy.list is not a strict superset of AI.list: missing DOMAIN-WILDCARD '{}'",
                wc
            );
        }
    }
    for (re, &ext) in &ai_idx.url_regexes {
        match proxy_idx.url_regexes.get(re) {
            Some(&p_ext) if !ext || p_ext => {}
            _ => bail!(
                "Proxy.list is not a strict superset of AI.list: missing URL-REGEX '{}'",
                re
            ),
        }
    }
    for ua in &ai_idx.user_agents {
        if !proxy_idx.user_agents.contains(ua) {
            bail!(
                "Proxy.list is not a strict superset of AI.list: missing USER-AGENT '{}'",
                ua
            );
        }
    }
    for proc_name in &ai_idx.process_names {
        if !proxy_idx.process_names.contains(proc_name) {
            bail!(
                "Proxy.list is not a strict superset of AI.list: missing PROCESS-NAME '{}'",
                proc_name
            );
        }
    }
    for and_val in &ai_idx.logical_ands {
        if !proxy_idx.logical_ands.contains(and_val) {
            bail!(
                "Proxy.list is not a strict superset of AI.list: missing AND '{}'",
                and_val
            );
        }
    }
    for ai_v4 in &ai_idx.v4_cidrs {
        if !proxy_idx
            .v4_cidrs
            .iter()
            .any(|p| p.prefix_len() <= ai_v4.prefix_len() && p.contains(&ai_v4.network()))
        {
            bail!(
                "Proxy.list is not a strict superset of AI.list: missing IP-CIDR {}",
                ai_v4
            );
        }
    }
    for ai_v6 in &ai_idx.v6_cidrs {
        if !proxy_idx
            .v6_cidrs
            .iter()
            .any(|p| p.prefix_len() <= ai_v6.prefix_len() && p.contains(&ai_v6.network()))
        {
            bail!(
                "Proxy.list is not a strict superset of AI.list: missing IP-CIDR6 {}",
                ai_v6
            );
        }
    }
    for asn in &ai_idx.asns {
        if !proxy_idx.asns.contains(asn) {
            bail!(
                "Proxy.list is not a strict superset of AI.list: missing IP-ASN,{}",
                asn
            );
        }
    }
    Ok(())
}

fn verify_reserved_ip_absence(
    direct_idx: &ParsedListIndex,
    ai_idx: &ParsedListIndex,
    proxy_idx: &ParsedListIndex,
) -> Result<()> {
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
        for (name, idx) in [
            ("Direct.list", direct_idx),
            ("AI.list", ai_idx),
            ("Proxy.list", proxy_idx),
        ] {
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
    proxy_idx: &ParsedListIndex,
) -> Result<usize> {
    let mut checked = 0usize;

    // 1. Direct domains (Mainland services, CN-only services, domestic AI, CN CDN endpoints)
    for dom in [
        "www.baidu.com",
        "www.qq.com",
        "www.taobao.com",
        "www.bilibili.com",
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
        if ai_idx.covers_domain_exact_or_suffix(dom) {
            bail!(
                "canary failed: AI.list must NOT match domestic/direct domain '{}'",
                dom
            );
        }
        checked += 2;
    }

    // 2. Overseas AI & region-restricted platforms (must match BOTH AI.list AND Proxy.list)
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
        "challenges.cloudflare.com",
        "www.netflix.com",
        "www.disneyplus.com",
        "www.youtube.com",
        "open.spotify.com",
        "www.tiktok.com",
        "ani.gamer.com.tw",
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
        if direct_idx.covers_domain_exact_or_suffix(dom) {
            bail!("canary failed: Direct.list must NOT match '{}'", dom);
        }
        checked += 3;
    }

    // 3. Overseas Proxy domains (non-AI general overseas services must match Proxy.list and NOT Direct.list)
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

    // 4. IP / ASN canaries
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
| `{}` | {} | {} | {} B | `{}` |\n\n\
Verified invariants: `AI.list ⊆ Proxy.list` (100% syntactic & semantic subset), `sharedInfraRoots` apex protection active, reserved/LAN/Fake-IP/Tailscale/Cloudflare-Mesh CIDRs excluded, all IP/ASN entries emit `no-resolve`, and {} production canaries passed.\n",
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
        report.proxy.file_name,
        report.proxy_total,
        report.proxy_extended_count,
        report.proxy.size_bytes,
        report.proxy.sha256,
        report.canaries_checked
    )
}
