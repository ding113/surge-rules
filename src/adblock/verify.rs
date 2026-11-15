use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use ipnet::{Ipv4Net, Ipv6Net};
use regex::Regex;
use rustc_hash::FxHashSet;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::adblock::compiler::{
    DomainTrie, overlaps_reserved_v4, overlaps_reserved_v6, overlaps_shared_cdn_or_dns_v4,
    overlaps_shared_cdn_or_dns_v6,
};
use crate::adblock::config::AdblockOverrides;
use crate::adblock::model::{MAX_BINARY_SCRIPT_MAX_SIZE, MAX_SCRIPT_TIMEOUT_SECS};
use crate::adblock::parsers::surge_module::{split_surge_script_params, unquote_surge_value};
use crate::adblock::regex_util::{
    has_balanced_delimiters, is_valid_domain, is_valid_domain_wildcard, is_valid_mitm_host,
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
    pub module: AdblockFileSummary,
    pub canaries_checked: usize,
    pub ruleset_total: usize,
    pub module_scripts: usize,
    pub module_mitm_hosts: usize,
}

const PURE_AD_CANARIES: &[&str] = &[
    "doubleclick.net",
    "googlesyndication.com",
    "app-measurement.com",
    "mobads.baidu.com",
    "pos.baidu.com",
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

/// Verifies `Adblock.list` and `Adblock.sgmodule` against official Surge syntax and protection invariants.
pub fn verify_adblock_dir(
    dir: &Path,
    overrides: &AdblockOverrides,
    min_ruleset_lines: usize,
) -> Result<AdblockVerificationReport> {
    let ruleset_path = dir.join("Adblock.list");
    let module_path = dir.join("Adblock.sgmodule");

    let ruleset_raw = fs::read_to_string(&ruleset_path)
        .with_context(|| format!("missing generated ruleset {}", ruleset_path.display()))?;
    let module_raw = fs::read_to_string(&module_path)
        .with_context(|| format!("missing generated module {}", module_path.display()))?;

    let (domain_trie, ruleset_total) = verify_ruleset_text(&ruleset_raw, min_ruleset_lines)?;
    let (module_scripts, module_mitm_hosts, mitm_exclusions_seen) =
        verify_module_text_inner(&module_raw)?;

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
        if min_ruleset_lines > 0 && !domain_trie.matches_domain(ad) {
            bail!(
                "expected pure ad canary '{}' to be blocked by Adblock.list",
                ad
            );
        }
        canaries_checked += 1;
    }

    for benign in BENIGN_PROTECTED_CANARIES {
        if domain_trie.matches_domain(benign) {
            bail!(
                "protected / first-party functional domain '{}' must NEVER be blocked by Adblock.list",
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
        if domain_trie.matches_domain(&dom) {
            bail!(
                "override allowDomain '{}' was unexpectedly matched by Adblock.list",
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
        if domain_trie.matches_domain(&dom) {
            bail!(
                "override protectedApexDomain '{}' was unexpectedly matched by Adblock.list",
                dom
            );
        }
        canaries_checked += 1;
    }

    Ok(AdblockVerificationReport {
        ruleset: file_summary("Adblock.list", ruleset_raw.as_bytes(), ruleset_total),
        module: file_summary(
            "Adblock.sgmodule",
            module_raw.as_bytes(),
            module_raw.lines().count(),
        ),
        canaries_checked,
        ruleset_total,
        module_scripts,
        module_mitm_hosts,
    })
}

fn verify_ruleset_text(text: &str, min_ruleset_lines: usize) -> Result<(DomainTrie, usize)> {
    let mut trie = DomainTrie::default();
    let mut total = 0usize;

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
                    "Adblock.list line {} contains illegal token '{}': {}",
                    line_no + 1,
                    forbidden,
                    line
                );
            }
        }
        let parts: Vec<&str> = line.split(',').map(str::trim).collect();
        if parts.len() < 2 {
            bail!("Adblock.list line {} malformed: {}", line_no + 1, line);
        }
        let rtype = parts[0];
        let val = parts[1];
        match rtype {
            "DOMAIN" => {
                if !is_valid_domain(val) {
                    bail!("Adblock.list line {} invalid DOMAIN: {}", line_no + 1, val);
                }
                trie.insert_exact(val);
            }
            "DOMAIN-SUFFIX" => {
                if !is_valid_domain(val) {
                    bail!(
                        "Adblock.list line {} invalid DOMAIN-SUFFIX: {}",
                        line_no + 1,
                        val
                    );
                }
                trie.insert_suffix(val);
            }
            "DOMAIN-KEYWORD" => {
                if val.is_empty() || val.contains(char::is_whitespace) {
                    bail!(
                        "Adblock.list line {} invalid DOMAIN-KEYWORD: {}",
                        line_no + 1,
                        val
                    );
                }
            }
            "DOMAIN-WILDCARD" => {
                if !is_valid_domain_wildcard(val) {
                    bail!(
                        "Adblock.list line {} invalid DOMAIN-WILDCARD: {}",
                        line_no + 1,
                        val
                    );
                }
            }
            "IP-CIDR" => {
                let net: Ipv4Net = val.parse().with_context(|| {
                    format!(
                        "Adblock.list line {} invalid IP-CIDR '{}'",
                        line_no + 1,
                        val
                    )
                })?;
                if net.trunc() != net {
                    bail!(
                        "Adblock.list line {} non-canonical IP-CIDR '{}'",
                        line_no + 1,
                        val
                    );
                }
                if overlaps_reserved_v4(net) || overlaps_shared_cdn_or_dns_v4(net) {
                    bail!(
                        "Adblock.list line {} overlaps reserved/private/shared-CDN/DNS range '{}'",
                        line_no + 1,
                        val
                    );
                }
                if parts.get(2).copied() != Some("no-resolve") {
                    bail!(
                        "Adblock.list line {} IP-CIDR missing no-resolve: {}",
                        line_no + 1,
                        line
                    );
                }
            }
            "IP-CIDR6" => {
                let net: Ipv6Net = val.parse().with_context(|| {
                    format!(
                        "Adblock.list line {} invalid IP-CIDR6 '{}'",
                        line_no + 1,
                        val
                    )
                })?;
                if net.trunc() != net {
                    bail!(
                        "Adblock.list line {} non-canonical IP-CIDR6 '{}'",
                        line_no + 1,
                        val
                    );
                }
                if overlaps_reserved_v6(net) || overlaps_shared_cdn_or_dns_v6(net) {
                    bail!(
                        "Adblock.list line {} overlaps reserved/private/shared-CDN/DNS range '{}'",
                        line_no + 1,
                        val
                    );
                }
                if parts.get(2).copied() != Some("no-resolve") {
                    bail!(
                        "Adblock.list line {} IP-CIDR6 missing no-resolve: {}",
                        line_no + 1,
                        line
                    );
                }
            }
            "IP-ASN" => {
                let asn: u32 = val.parse().with_context(|| {
                    format!("Adblock.list line {} invalid IP-ASN '{}'", line_no + 1, val)
                })?;
                if asn == 0 || parts.get(2).copied() != Some("no-resolve") {
                    bail!(
                        "Adblock.list line {} invalid IP-ASN line: {}",
                        line_no + 1,
                        line
                    );
                }
            }
            "USER-AGENT" | "PROCESS-NAME" => {
                if val.is_empty() {
                    bail!("Adblock.list line {} empty {}", line_no + 1, rtype);
                }
            }
            other => {
                bail!(
                    "Adblock.list line {} unsupported rule type '{}'",
                    line_no + 1,
                    other
                );
            }
        }
        total += 1;
    }

    if total < min_ruleset_lines {
        bail!(
            "Adblock.list contains only {} rules (minimum expected: {})",
            total,
            min_ruleset_lines
        );
    }

    Ok((trie, total))
}

/// Validates an emitted `Adblock.sgmodule` strictly against Surge's official module specification.
pub fn verify_module_text(text: &str) -> Result<(usize, usize)> {
    let (scripts, hosts, _) = verify_module_text_inner(text)?;
    Ok((scripts, hosts))
}

fn verify_module_text_inner(text: &str) -> Result<(usize, usize, FxHashSet<String>)> {
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
                        if !is_valid_mitm_host(item) {
                            bail!("Adblock.sgmodule [MITM] invalid host '{}'", item);
                        }
                        mitm_hosts_count += 1;
                    }
                }
            }
            _ => {}
        }
    }

    if !has_mitm_section {
        bail!("Adblock.sgmodule missing [MITM] section");
    }

    Ok((script_names.len(), mitm_hosts_count, mitm_exclusions_seen))
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
        - 活跃上游数据源：`{active} / {total}`\n\
        - `Adblock.list`：共 `{rules}` 条 Surge RULE-SET 规则（自动保护与白名单过滤 `{suppr}` 条、前缀树 subsumption 去重 `{subsumed}` 条），大小 `{rbytes}` B，SHA-256 `{rsha}`\n\
        - `Adblock.sgmodule`：包含 `{scripts}` 条无冲突脚本规则与 `{mitm}` 个 MITM 解密域名（`-` 固定证书域名均置顶排除），大小 `{mbytes}` B，SHA-256 `{msha}`\n\
        - 校验通过：`{canaries}` 项正反金丝雀断言与 Surge 模块格式严格校验全部通过\n\n\
        ```ini\n\
        [Rule]\n\
        RULE-SET,https://github.com/ding113/surge-rules/releases/latest/download/Adblock.list,REJECT,extended-matching\n\
        ```\n\
        模块直链：`https://github.com/ding113/surge-rules/releases/latest/download/Adblock.sgmodule`\n",
        active = active_sources,
        total = total_sources,
        rules = report.ruleset_total,
        suppr = suppressed_by_protection,
        subsumed = subsumed_by_trie,
        rbytes = report.ruleset.size_bytes,
        rsha = report.ruleset.sha256,
        scripts = report.module_scripts,
        mitm = report.module_mitm_hosts,
        mbytes = report.module.size_bytes,
        msha = report.module.sha256,
        canaries = report.canaries_checked,
    )
}
