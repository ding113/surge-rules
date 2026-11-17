use std::fs;
use std::path::Path;

use proptest::prelude::*;
use tempfile::tempdir;

use surge_rules::adblock::config::AdblockOverrides;
use surge_rules::routing::compiler::{
    CnCidrExclusionSet, CompiledRoutingArtifacts, RoutingSourceCounts, compile_routing,
    compile_routing_with_cn_exclusions,
};
use surge_rules::routing::config::{
    GeositeTagFilter, RoutingExclusionOverride, RoutingOverrides, RoutingRuleKind,
    RoutingRuleOverride, RoutingSourceConfig, RoutingSourceFormat, RoutingTarget,
    SharedInfraRootEntry,
};
use surge_rules::routing::model::{
    ParsedRoutingSource, RoutingRule, RoutingRuleKey, format_routing_rule_line,
    normalize_logical_and_value, normalize_rule_value, parse_logical_and_clauses,
};
use surge_rules::routing::parsers::parse_routing_source;
use surge_rules::routing::verify::{RoutingThresholds, verify_routing_dir};

fn write_compiled_dir(dir: &Path, compiled: &CompiledRoutingArtifacts) {
    fs::write(dir.join("Direct.list"), &compiled.direct_text).unwrap();
    fs::write(dir.join("AI.list"), &compiled.ai_text).unwrap();
    fs::write(dir.join("Payment.list"), &compiled.payment_text).unwrap();
    fs::write(dir.join("Telemetry.list"), &compiled.telemetry_text).unwrap();
    fs::write(dir.join("Proxy.list"), &compiled.proxy_text).unwrap();
}

fn write_raw_lists(
    dir: &Path,
    direct: &str,
    ai: &str,
    payment: &str,
    telemetry: &str,
    proxy: &str,
) {
    fs::write(dir.join("Direct.list"), direct).unwrap();
    fs::write(dir.join("AI.list"), ai).unwrap();
    fs::write(dir.join("Payment.list"), payment).unwrap();
    fs::write(dir.join("Telemetry.list"), telemetry).unwrap();
    fs::write(dir.join("Proxy.list"), proxy).unwrap();
}

fn rule_lines(text: &str) -> std::collections::BTreeSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect()
}

fn dummy_source_cfg(
    id: &str,
    target: RoutingTarget,
    lineage: &str,
    format: RoutingSourceFormat,
    geosite_filter: Option<GeositeTagFilter>,
    weight: u16,
) -> RoutingSourceConfig {
    RoutingSourceConfig {
        id: id.to_string(),
        name: id.to_string(),
        target,
        lineage: lineage.to_string(),
        format,
        geosite_filter,
        weight,
        core: true,
        endpoints: Vec::new(),
    }
}

fn encode_base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn rule(kind: RoutingRuleKind, value: &str, extended: bool) -> RoutingRule {
    RoutingRule {
        key: RoutingRuleKey {
            kind,
            value: value.to_string(),
        },
        extended_matching: extended && kind.supports_extended_matching(),
    }
}

#[test]
fn parse_surge_ruleset_and_clash_classical_strips_policies_and_preserves_extended() {
    let input = "\
# comment
[Rule]
DOMAIN-SUFFIX,openai.com,Proxy
DOMAIN,chatgpt.com,AI,extended-matching
DOMAIN-KEYWORD,claude,Proxy,pre-matching,force-remote-dns
URL-REGEX,^https://api\\.openai\\.com/v[0-9]{1,3}/(a,b),Proxy,extended-matching
IP-ASN,AS62041,Proxy,no-resolve
PROCESS-NAME,Cursor,Proxy
FINAL,Proxy
";
    let cfg = dummy_source_cfg(
        "test_ruleset",
        RoutingTarget::Ai,
        "test",
        RoutingSourceFormat::SurgeRuleset,
        None,
        90,
    );
    let parsed = parse_routing_source(input.as_bytes(), &cfg).unwrap();

    assert!(
        parsed
            .rules
            .contains(&rule(RoutingRuleKind::DomainSuffix, "openai.com", false))
    );
    assert!(
        parsed
            .rules
            .contains(&rule(RoutingRuleKind::Domain, "chatgpt.com", true))
    );
    assert!(
        parsed
            .rules
            .contains(&rule(RoutingRuleKind::DomainKeyword, "claude", false))
    );
    assert!(parsed.rules.contains(&rule(
        RoutingRuleKind::UrlRegex,
        "^https://api\\.openai\\.com/v[0-9]{1,3}/(a,b)",
        true
    )));
    assert!(
        parsed
            .rules
            .contains(&rule(RoutingRuleKind::IpAsn, "62041", false))
    );
    assert!(
        parsed
            .rules
            .contains(&rule(RoutingRuleKind::ProcessName, "Cursor", false))
    );
    assert_eq!(parsed.rules.len(), 6);
}

#[test]
fn parse_domain_set_and_clash_yaml_variants() {
    let domainset = "\
.openai.com
chat.openai.com
*.githubcopilot.com
";
    let ds_cfg = dummy_source_cfg(
        "ds",
        RoutingTarget::Ai,
        "ds",
        RoutingSourceFormat::DomainSet,
        None,
        85,
    );
    let ds_parsed = parse_routing_source(domainset.as_bytes(), &ds_cfg).unwrap();
    assert!(
        ds_parsed
            .rules
            .contains(&rule(RoutingRuleKind::DomainSuffix, "openai.com", false))
    );
    assert!(
        ds_parsed
            .rules
            .contains(&rule(RoutingRuleKind::Domain, "chat.openai.com", false))
    );
    assert!(ds_parsed.rules.contains(&rule(
        RoutingRuleKind::DomainWildcard,
        "*.githubcopilot.com",
        false
    )));

    let yaml = "\
payload:
  - '+.anthropic.com' # suffix
  - '.claude.ai'
  - '*.cursor.sh'
  - 'api2.cursor.sh'
  - 'DOMAIN-SUFFIX,perplexity.ai,Proxy'
  - '149.154.160.0/20'
";
    let yaml_cfg = dummy_source_cfg(
        "yaml",
        RoutingTarget::Proxy,
        "yaml",
        RoutingSourceFormat::ClashYaml,
        None,
        90,
    );
    let yaml_parsed = parse_routing_source(yaml.as_bytes(), &yaml_cfg).unwrap();
    assert!(yaml_parsed.rules.contains(&rule(
        RoutingRuleKind::DomainSuffix,
        "anthropic.com",
        false
    )));
    assert!(
        yaml_parsed
            .rules
            .contains(&rule(RoutingRuleKind::DomainSuffix, "claude.ai", false))
    );
    assert!(yaml_parsed.rules.contains(&rule(
        RoutingRuleKind::DomainWildcard,
        "*.cursor.sh",
        false
    )));
    assert!(
        yaml_parsed
            .rules
            .contains(&rule(RoutingRuleKind::Domain, "api2.cursor.sh", false))
    );
    assert!(yaml_parsed.rules.contains(&rule(
        RoutingRuleKind::DomainSuffix,
        "perplexity.ai",
        false
    )));
    assert!(
        yaml_parsed
            .rules
            .contains(&rule(RoutingRuleKind::IpCidr, "149.154.160.0/20", false))
    );

    let zone_set = "\
# Zone / DNS domain list
*.oisd-example.org
pornhub.com # inline comment
full:exact-only.example.net
||abp-zone.io^
@@||whitelisted.io^
";
    let zs_cfg = dummy_source_cfg(
        "zs",
        RoutingTarget::Proxy,
        "zs",
        RoutingSourceFormat::DomainSuffixSet,
        None,
        85,
    );
    let zs_parsed = parse_routing_source(zone_set.as_bytes(), &zs_cfg).unwrap();
    assert!(zs_parsed.rules.contains(&rule(
        RoutingRuleKind::DomainSuffix,
        "oisd-example.org",
        false
    )));
    assert!(
        zs_parsed
            .rules
            .contains(&rule(RoutingRuleKind::DomainSuffix, "pornhub.com", false))
    );
    assert!(zs_parsed.rules.contains(&rule(
        RoutingRuleKind::Domain,
        "exact-only.example.net",
        false
    )));
    assert!(
        zs_parsed
            .rules
            .contains(&rule(RoutingRuleKind::DomainSuffix, "abp-zone.io", false))
    );
    assert!(
        !zs_parsed
            .rules
            .iter()
            .any(|r| r.key.value.contains("whitelisted"))
    );
}

#[test]
fn parse_geosite_filters_tags_and_drops_ads() {
    let geosite_text = "\
# sample geosite data
openai.com
full:chat.openai.com
keyword:anthropic
apple.com.cn @cn
ads.example.com @ads @cn
tracker.openai.com @ads
regexp:^ai-[0-9]+\\.example\\.com$
include:common
";

    let only_cn = dummy_source_cfg(
        "gs_cn",
        RoutingTarget::Direct,
        "v2fly",
        RoutingSourceFormat::Geosite,
        Some(GeositeTagFilter::OnlyCn),
        90,
    );
    let parsed_cn = parse_routing_source(geosite_text.as_bytes(), &only_cn).unwrap();
    assert_eq!(
        parsed_cn.rules,
        vec![rule(RoutingRuleKind::DomainSuffix, "apple.com.cn", false)]
    );

    let exclude_cn = dummy_source_cfg(
        "gs_not_cn",
        RoutingTarget::Proxy,
        "v2fly",
        RoutingSourceFormat::Geosite,
        Some(GeositeTagFilter::ExcludeCn),
        90,
    );
    let parsed_not_cn = parse_routing_source(geosite_text.as_bytes(), &exclude_cn).unwrap();
    assert!(parsed_not_cn.rules.contains(&rule(
        RoutingRuleKind::DomainSuffix,
        "openai.com",
        false
    )));
    assert!(
        parsed_not_cn
            .rules
            .contains(&rule(RoutingRuleKind::Domain, "chat.openai.com", false))
    );
    assert!(parsed_not_cn.rules.contains(&rule(
        RoutingRuleKind::DomainKeyword,
        "anthropic",
        false
    )));
    assert!(
        !parsed_not_cn
            .rules
            .iter()
            .any(|r| r.key.value.contains("apple")
                || r.key.value.contains("ads")
                || r.key.value.contains("tracker"))
    );

    let all_non_ads = dummy_source_cfg(
        "gs_all",
        RoutingTarget::Direct,
        "v2fly",
        RoutingSourceFormat::Geosite,
        Some(GeositeTagFilter::AllNonAds),
        90,
    );
    let parsed_all = parse_routing_source(geosite_text.as_bytes(), &all_non_ads).unwrap();
    assert_eq!(parsed_all.rules.len(), 4);
}

#[test]
fn parse_dnsmasq_china_accepts_domains_and_tlds() {
    let input = "\
# dnsmasq china list
server=/10010.com/114.114.114.114
server=/cn/114.114.114.114
server=/xn--fiqs8s/114.114.114.114
local=/localhost/127.0.0.1
";
    let cfg = dummy_source_cfg(
        "dnsmasq",
        RoutingTarget::Direct,
        "felixonmars",
        RoutingSourceFormat::DnsmasqChina,
        None,
        68,
    );
    let parsed = parse_routing_source(input.as_bytes(), &cfg).unwrap();
    assert!(
        parsed
            .rules
            .contains(&rule(RoutingRuleKind::DomainSuffix, "10010.com", false))
    );
    assert!(
        parsed
            .rules
            .contains(&rule(RoutingRuleKind::DomainSuffix, "cn", false))
    );
    assert!(
        parsed
            .rules
            .contains(&rule(RoutingRuleKind::DomainSuffix, "xn--fiqs8s", false))
    );
    assert!(!parsed.rules.iter().any(|r| r.key.value == "localhost"));
}

#[test]
fn parse_gfwlist_base64_extracts_proxy_and_skips_autoproxy_whitelist() {
    let raw_autoproxy = "\
[AutoProxy 0.2.9]
! Checksum: dummy
||google.com
.twitter.com
|https://github.com/login
@@||qq.com
@@||baidu.com
@@.weibo.com
/unanchored-regex/
";
    let b64 = encode_base64(raw_autoproxy.as_bytes());
    let wrapped = format!("{}\n{}", &b64[..20], &b64[20..]);

    let cfg = dummy_source_cfg(
        "gfwlist",
        RoutingTarget::Proxy,
        "gfwlist",
        RoutingSourceFormat::GfwlistBase64,
        None,
        85,
    );
    let parsed = parse_routing_source(wrapped.as_bytes(), &cfg).unwrap();
    assert!(
        parsed
            .rules
            .contains(&rule(RoutingRuleKind::DomainSuffix, "google.com", false))
    );
    assert!(
        parsed
            .rules
            .contains(&rule(RoutingRuleKind::DomainSuffix, "twitter.com", false))
    );
    assert!(
        parsed
            .rules
            .contains(&rule(RoutingRuleKind::DomainSuffix, "github.com", false))
    );
    assert!(
        !parsed
            .rules
            .iter()
            .any(|r| matches!(r.key.value.as_str(), "qq.com" | "baidu.com" | "weibo.com"))
    );
}

#[test]
fn shared_infra_roots_blocks_apex_and_wildcards_while_allowing_ai_children() {
    let overrides = RoutingOverrides {
        schema_version: 1,
        shared_infra_roots: vec![
            SharedInfraRootEntry {
                domain: "amazonaws.com".to_string(),
                rationale: "AWS".to_string(),
            },
            SharedInfraRootEntry {
                domain: "cloudflare.com".to_string(),
                rationale: "Cloudflare".to_string(),
            },
            SharedInfraRootEntry {
                domain: "googleapis.com".to_string(),
                rationale: "Google APIs".to_string(),
            },
        ],
        force_entries: Vec::new(),
        exclude_entries: Vec::new(),
    };

    let sources = vec![ParsedRoutingSource {
        source_id: "noisy_ai".to_string(),
        target: RoutingTarget::Ai,
        lineage: "noisy".to_string(),
        weight: 90,
        strict_cn_cidr_guard: false,
        rules: vec![
            rule(RoutingRuleKind::DomainSuffix, "amazonaws.com", false),
            rule(RoutingRuleKind::Domain, "cloudflare.com", false),
            rule(RoutingRuleKind::DomainWildcard, "*.amazonaws.com", false),
            rule(RoutingRuleKind::DomainKeyword, "aws", false),
            rule(
                RoutingRuleKind::DomainSuffix,
                "generativelanguage.googleapis.com",
                false,
            ),
            rule(RoutingRuleKind::Domain, "aiplatform.googleapis.com", true),
        ],
    }];

    let compiled = compile_routing(
        &sources,
        &overrides,
        &AdblockOverrides::empty(),
        RoutingSourceCounts::default(),
    );

    assert!(!compiled.ai_text.contains("DOMAIN-SUFFIX,amazonaws.com"));
    assert!(!compiled.ai_text.contains("DOMAIN,cloudflare.com"));
    assert!(!compiled.ai_text.contains("DOMAIN-WILDCARD,*.amazonaws.com"));
    assert!(!compiled.ai_text.contains("DOMAIN-KEYWORD,aws"));
    assert!(
        compiled
            .ai_text
            .contains("DOMAIN-SUFFIX,generativelanguage.googleapis.com")
    );
    assert!(
        compiled
            .ai_text
            .contains("DOMAIN,aiplatform.googleapis.com,extended-matching")
    );

    // Must be cleanly verifiable including shared infra apex checks and AI subset of Proxy.
    let dir = tempdir().unwrap();
    write_compiled_dir(dir.path(), &compiled);
    verify_routing_dir(
        dir.path(),
        &overrides,
        RoutingThresholds {
            min_ai_lines: 1,
            min_proxy_lines: 1,
            ..RoutingThresholds::default()
        },
        false,
    )
    .unwrap();
}

#[test]
fn direct_vs_proxy_scoring_and_real_overrides_reconcile_cleanly() {
    let routing_ov_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("overrides/generated/routing-overrides.json");
    let adblock_ov_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("overrides/generated/adblock-overrides.json");
    let routing_ov = RoutingOverrides::load_from_path(&routing_ov_path).unwrap();
    let adblock_ov = AdblockOverrides::load_from_path(&adblock_ov_path).unwrap();

    let sources = vec![
        ParsedRoutingSource {
            source_id: "dnsmasq_china".to_string(),
            target: RoutingTarget::Direct,
            lineage: "felixonmars".to_string(),
            weight: 68,
            strict_cn_cidr_guard: false,
            rules: vec![
                rule(RoutingRuleKind::DomainSuffix, "overseas-example.com", false),
                rule(RoutingRuleKind::DomainSuffix, "baidu.com", false),
            ],
        },
        ParsedRoutingSource {
            source_id: "proxy_a".to_string(),
            target: RoutingTarget::Proxy,
            lineage: "loyalsoldier".to_string(),
            weight: 88,
            strict_cn_cidr_guard: false,
            rules: vec![rule(
                RoutingRuleKind::DomainSuffix,
                "overseas-example.com",
                false,
            )],
        },
        ParsedRoutingSource {
            source_id: "proxy_b".to_string(),
            target: RoutingTarget::Proxy,
            lineage: "sukkaw".to_string(),
            weight: 90,
            strict_cn_cidr_guard: false,
            rules: vec![rule(
                RoutingRuleKind::DomainSuffix,
                "overseas-example.com",
                false,
            )],
        },
        ParsedRoutingSource {
            source_id: "noisy_ai".to_string(),
            target: RoutingTarget::Ai,
            lineage: "upstream_ai".to_string(),
            weight: 92,
            strict_cn_cidr_guard: false,
            rules: vec![
                rule(RoutingRuleKind::DomainSuffix, "deepseek.com", false),
                rule(RoutingRuleKind::DomainSuffix, "moonshot.cn", false),
                rule(RoutingRuleKind::DomainSuffix, "doubleclick.net", false),
                // Upstream AI bundled payment & CAPTCHA spillover must yield to Payment/Telemetry
                rule(RoutingRuleKind::DomainSuffix, "stripe.com", false),
                rule(RoutingRuleKind::DomainSuffix, "arkoselabs.com", false),
            ],
        },
    ];

    let compiled = compile_routing(
        &sources,
        &routing_ov,
        &adblock_ov,
        RoutingSourceCounts::default(),
    );

    // Multi-lineage Proxy (90 + 12 = 102) must beat single-lineage dnsmasq_china (68).
    assert!(
        !compiled
            .direct_text
            .contains("DOMAIN-SUFFIX,overseas-example.com")
    );
    assert!(
        compiled
            .proxy_text
            .contains("DOMAIN-SUFFIX,overseas-example.com")
    );

    // Domestic AI must stay in Direct and out of AI/Payment/Telemetry/Proxy.
    assert!(compiled.direct_text.contains("DOMAIN-SUFFIX,deepseek.com"));
    assert!(!compiled.ai_text.contains("deepseek.com"));
    assert!(!compiled.payment_text.contains("deepseek.com"));
    assert!(!compiled.telemetry_text.contains("deepseek.com"));
    assert!(!compiled.proxy_text.contains("deepseek.com"));
    assert!(!compiled.ai_text.contains("moonshot.cn"));

    // Pure ad tracker stripped, while AI/Payment/Telemetry curated domains land in disjoint sets & Proxy.
    assert!(!compiled.ai_text.contains("doubleclick.net"));
    assert!(!compiled.proxy_text.contains("doubleclick.net"));
    assert!(compiled.ai_text.contains("DOMAIN-SUFFIX,oaistatsig.com"));
    assert!(compiled.payment_text.contains("DOMAIN-SUFFIX,stripe.com"));
    assert!(!compiled.ai_text.contains("DOMAIN-SUFFIX,stripe.com"));
    assert!(
        compiled
            .telemetry_text
            .contains("DOMAIN-SUFFIX,arkoselabs.com")
    );
    assert!(!compiled.ai_text.contains("arkoselabs.com"));
    assert!(compiled.proxy_text.contains("DOMAIN-SUFFIX,oaistatsig.com"));
    assert!(compiled.proxy_text.contains("DOMAIN-SUFFIX,stripe.com"));
    assert!(compiled.proxy_text.contains("DOMAIN-SUFFIX,arkoselabs.com"));

    let dir = tempdir().unwrap();
    write_compiled_dir(dir.path(), &compiled);
    verify_routing_dir(dir.path(), &routing_ov, RoutingThresholds::default(), false).unwrap();
}

#[test]
fn verify_routing_dir_rejects_invalid_ruleset_invariants() {
    let overrides = RoutingOverrides::empty();
    let zero = RoutingThresholds::default();

    // 1. Policy column in external RULE-SET must fail.
    let d1 = tempdir().unwrap();
    write_raw_lists(
        d1.path(),
        "DOMAIN-SUFFIX,baidu.com,DIRECT\n",
        "DOMAIN-SUFFIX,openai.com\n",
        "",
        "",
        "DOMAIN-SUFFIX,openai.com\n",
    );
    assert!(verify_routing_dir(d1.path(), &overrides, zero, false).is_err());

    // 2. IP-CIDR without no-resolve must fail.
    let d2 = tempdir().unwrap();
    write_raw_lists(
        d2.path(),
        "DOMAIN-SUFFIX,baidu.com\n",
        "DOMAIN-SUFFIX,openai.com\n",
        "",
        "",
        "DOMAIN-SUFFIX,openai.com\nIP-CIDR,149.154.160.0/20\n",
    );
    assert!(verify_routing_dir(d2.path(), &overrides, zero, false).is_err());

    // 3. Reserved/Tailscale CIDR must fail.
    let d3 = tempdir().unwrap();
    write_raw_lists(
        d3.path(),
        "IP-CIDR,100.64.0.0/10,no-resolve\n",
        "",
        "",
        "",
        "",
    );
    assert!(verify_routing_dir(d3.path(), &overrides, zero, false).is_err());

    // 4. Broken Payment subset of Proxy must fail.
    let d4 = tempdir().unwrap();
    write_raw_lists(
        d4.path(),
        "DOMAIN-SUFFIX,baidu.com\n",
        "DOMAIN-SUFFIX,openai.com\n",
        "DOMAIN-SUFFIX,paypal.com\n",
        "",
        "DOMAIN-SUFFIX,openai.com\n",
    );
    assert!(verify_routing_dir(d4.path(), &overrides, zero, false).is_err());

    // 5. Proxy missing extended-matching present on AI rule must fail.
    let d5 = tempdir().unwrap();
    write_raw_lists(
        d5.path(),
        "",
        "DOMAIN,api.openai.com,extended-matching\n",
        "",
        "",
        "DOMAIN-SUFFIX,openai.com\n",
    );
    assert!(verify_routing_dir(d5.path(), &overrides, zero, false).is_err());

    // 6. Direct.list with extended-matching must be rejected.
    let d6 = tempdir().unwrap();
    write_raw_lists(
        d6.path(),
        "DOMAIN-SUFFIX,cn,extended-matching\n",
        "",
        "",
        "",
        "",
    );
    assert!(verify_routing_dir(d6.path(), &overrides, zero, false).is_err());

    // 7. Overlapping domain between AI.list and Payment.list must fail disjointness check.
    let d7 = tempdir().unwrap();
    write_raw_lists(
        d7.path(),
        "",
        "DOMAIN,checkout.stripe.com\n",
        "DOMAIN-SUFFIX,stripe.com\n",
        "",
        "DOMAIN-SUFFIX,stripe.com\n",
    );
    assert!(verify_routing_dir(d7.path(), &overrides, zero, false).is_err());

    // 8. Overlapping CIDR between AI.list and Telemetry.list must fail disjointness check.
    let d8 = tempdir().unwrap();
    write_raw_lists(
        d8.path(),
        "",
        "IP-CIDR,160.79.104.0/21,no-resolve\n",
        "",
        "IP-CIDR,160.79.104.1/32,no-resolve\n",
        "IP-CIDR,160.79.104.0/21,no-resolve\n",
    );
    assert!(verify_routing_dir(d8.path(), &overrides, zero, false).is_err());
}

#[test]
fn direct_list_strips_extended_matching_even_when_requested() {
    let sources = vec![ParsedRoutingSource {
        source_id: "direct_src".to_string(),
        target: RoutingTarget::Direct,
        lineage: "test".to_string(),
        weight: 90,
        strict_cn_cidr_guard: false,
        rules: vec![
            rule(RoutingRuleKind::DomainSuffix, "baidu.com", true),
            rule(RoutingRuleKind::DomainWildcard, "*.qq.com", true),
        ],
    }];
    let overrides = RoutingOverrides {
        force_entries: vec![
            RoutingRuleOverride {
                target: RoutingTarget::Direct,
                kind: RoutingRuleKind::DomainSuffix,
                value: "cn".to_string(),
                extended_matching: true,
                rationale: "direct test".to_string(),
            },
            RoutingRuleOverride {
                target: RoutingTarget::Ai,
                kind: RoutingRuleKind::DomainSuffix,
                value: "openai.com".to_string(),
                extended_matching: true,
                rationale: "ai test".to_string(),
            },
        ],
        ..RoutingOverrides::empty()
    };

    let compiled = compile_routing(
        &sources,
        &overrides,
        &AdblockOverrides::empty(),
        RoutingSourceCounts::default(),
    );

    assert!(
        !compiled.direct_text.contains("extended-matching"),
        "Direct.list must never emit extended-matching:\n{}",
        compiled.direct_text
    );
    assert!(compiled.direct_text.contains("DOMAIN-SUFFIX,cn\n"));
    assert!(compiled.direct_text.contains("DOMAIN-SUFFIX,baidu.com\n"));
    assert!(compiled.direct_text.contains("DOMAIN-WILDCARD,*.qq.com\n"));
    assert!(
        compiled
            .ai_text
            .contains("DOMAIN-SUFFIX,openai.com,extended-matching\n")
    );

    let dir = tempdir().unwrap();
    write_compiled_dir(dir.path(), &compiled);
    verify_routing_dir(
        dir.path(),
        &overrides,
        RoutingThresholds {
            min_ai_lines: 1,
            ..RoutingThresholds::default()
        },
        false,
    )
    .unwrap();
}

#[test]
fn logical_and_normalization_guard_and_subset_propagation() {
    let normalized =
        normalize_logical_and_value("((DOMAIN-SUFFIX, Auth0.COM), (PROCESS-NAME, ChatGPT))")
            .expect("valid two-clause AND must normalize");
    assert_eq!(
        normalized,
        "((DOMAIN-SUFFIX,auth0.com),(PROCESS-NAME,ChatGPT))"
    );
    assert_eq!(
        format_routing_rule_line(&rule(RoutingRuleKind::And, &normalized, false)),
        "AND,((DOMAIN-SUFFIX,auth0.com),(PROCESS-NAME,ChatGPT))"
    );
    assert_eq!(parse_logical_and_clauses(&normalized).unwrap().len(), 2);

    // Reject single clause, nested AND, IN-RANGE, and unsupported sub-rule inside AND.
    assert!(normalize_rule_value(RoutingRuleKind::And, "((DOMAIN-SUFFIX,auth0.com))").is_none());
    assert!(
        normalize_rule_value(
            RoutingRuleKind::And,
            "((AND,((DOMAIN,a.com),(PROCESS-NAME,X))),(PROCESS-NAME,ChatGPT))"
        )
        .is_none()
    );
    assert!(
        normalize_rule_value(
            RoutingRuleKind::And,
            "((IN-RANGE,10.0.0.1-10.0.0.5),(PROCESS-NAME,ChatGPT))"
        )
        .is_none()
    );
    assert!(
        normalize_rule_value(RoutingRuleKind::And, "((DOMAIN,auth0.com),(PROTOCOL,TCP))").is_none()
    );

    let overrides = RoutingOverrides {
        shared_infra_roots: vec![
            SharedInfraRootEntry {
                domain: "auth0.com".to_string(),
                rationale: "shared identity".to_string(),
            },
            SharedInfraRootEntry {
                domain: "sentry.io".to_string(),
                rationale: "shared telemetry".to_string(),
            },
        ],
        force_entries: vec![
            // Valid process-scoped shared-infra AND rule -> kept in AI & Proxy.
            RoutingRuleOverride {
                target: RoutingTarget::Ai,
                kind: RoutingRuleKind::And,
                value: "((DOMAIN-SUFFIX,auth0.com),(PROCESS-NAME,ChatGPT))".to_string(),
                extended_matching: false,
                rationale: "ChatGPT auth0 login".to_string(),
            },
            // Unguarded shared-infra AND (missing PROCESS-NAME / USER-AGENT) -> dropped by AI guard.
            RoutingRuleOverride {
                target: RoutingTarget::Ai,
                kind: RoutingRuleKind::And,
                value: "((DOMAIN-SUFFIX,sentry.io),(DEST-PORT,443))".to_string(),
                extended_matching: false,
                rationale: "should be stripped without process or ua".to_string(),
            },
        ],
        ..RoutingOverrides::empty()
    };

    let compiled = compile_routing(
        &[],
        &overrides,
        &AdblockOverrides::empty(),
        RoutingSourceCounts::default(),
    );
    assert!(
        compiled
            .ai_text
            .contains("AND,((DOMAIN-SUFFIX,auth0.com),(PROCESS-NAME,ChatGPT))\n"),
        "AI.list must emit valid process-scoped AND rule:\n{}",
        compiled.ai_text
    );
    assert!(
        compiled
            .proxy_text
            .contains("AND,((DOMAIN-SUFFIX,auth0.com),(PROCESS-NAME,ChatGPT))\n"),
        "Proxy.list must include AI AND rule:\n{}",
        compiled.proxy_text
    );
    assert!(
        !compiled.ai_text.contains("sentry.io"),
        "Unguarded shared-infra AND must be stripped:\n{}",
        compiled.ai_text
    );

    let dir = tempdir().unwrap();
    write_compiled_dir(dir.path(), &compiled);
    verify_routing_dir(dir.path(), &overrides, RoutingThresholds::default(), false).unwrap();

    // Verifier must reject AI AND missing from Proxy.list.
    let bad_subset = tempdir().unwrap();
    write_raw_lists(
        bad_subset.path(),
        "",
        "AND,((DOMAIN-SUFFIX,auth0.com),(PROCESS-NAME,ChatGPT))\n",
        "",
        "",
        "",
    );
    assert!(
        verify_routing_dir(
            bad_subset.path(),
            &overrides,
            RoutingThresholds::default(),
            false
        )
        .is_err()
    );

    // Verifier must reject reserved IP inside AND.
    let bad_ip = tempdir().unwrap();
    write_raw_lists(
        bad_ip.path(),
        "AND,((IP-CIDR,192.168.0.0/16),(PROCESS-NAME,WeChat))\n",
        "",
        "",
        "",
        "",
    );
    assert!(
        verify_routing_dir(
            bad_ip.path(),
            &overrides,
            RoutingThresholds::default(),
            false
        )
        .is_err()
    );
}

fn arb_domain() -> impl Strategy<Value = String> {
    prop::collection::vec("[a-z]{2,7}", 2..=4).prop_map(|labels| labels.join("."))
}

fn arb_routing_rule() -> impl Strategy<Value = RoutingRule> {
    prop_oneof![
        (arb_domain(), any::<bool>()).prop_map(|(d, ext)| rule(RoutingRuleKind::Domain, &d, ext)),
        (arb_domain(), any::<bool>()).prop_map(|(d, ext)| rule(
            RoutingRuleKind::DomainSuffix,
            &d,
            ext
        )),
        ("[a-z]{4,8}", any::<bool>()).prop_map(|(kw, ext)| rule(
            RoutingRuleKind::DomainKeyword,
            &kw,
            ext
        )),
        (arb_domain(), any::<bool>()).prop_map(|(d, ext)| rule(
            RoutingRuleKind::DomainWildcard,
            &format!("*.{}", d),
            ext
        )),
        (1u8..223u8, 0u8..=255u8).prop_map(|(a, b)| {
            // Avoid RFC 1918 / reserved prefixes that will also be tested separately.
            let octet0 = if matches!(a, 10 | 100 | 127 | 169 | 172 | 192 | 198) {
                1
            } else {
                a
            };
            rule(
                RoutingRuleKind::IpCidr,
                &format!("{}.{}.0.0/16", octet0, b),
                false,
            )
        }),
        (1u32..400_000u32).prop_map(|asn| rule(RoutingRuleKind::IpAsn, &asn.to_string(), false)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn prop_clean_split_is_disjoint_union_and_proxy_superset(
        direct_rules in prop::collection::vec(arb_routing_rule(), 0..20),
        ai_rules in prop::collection::vec(arb_routing_rule(), 1..20),
        payment_rules in prop::collection::vec(arb_routing_rule(), 0..20),
        telemetry_rules in prop::collection::vec(arb_routing_rule(), 0..20),
        proxy_rules in prop::collection::vec(arb_routing_rule(), 0..20),
    ) {
        let overrides = RoutingOverrides {
            schema_version: 1,
            shared_infra_roots: vec![SharedInfraRootEntry {
                domain: "amazonaws.com".to_string(),
                rationale: "AWS".to_string(),
            }],
            force_entries: Vec::new(),
            exclude_entries: Vec::new(),
        };
        let split_sources = vec![
            ParsedRoutingSource {
                source_id: "d".to_string(),
                target: RoutingTarget::Direct,
                lineage: "d".to_string(),
                weight: 70,
                strict_cn_cidr_guard: false,
                rules: direct_rules.clone(),
            },
            ParsedRoutingSource {
                source_id: "a".to_string(),
                target: RoutingTarget::Ai,
                lineage: "a".to_string(),
                weight: 90,
                strict_cn_cidr_guard: false,
                rules: ai_rules.clone(),
            },
            ParsedRoutingSource {
                source_id: "pay".to_string(),
                target: RoutingTarget::Payment,
                lineage: "pay".to_string(),
                weight: 90,
                strict_cn_cidr_guard: false,
                rules: payment_rules.clone(),
            },
            ParsedRoutingSource {
                source_id: "tel".to_string(),
                target: RoutingTarget::Telemetry,
                lineage: "tel".to_string(),
                weight: 90,
                strict_cn_cidr_guard: false,
                rules: telemetry_rules.clone(),
            },
            ParsedRoutingSource {
                source_id: "p".to_string(),
                target: RoutingTarget::Proxy,
                lineage: "p".to_string(),
                weight: 90,
                strict_cn_cidr_guard: false,
                rules: proxy_rules.clone(),
            },
        ];

        // Reference unified pre-split build where all three clean feeds target `Ai` with the same lineages.
        let unified_sources = vec![
            ParsedRoutingSource {
                source_id: "d".to_string(),
                target: RoutingTarget::Direct,
                lineage: "d".to_string(),
                weight: 70,
                strict_cn_cidr_guard: false,
                rules: direct_rules,
            },
            ParsedRoutingSource {
                source_id: "a".to_string(),
                target: RoutingTarget::Ai,
                lineage: "a".to_string(),
                weight: 90,
                strict_cn_cidr_guard: false,
                rules: ai_rules,
            },
            ParsedRoutingSource {
                source_id: "pay_as_ai".to_string(),
                target: RoutingTarget::Ai,
                lineage: "pay".to_string(),
                weight: 90,
                strict_cn_cidr_guard: false,
                rules: payment_rules,
            },
            ParsedRoutingSource {
                source_id: "tel_as_ai".to_string(),
                target: RoutingTarget::Ai,
                lineage: "tel".to_string(),
                weight: 90,
                strict_cn_cidr_guard: false,
                rules: telemetry_rules,
            },
            ParsedRoutingSource {
                source_id: "p".to_string(),
                target: RoutingTarget::Proxy,
                lineage: "p".to_string(),
                weight: 90,
                strict_cn_cidr_guard: false,
                rules: proxy_rules,
            },
        ];

        let split = compile_routing(
            &split_sources,
            &overrides,
            &AdblockOverrides::empty(),
            RoutingSourceCounts::default(),
        );
        let unified = compile_routing(
            &unified_sources,
            &overrides,
            &AdblockOverrides::empty(),
            RoutingSourceCounts::default(),
        );

        let ai_set = rule_lines(&split.ai_text);
        let pay_set = rule_lines(&split.payment_text);
        let tel_set = rule_lines(&split.telemetry_text);
        let unified_set = rule_lines(&unified.ai_text);

        // Pairwise disjointness of emitted lines
        prop_assert!(ai_set.is_disjoint(&pay_set));
        prop_assert!(ai_set.is_disjoint(&tel_set));
        prop_assert!(pay_set.is_disjoint(&tel_set));
        prop_assert_eq!(ai_set.len() + pay_set.len() + tel_set.len(), unified_set.len());

        // Union of the 3 split rule sets equals 100% of the unified rule set
        let mut union_set = ai_set;
        union_set.extend(pay_set);
        union_set.extend(tel_set);
        prop_assert_eq!(union_set, unified_set);

        // Direct.list and Proxy.list remain 100% unchanged
        prop_assert_eq!(rule_lines(&split.direct_text), rule_lines(&unified.direct_text));
        prop_assert_eq!(rule_lines(&split.proxy_text), rule_lines(&unified.proxy_text));

        let dir = tempdir().unwrap();
        write_compiled_dir(dir.path(), &split);
        prop_assert!(verify_routing_dir(dir.path(), &overrides, RoutingThresholds::default(), false).is_ok());
    }

    #[test]
    fn prop_ai_never_captures_shared_infra_apexes(
        extra_rules in prop::collection::vec(arb_routing_rule(), 0..15),
        shared_idx in 0usize..6,
        target_idx in 0usize..3,
        forced in any::<bool>(),
    ) {
        let shared_roots = [
            "amazonaws.com",
            "cloudflare.com",
            "googleapis.com",
            "github.com",
            "azure.com",
            "apple.com",
        ];
        let clean_targets = [
            RoutingTarget::Ai,
            RoutingTarget::Payment,
            RoutingTarget::Telemetry,
        ];
        let picked = shared_roots[shared_idx];
        let chosen_target = clean_targets[target_idx];
        let overrides = RoutingOverrides {
            schema_version: 1,
            shared_infra_roots: shared_roots
                .iter()
                .map(|d| SharedInfraRootEntry {
                    domain: (*d).to_string(),
                    rationale: "shared".to_string(),
                })
                .collect(),
            force_entries: if forced {
                vec![RoutingRuleOverride {
                    target: chosen_target,
                    kind: RoutingRuleKind::DomainSuffix,
                    value: picked.to_string(),
                    extended_matching: false,
                    rationale: "test force".to_string(),
                }]
            } else {
                Vec::new()
            },
            exclude_entries: Vec::new(),
        };

        let mut clean_rules = extra_rules;
        clean_rules.push(rule(RoutingRuleKind::DomainSuffix, picked, false));
        clean_rules.push(rule(RoutingRuleKind::Domain, picked, false));
        clean_rules.push(rule(
            RoutingRuleKind::DomainWildcard,
            &format!("*.{}", picked),
            false,
        ));
        clean_rules.push(rule(RoutingRuleKind::DomainKeyword, "amazon", false));

        let sources = vec![ParsedRoutingSource {
            source_id: "clean".to_string(),
            target: chosen_target,
            lineage: "clean".to_string(),
            weight: 95,
            strict_cn_cidr_guard: false,
            rules: clean_rules,
        }];

        let compiled = compile_routing(
            &sources,
            &overrides,
            &AdblockOverrides::empty(),
            RoutingSourceCounts::default(),
        );
        let dir = tempdir().unwrap();
        write_compiled_dir(dir.path(), &compiled);

        prop_assert!(verify_routing_dir(dir.path(), &overrides, RoutingThresholds::default(), false).is_ok());
    }

    #[test]
    fn prop_no_reserved_cidrs_and_mandatory_no_resolve(
        v4_a in any::<u8>(),
        v4_b in any::<u8>(),
        asn in 1u32..400_000u32,
    ) {
        let cidrs = vec![
            format!("10.{}.0.0/16", v4_b),
            format!("192.168.{}.0/24", v4_b),
            "198.18.0.0/15".to_string(),
            "100.64.0.0/10".to_string(),
            "172.16.0.1/32".to_string(),
            format!("{}.{}.0.0/16", v4_a, v4_b),
        ];
        let mut rules: Vec<RoutingRule> = cidrs
            .into_iter()
            .map(|c| rule(RoutingRuleKind::IpCidr, &c, false))
            .collect();
        rules.push(rule(RoutingRuleKind::IpCidr6, "fd7a:115c:a1e0::/48", false));
        rules.push(rule(RoutingRuleKind::IpCidr6, "fd01:db8:1111::/48", false));
        rules.push(rule(RoutingRuleKind::IpCidr6, "2606:4700::/32", false));
        rules.push(rule(RoutingRuleKind::IpAsn, &asn.to_string(), false));

        let sources = vec![ParsedRoutingSource {
            source_id: "ip".to_string(),
            target: RoutingTarget::Proxy,
            lineage: "ip".to_string(),
            weight: 90,
            strict_cn_cidr_guard: false,
            rules,
        }];
        let overrides = RoutingOverrides {
            schema_version: 1,
            shared_infra_roots: Vec::new(),
            force_entries: Vec::new(),
            exclude_entries: vec![RoutingExclusionOverride {
                target: RoutingTarget::Direct,
                kind: RoutingRuleKind::Domain,
                value: "unused.example".to_string(),
                rationale: "noop".to_string(),
            }],
        };

        let compiled = compile_routing(
            &sources,
            &overrides,
            &AdblockOverrides::empty(),
            RoutingSourceCounts::default(),
        );
        for line in compiled.proxy_text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("IP-CIDR,")
                || trimmed.starts_with("IP-CIDR6,")
                || trimmed.starts_with("IP-ASN,")
            {
                prop_assert!(trimmed.ends_with(",no-resolve"), "missing no-resolve: {}", trimmed);
            }
        }

        let dir = tempdir().unwrap();
        write_compiled_dir(dir.path(), &compiled);
        prop_assert!(verify_routing_dir(dir.path(), &overrides, RoutingThresholds::default(), false).is_ok());
    }

    #[test]
    fn prop_extended_matching_monotonicity(
        root in arb_domain(),
        sub in "[a-z]{2,6}",
        proxy_has_ancestor in any::<bool>(),
    ) {
        let child = format!("{}.{}", sub, root);
        let mut sources = vec![ParsedRoutingSource {
            source_id: "ai".to_string(),
            target: RoutingTarget::Ai,
            lineage: "ai".to_string(),
            weight: 95,
            strict_cn_cidr_guard: false,
            rules: vec![
                rule(RoutingRuleKind::DomainSuffix, &root, false),
                rule(RoutingRuleKind::Domain, &child, true),
            ],
        }];
        if proxy_has_ancestor {
            sources.push(ParsedRoutingSource {
                source_id: "proxy".to_string(),
                target: RoutingTarget::Proxy,
                lineage: "proxy".to_string(),
                weight: 95,
                strict_cn_cidr_guard: false,
                rules: vec![rule(RoutingRuleKind::DomainSuffix, &root, false)],
            });
        }

        let compiled = compile_routing(
            &sources,
            &RoutingOverrides::empty(),
            &AdblockOverrides::empty(),
            RoutingSourceCounts::default(),
        );

        let expected = format!("DOMAIN-SUFFIX,{},extended-matching", root);
        prop_assert!(
            compiled.ai_text.lines().any(|l| l.trim() == expected),
            "AI.list must propagate extended-matching to ancestor {}: {}",
            root,
            compiled.ai_text
        );
        prop_assert!(
            compiled.proxy_text.lines().any(|l| l.trim() == expected),
            "Proxy.list must propagate extended-matching to ancestor {}: {}",
            root,
            compiled.proxy_text
        );
    }

    #[test]
    fn prop_logical_and_shared_infra_and_direct_ext_invariants(
        shared_root in arb_domain(),
        proc_name in "[A-Za-z][A-Za-z0-9_-]{1,12}",
        has_proc_scope in any::<bool>(),
        direct_ext in any::<bool>(),
    ) {
        let and_value = if has_proc_scope {
            format!("((DOMAIN-SUFFIX,{}),(PROCESS-NAME,{}))", shared_root, proc_name)
        } else {
            format!("((DOMAIN-SUFFIX,{}),(DEST-PORT,443))", shared_root)
        };
        let overrides = RoutingOverrides {
            shared_infra_roots: vec![SharedInfraRootEntry {
                domain: shared_root.clone(),
                rationale: "prop test".to_string(),
            }],
            force_entries: vec![
                RoutingRuleOverride {
                    target: RoutingTarget::Ai,
                    kind: RoutingRuleKind::And,
                    value: and_value.clone(),
                    extended_matching: false,
                    rationale: "prop test".to_string(),
                },
                RoutingRuleOverride {
                    target: RoutingTarget::Direct,
                    kind: RoutingRuleKind::DomainSuffix,
                    value: "direct-only.example".to_string(),
                    extended_matching: direct_ext,
                    rationale: "prop direct".to_string(),
                },
            ],
            ..RoutingOverrides::empty()
        };

        let compiled = compile_routing(
            &[],
            &overrides,
            &AdblockOverrides::empty(),
            RoutingSourceCounts::default(),
        );
        prop_assert!(!compiled.direct_text.contains(",extended-matching"));

        let expected_line = format!("AND,{}", and_value);
        if has_proc_scope {
            prop_assert!(compiled.ai_text.lines().any(|l| l.trim() == expected_line));
            prop_assert!(compiled.proxy_text.lines().any(|l| l.trim() == expected_line));
        } else {
            prop_assert!(!compiled.ai_text.lines().any(|l| l.trim() == expected_line));
        }
    }
}

#[test]
fn non_adblock_abp_and_hosts_lists_route_to_proxy_while_protecting_direct_cn() {
    let direct_cfg = dummy_source_cfg(
        "direct_cn",
        RoutingTarget::Direct,
        "cn_core",
        RoutingSourceFormat::SurgeRuleset,
        None,
        95,
    );
    let proxy_abp_cfg = dummy_source_cfg(
        "hagezi_doh_proxy",
        RoutingTarget::Proxy,
        "hagezi_bypass",
        RoutingSourceFormat::AbpFilter,
        None,
        85,
    );
    let proxy_hosts_cfg = dummy_source_cfg(
        "social_hosts",
        RoutingTarget::Proxy,
        "stevenblack_social",
        RoutingSourceFormat::Hosts,
        None,
        85,
    );

    let d_src = parse_routing_source(
        b"DOMAIN-SUFFIX,alidns.com\nDOMAIN-SUFFIX,douyin.com\nIP-CIDR,223.5.5.5/32,no-resolve\n",
        &direct_cfg,
    )
    .unwrap();
    let p_abp = parse_routing_source(
        b"||dns.google^\n||cloudflare-dns.com^\n||dns.alidns.com^\n||doh.360.cn^\n||doubleclick.net^\n[/archive.org/1lib.sk/baidu.cn/]https://dns.opendns.com:443/dns-query\n",
        &proxy_abp_cfg,
    )
    .unwrap();
    let p_hosts = parse_routing_source(
        b"0.0.0.0 www.facebook.com graph.facebook.com\n0.0.0.0 open.douyin.com\n0.0.0.0 exoclick.com\n",
        &proxy_hosts_cfg,
    )
    .unwrap();

    let compiled = compile_routing(
        &[d_src, p_abp, p_hosts],
        &RoutingOverrides::empty(),
        &AdblockOverrides::empty(),
        RoutingSourceCounts::default(),
    );

    // Overseas DoH, AdGuard Home upstream [/.../], & social hosts route to Proxy
    assert!(compiled.proxy_text.contains("DOMAIN-SUFFIX,dns.google"));
    assert!(
        compiled
            .proxy_text
            .contains("DOMAIN-SUFFIX,cloudflare-dns.com")
    );
    assert!(compiled.proxy_text.contains("DOMAIN-SUFFIX,archive.org"));
    assert!(compiled.proxy_text.contains("DOMAIN-SUFFIX,1lib.sk"));
    assert!(compiled.proxy_text.contains("DOMAIN,www.facebook.com"));
    assert!(!compiled.proxy_text.contains("baidu.cn"));
    // Domestic `.cn` and Direct-ancestor children (`dns.alidns.com`, `open.douyin.com`) NEVER leak into Proxy
    assert!(!compiled.proxy_text.contains("alidns.com"));
    assert!(!compiled.proxy_text.contains("360.cn"));
    assert!(!compiled.proxy_text.contains("douyin.com"));
    // Pure ad networks stripped from Proxy
    assert!(!compiled.proxy_text.contains("doubleclick.net"));
    assert!(!compiled.proxy_text.contains("exoclick.com"));
}

#[test]
fn parses_openai_chatgpt_voice_json() {
    use surge_rules::routing::config::RoutingSourceCatalog;

    let catalog =
        RoutingSourceCatalog::load_from_path(Path::new("sources/generated/routing-sources.json"))
            .expect("sources/generated/routing-sources.json should load cleanly");
    assert!(
        catalog
            .sources
            .iter()
            .any(|s| s.id == "openai_chatgpt_voice_cidr"
                && s.format == RoutingSourceFormat::OpenaiIpJson
                && s.target == RoutingTarget::Ai),
        "routing catalog must include openai_chatgpt_voice_cidr"
    );

    let cfg = dummy_source_cfg(
        "openai_chatgpt_voice_cidr",
        RoutingTarget::Ai,
        "openai_official",
        RoutingSourceFormat::OpenaiIpJson,
        None,
        96,
    );
    let payload = br#"{
        "creationTime": "2026-11-16T01:33:53.175979+00:00",
        "prefixes": [
            {"ipv4Prefix": "102.37.57.54/32"},
            {"ipv4Prefix": "10.0.0.1/32"},
            {"ipv6Prefix": "2603:1030:7::/48"}
        ]
    }"#;
    let parsed = parse_routing_source(payload, &cfg).unwrap();
    assert!(
        parsed
            .rules
            .contains(&rule(RoutingRuleKind::IpCidr, "102.37.57.54/32", false))
    );
    assert!(
        parsed
            .rules
            .contains(&rule(RoutingRuleKind::IpCidr6, "2603:1030:7::/48", false))
    );

    let compiled = compile_routing(
        &[parsed],
        &RoutingOverrides::empty(),
        &AdblockOverrides::empty(),
        RoutingSourceCounts::default(),
    );
    assert!(
        compiled
            .ai_text
            .contains("IP-CIDR,102.37.57.54/32,no-resolve\n")
    );
    assert!(
        compiled
            .ai_text
            .contains("IP-CIDR6,2603:1030:7::/48,no-resolve\n")
    );
    assert!(!compiled.ai_text.contains("10.0.0.1"));
    assert!(
        compiled
            .proxy_text
            .contains("IP-CIDR,102.37.57.54/32,no-resolve\n")
    );

    assert!(parse_routing_source(b"not-json", &cfg).is_err());
}

#[test]
fn cn_safe_game_cdn_enforces_cdn_apex_guard_and_overseas_storefront_deny_filter() {
    use surge_rules::routing::config::RoutingSourceCatalog;

    let catalog =
        RoutingSourceCatalog::load_from_path(Path::new("sources/generated/routing-sources.json"))
            .expect("sources/generated/routing-sources.json should load cleanly");
    for expected_id in [
        "uklans_cache_blizzard",
        "uklans_cache_epicgames",
        "uklans_cache_riot",
        "uklans_cache_origin",
        "uklans_cache_uplay",
        "uklans_cache_rockstar",
        "uklans_cache_steam",
        "metacubex_game_platforms_dl_filtered",
        "sukkaw_game_download_filtered",
    ] {
        assert!(
            catalog.sources.iter().any(|s| {
                s.id == expected_id
                    && s.format == RoutingSourceFormat::CnSafeGameCdn
                    && s.target == RoutingTarget::Direct
            }),
            "routing catalog must register {} as cn_safe_game_cdn -> direct",
            expected_id
        );
    }

    let raw_mixed_feed = "\
# Combined uklans/cache-domains, clash_classical, and SukkaW domainset lines
*.akamaized.net
DOMAIN-SUFFIX,akamaihd.net
.edgesuite.net
*.vo.llnwd.net
amazonaws.com
egdownload.fastly-edge.com
DOMAIN-SUFFIX,egdownload.fastly-edge.com
fastly-download.epicgames.com
cloudflare.epicgamescdn.com
egs-cloudfront-chunks.epicgamescdn.com
.epicgamescdn.com
edge.blizzard.top.comcast.net
edge.steam-dns.top.comcast.net
ecs-lp1.hac.shop.nintendo.net
*.hac.lp1.eshop.nintendo.net
eshop.nintendo.net
.wup.shop.nintendo.net
store.steampowered.com
.content.steampowered.com
steamcommunity.com
api.steamgames.com
auth.riotgames.com
l3cdn.riotgames.com
epicgames.com
download.epicgames.com
xvcf1.xboxlive.com
.dl.playstation.net
recommendations-api.gog.com
discord.gg
twitch.tv

# Valid concrete 3+-label tenant depot hostnames -> exact DOMAIN ONLY
steampipe.akamaized.net # inline comment
DOMAIN,epicgames-download1.akamaized.net
blzddist1-a.akamaihd.net
riotgamespatcher-a.akamaihd.net
origin-a.akamaihd.net
blizzard.vo.llnwd.net

# Valid dedicated game patch CDN subdomains -> DOMAIN-SUFFIX
*.dyn.riotcdn.net
.cdn.ubi.com
*.cdn.blizzard.com
.steamcontent.com
";

    let cfg = dummy_source_cfg(
        "test_cn_game_cdn",
        RoutingTarget::Direct,
        "uklans_lancache",
        RoutingSourceFormat::CnSafeGameCdn,
        None,
        88,
    );
    let parsed = parse_routing_source(raw_mixed_feed.as_bytes(), &cfg).unwrap();

    // Concrete 3+-label tenant depot hostnames MUST emit exact DOMAIN, never DOMAIN-SUFFIX
    for exact_depot in [
        "steampipe.akamaized.net",
        "epicgames-download1.akamaized.net",
        "blzddist1-a.akamaihd.net",
        "riotgamespatcher-a.akamaihd.net",
        "origin-a.akamaihd.net",
        "blizzard.vo.llnwd.net",
    ] {
        assert!(
            parsed
                .rules
                .contains(&rule(RoutingRuleKind::Domain, exact_depot, false)),
            "expected exact DOMAIN for {}",
            exact_depot
        );
        assert!(
            !parsed
                .rules
                .iter()
                .any(|r| r.key.kind == RoutingRuleKind::DomainSuffix && r.key.value == exact_depot),
            "must NOT emit DOMAIN-SUFFIX for shared CDN tenant {}",
            exact_depot
        );
    }

    // Dedicated 1st-party game CDN subdomains may emit DOMAIN-SUFFIX
    for sfx_depot in [
        "dyn.riotcdn.net",
        "cdn.ubi.com",
        "cdn.blizzard.com",
        "steamcontent.com",
    ] {
        assert!(
            parsed
                .rules
                .contains(&rule(RoutingRuleKind::DomainSuffix, sfx_depot, false)),
            "expected DOMAIN-SUFFIX for {}",
            sfx_depot
        );
    }

    // Shared CDN parents, Fastly/CloudFront/Cloudflare/Comcast, and storefronts MUST be dropped
    for forbidden in [
        "akamaized.net",
        "akamaihd.net",
        "edgesuite.net",
        "llnwd.net",
        "vo.llnwd.net",
        "amazonaws.com",
        "egdownload.fastly-edge.com",
        "fastly-download.epicgames.com",
        "cloudflare.epicgamescdn.com",
        "egs-cloudfront-chunks.epicgamescdn.com",
        "epicgamescdn.com",
        "edge.blizzard.top.comcast.net",
        "edge.steam-dns.top.comcast.net",
        "ecs-lp1.hac.shop.nintendo.net",
        "eshop.nintendo.net",
        "wup.shop.nintendo.net",
        "store.steampowered.com",
        "content.steampowered.com",
        "steamcommunity.com",
        "api.steamgames.com",
        "auth.riotgames.com",
        "l3cdn.riotgames.com",
        "epicgames.com",
        "download.epicgames.com",
        "xvcf1.xboxlive.com",
        "dl.playstation.net",
        "recommendations-api.gog.com",
        "discord.gg",
        "twitch.tv",
    ] {
        assert!(
            !parsed.rules.iter().any(|r| r.key.value == forbidden),
            "forbidden domain '{}' leaked through cn_safe_game_cdn",
            forbidden
        );
    }

    let compiled = compile_routing(
        &[parsed],
        &RoutingOverrides::empty(),
        &AdblockOverrides::empty(),
        RoutingSourceCounts::default(),
    );
    assert!(
        compiled
            .direct_text
            .contains("DOMAIN,steampipe.akamaized.net\n")
    );
    assert!(
        compiled
            .direct_text
            .contains("DOMAIN,epicgames-download1.akamaized.net\n")
    );
    assert!(!compiled.direct_text.contains("fastly"));
    assert!(!compiled.direct_text.contains("comcast.net"));
    assert!(!compiled.direct_text.contains("nintendo.net"));
    assert!(!compiled.direct_text.contains("steampowered.com"));
}

#[test]
fn sstap_filtered_cidr_enforces_prefix_floor_bogons_ipset_and_cn_exclusion() {
    use ipnet::{Ipv4Net, Ipv6Net};
    use surge_rules::routing::config::RoutingSourceCatalog;

    let catalog =
        RoutingSourceCatalog::load_from_path(Path::new("sources/generated/routing-sources.json"))
            .expect("sources/generated/routing-sources.json should load cleanly");
    for expected_id in [
        "refilter_discord_voice_cidr",
        "ghostrooter_discord_voice_cidr",
        "fqrabbit_sstap_valorant",
        "fqrabbit_sstap_apex",
        "fqrabbit_sstap_cs2",
    ] {
        assert!(
            catalog.sources.iter().any(|s| {
                s.id == expected_id
                    && s.format == RoutingSourceFormat::SstapFilteredCidr
                    && s.target == RoutingTarget::Proxy
            }),
            "routing catalog must register {} as sstap_filtered_cidr -> proxy",
            expected_id
        );
    }
    // Verify #49 restored entries and co-origin lineage deduplication
    assert!(
        catalog
            .sources
            .iter()
            .any(|s| s.id == "hezhijie_gfwlist_agh" && s.lineage == "gfwlist")
    );
    for rpi_id in ["rpilist_pornblock1", "rpilist_proxies", "rpilist_streaming"] {
        assert!(
            catalog.sources.iter().any(|s| s.id == rpi_id
                && s.lineage == "rpilist"
                && s.target == RoutingTarget::Proxy),
            "routing catalog must restore {}",
            rpi_id
        );
    }

    let raw_sstap_and_discord = "\
#Valorant,无畏契约,0,0,1,0,0,0,By-小明
# Cloud supernets (< /22 IPv4 and < /40 IPv6) -> MUST DROP
104.16.0.0/12
52.0.0.0/13
13.32.0.0/15
34.64.0.0/20
35.184.0.0/21
2600:1900::/28
2404:6800::/39

# Bogon / private / loopback / CGNAT / benchmarking / documentation / multicast -> MUST DROP
0.0.0.0/24
10.0.0.0/24
100.64.1.0/24
127.0.0.1/32
169.254.1.0/24
172.16.5.0/24
192.0.2.0/24
192.88.99.0/24
192.168.1.0/24
198.18.0.0/24
198.51.100.0/24
203.0.113.0/24
224.0.0.0/24
240.0.0.0/24
::1/128
2001:db8::/48
fc00::/48
fe80::/64

# Domestic CN CIDRs (to be suppressed by compiler CN exclusion guard even if >= /22)
14.17.12.0/24
114.114.114.114/32
223.5.5.0/24
240e:900::/44

# Valid overseas game / Discord voice subnets (>= /22 IPv4, >= /40 IPv6, plus ipset line)
66.22.244.163/24
138.128.140.253/32
add unblock 66.22.196.10 -exist
2606:4700:10::1/44
";

    let sstap_cfg = dummy_source_cfg(
        "test_sstap",
        RoutingTarget::Proxy,
        "fqrabbit_sstap",
        RoutingSourceFormat::SstapFilteredCidr,
        None,
        89,
    );
    let parsed_sstap = parse_routing_source(raw_sstap_and_discord.as_bytes(), &sstap_cfg).unwrap();
    assert!(parsed_sstap.strict_cn_cidr_guard);

    // Supernets and bogons must already be dropped at parse time
    for dropped_at_parse in [
        "104.16.0.0/12",
        "52.0.0.0/13",
        "13.32.0.0/15",
        "34.64.0.0/20",
        "35.184.0.0/21",
        "2600:1900::/28",
        "2404:6800::/39",
        "10.0.0.0/24",
        "100.64.1.0/24",
        "127.0.0.1/32",
        "192.88.99.0/24",
        "192.168.1.0/24",
        "198.18.0.0/24",
        "203.0.113.0/24",
        "2001:db8::/48",
    ] {
        assert!(
            !parsed_sstap
                .rules
                .iter()
                .any(|r| r.key.value == dropped_at_parse),
            "supernet/bogon '{}' must be dropped by sstap_filtered_cidr parser",
            dropped_at_parse
        );
    }

    // Canonicalized host-bit truncation and ipset extraction
    assert!(
        parsed_sstap
            .rules
            .contains(&rule(RoutingRuleKind::IpCidr, "66.22.244.0/24", false))
    );
    assert!(
        parsed_sstap
            .rules
            .contains(&rule(RoutingRuleKind::IpCidr, "66.22.196.10/32", false))
    );
    assert!(parsed_sstap.rules.contains(&rule(
        RoutingRuleKind::IpCidr6,
        "2606:4700:10::/44",
        false
    )));

    // Deliberately give Direct a LOWER weight (60 < 89) to prove `sstap_filtered_cidr` yields
    // unconditionally to ANY Direct CN CIDR, AND also test external `CnCidrExclusionSet` (MMDB).
    let direct_cn_cfg = dummy_source_cfg(
        "direct_cn_cidr",
        RoutingTarget::Direct,
        "gaoyifan_cn",
        RoutingSourceFormat::IpCidr,
        None,
        60,
    );
    let parsed_direct_cn =
        parse_routing_source(b"14.16.0.0/14\n114.114.114.114/32\n", &direct_cn_cfg).unwrap();

    let mmdb_cn_exclusions = CnCidrExclusionSet::from_cidrs(
        &["223.5.0.0/16".parse::<Ipv4Net>().unwrap()],
        &["240e::/20".parse::<Ipv6Net>().unwrap()],
    );

    let compiled = compile_routing_with_cn_exclusions(
        &[parsed_direct_cn, parsed_sstap],
        &RoutingOverrides::empty(),
        &AdblockOverrides::empty(),
        RoutingSourceCounts::default(),
        &mmdb_cn_exclusions,
    );

    // Overseas Discord voice / game subnets MUST emit `,no-resolve` in Proxy.list
    assert!(
        compiled
            .proxy_text
            .contains("IP-CIDR,66.22.244.0/24,no-resolve\n")
    );
    assert!(
        compiled
            .proxy_text
            .contains("IP-CIDR,138.128.140.253/32,no-resolve\n")
    );
    assert!(
        compiled
            .proxy_text
            .contains("IP-CIDR,66.22.196.10/32,no-resolve\n")
    );
    assert!(
        compiled
            .proxy_text
            .contains("IP-CIDR6,2606:4700:10::/44,no-resolve\n")
    );

    // ALL CN-overlapping CIDRs (both Direct-claimed and Country-cn.mmdb-claimed) MUST be suppressed
    assert!(!compiled.proxy_text.contains("14.17.12.0"));
    assert!(!compiled.proxy_text.contains("114.114.114.114"));
    assert!(!compiled.proxy_text.contains("223.5.5.0"));
    assert!(!compiled.proxy_text.contains("240e:900::"));
}
