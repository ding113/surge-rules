use std::fs;
use std::path::Path;

use ipnet::{Ipv4Net, Ipv6Net};
use proptest::prelude::*;
use tempfile::TempDir;

use surge_rules::adblock::compiler::{
    DirectProtectionSet, DomainTrie, TelemetryProtectionSet, compile_adblock,
    compile_adblock_with_guards, compile_adblock_with_telemetry_guard, overlaps_reserved_v4,
    overlaps_reserved_v6, overlaps_shared_cdn_or_dns_v4, overlaps_shared_cdn_or_dns_v6,
};
use surge_rules::adblock::config::{
    AdblockCategory, AdblockOverrides, AdblockPlatformScope, AdblockRuleTarget,
    AdblockSourceCatalog, AdblockSourceConfig, AdblockSourceFormat, AdblockSourceRole,
    AllowDomainMatchType, AllowDomainOverride, ForceRuleSetOverride, MitmHostOverride,
    ProtectedApexDomainOverride,
};
use surge_rules::adblock::jq_transpile::transpile_jsonprune_to_jq;
use surge_rules::adblock::model::{
    BodyRewriteKind, MapLocalDataType, ParsedAdblockSource, RemoveParamRule, ScriptRule,
    ScriptType, UrlRewriteMode,
};
use surge_rules::adblock::parsers::parse_adblock_source;
use surge_rules::adblock::regex_util::{
    extract_hosts_from_regex, is_valid_domain, is_valid_mitm_host, is_valid_positive_mitm_host,
    normalize_surge_regex,
};
use surge_rules::adblock::verify::{verify_adblock_dir, verify_module_text};
use surge_rules::config::EndpointConfig;

fn dummy_adblock_source(
    id: &str,
    role: AdblockSourceRole,
    format: AdblockSourceFormat,
    weight: u16,
) -> AdblockSourceConfig {
    AdblockSourceConfig {
        id: id.to_string(),
        role,
        category: if role == AdblockSourceRole::Allowlist {
            AdblockCategory::Both
        } else {
            AdblockCategory::Ad
        },
        format,
        platform: AdblockPlatformScope::Universal,
        lineage: format!("test:{}", id),
        weight,
        core: true,
        extract_complex_network_rules: true,
        extract_fallback_domain_rules: true,
        filter_direct_collisions: false,
        endpoints: vec![EndpointConfig::Direct {
            url: format!("https://example.com/{}.txt", id),
        }],
    }
}

#[test]
fn real_adblock_catalog_and_overrides_load_cleanly() {
    let catalog =
        AdblockSourceCatalog::load_from_path(Path::new("sources/generated/adblock-sources.json"))
            .expect("sources/generated/adblock-sources.json should load cleanly");
    assert!(
        catalog.sources.len() >= 45,
        "expected >= 45 upstream adblock feeds, got {}",
        catalog.sources.len()
    );
    assert!(
        catalog
            .sources
            .iter()
            .any(|s| s.role == AdblockSourceRole::ComplexFirst),
        "expected at least one complex_first feed"
    );
    assert!(
        catalog
            .sources
            .iter()
            .any(|s| s.role == AdblockSourceRole::Allowlist),
        "expected at least one allowlist feed"
    );

    assert!(
        catalog
            .sources
            .iter()
            .any(|s| s.role == AdblockSourceRole::RulesetFallback
                && s.category == AdblockCategory::Ad
                && s.core),
        "expected at least one core 'ad' ruleset feed"
    );
    assert!(
        catalog
            .sources
            .iter()
            .any(|s| s.role == AdblockSourceRole::RulesetFallback
                && s.category == AdblockCategory::Privacy
                && s.core),
        "expected at least one core 'privacy' ruleset feed"
    );

    let overrides =
        AdblockOverrides::load_from_path(Path::new("overrides/generated/adblock-overrides.json"))
            .expect("overrides/generated/adblock-overrides.json should load cleanly");
    assert!(
        overrides
            .force_rule_set_entries
            .iter()
            .any(|f| f.target == AdblockRuleTarget::Ad)
            && overrides
                .force_rule_set_entries
                .iter()
                .any(|f| f.target == AdblockRuleTarget::Privacy),
        "expected forceRuleSetEntries covering both 'ad' and 'privacy' targets"
    );
    assert!(
        overrides.allow_domains.len() >= 30,
        "expected curated allowDomains in overrides"
    );
    assert!(
        overrides.protected_apex_domains.len() >= 30,
        "expected curated protectedApexDomains in overrides"
    );
    for pinned in [
        "*.apple.com",
        "*.googleapis.com",
        "*.beacon.qq.com",
        "*.snssdk.com",
    ] {
        assert!(
            overrides
                .mitm_excluded_hosts
                .iter()
                .any(|m| m.pattern == pinned),
            "expected certificate-pinned host '{}' excluded from MITM",
            pinned
        );
    }
}

#[test]
fn jsonprune_transpiler_handles_paths_and_rejects_conditionals() {
    assert_eq!(
        transpile_jsonprune_to_jq(r"\$.data.ad_info"),
        Some("del(.data?.ad_info?)".to_string())
    );
    assert_eq!(
        transpile_jsonprune_to_jq(r"\$.items.[].ad"),
        Some("del(.items?[]?.ad?)".to_string())
    );
    assert_eq!(
        transpile_jsonprune_to_jq(r"\$.items[].ad"),
        Some("del(.items?[]?.ad?)".to_string())
    );
    assert_eq!(
        transpile_jsonprune_to_jq(r"\.ads \.tracking.banners"),
        Some("del(.ads?, .tracking?.banners?)".to_string())
    );
    assert_eq!(
        transpile_jsonprune_to_jq(r"\$.data.feed[*].sponsor"),
        Some("del(.data?.feed?[]?.sponsor?)".to_string())
    );

    // Unsupported or unsafe conditional/negated/quote-containing expressions must return None
    assert_eq!(transpile_jsonprune_to_jq(""), None);
    assert_eq!(transpile_jsonprune_to_jq(r"-\$"), None);
    assert_eq!(
        transpile_jsonprune_to_jq(r"\$.items[?(@.is_ad==true)]"),
        None
    );
    assert_eq!(transpile_jsonprune_to_jq(r".data.items'evil"), None);
}

#[test]
fn abp_parser_converts_complex_rules_and_drops_cosmetic_selectors() {
    let src = dummy_adblock_source(
        "abp_complex",
        AdblockSourceRole::ComplexFirst,
        AdblockSourceFormat::AbpFilter,
        150,
    );
    let raw = r#"
! Title: Sample Complex Filter
example.com##.ad-banner
example.com#@#.whitelist-banner
example.com#?#.extended-ad
example.com#+js(nobab)
||video.example.com/feed.json$jsonprune=\$.data.ad_info
||api.example.com/feed?$removeparam=utm_source
||cdn.example.com/js/app.js$replace=/window\.ads=true/window.ads=false/
||scoped.example.net/ads/$domain=app.example.org
||dead-rule.example.org^
||dead-rule.example.org^$badfilter
||elemhide.example.org^$elemhide
||pure-ad.doubleclick-test.net^
@@||safe-partner.example.com^
"#;

    let parsed = parse_adblock_source(&src, raw.as_bytes()).expect("ABP parse should succeed");

    // Cosmetic selectors and scriptlets must never leak into ruleset or module
    assert!(!parsed.ruleset_domains.contains("example.com"));
    assert!(!parsed.ruleset_suffixes.contains("example.com"));

    // $domain= and $elemhide and $badfilter must not leak
    assert!(!parsed.ruleset_suffixes.contains("scoped.example.net"));
    assert!(!parsed.ruleset_suffixes.contains("dead-rule.example.org"));
    assert!(!parsed.ruleset_suffixes.contains("elemhide.example.org"));

    // Complex rules extracted cleanly
    assert_eq!(parsed.body_rewrites.len(), 2);
    assert!(parsed.body_rewrites.iter().any(
        |b| b.kind == BodyRewriteKind::HttpResponseJq && b.expression == "del(.data?.ad_info?)"
    ));
    assert!(
        parsed
            .body_rewrites
            .iter()
            .any(|b| b.kind == BodyRewriteKind::HttpResponse && b.expression == r"window\.ads=true")
    );

    assert_eq!(parsed.remove_params.len(), 1);
    assert_eq!(parsed.remove_params[0].host_scope, "api.example.com");
    assert_eq!(parsed.remove_params[0].param, "utm_source");

    // Complex hosts must automatically be marked for complex protection & MITM
    assert!(parsed.complex_protected_hosts.contains("video.example.com"));
    assert!(parsed.complex_protected_hosts.contains("cdn.example.com"));
    assert!(parsed.mitm_hosts.contains("video.example.com"));

    // Standard network domain & exception rules preserved
    assert!(
        parsed
            .ruleset_suffixes
            .contains("pure-ad.doubleclick-test.net")
    );
    assert!(
        parsed
            .allow_suffix_domains
            .contains("safe-partner.example.com")
    );
}

#[test]
fn qx_rewrite_upgrades_reject_variants_to_map_local_and_keeps_scripts() {
    let src = dummy_adblock_source(
        "qx_feed",
        AdblockSourceRole::ComplexFirst,
        AdblockSourceFormat::QxRewrite,
        140,
    );
    let raw = r#"
hostname = api.app.example.com, *.apple.com, *
^https?:\/\/api\.app\.example\.com\/v1\/ad\/ url reject-200
^https?:\/\/api\.app\.example\.com\/v1\/feed\/ad url reject-dict
^https?:\/\/api\.app\.example\.com\/v1\/banner\/list url reject-array
^https?:\/\/api\.app\.example\.com\/v1\/splash\.jpg url reject-img
^https?:\/\/api\.app\.example\.com\/v1\/feed$ url script-response-body https://raw.githubusercontent.com/example/repo/main/feed.js
^https?:\/\/api\.app\.example\.com\/v1\/hdr$ url request-header (\r\n)User-Agent:.+(\r\n) request-header $1User-Agent: clean$2
"#;

    let parsed = parse_adblock_source(&src, raw.as_bytes()).expect("QX parse should succeed");
    assert_eq!(parsed.map_locals.len(), 4);
    assert_eq!(parsed.scripts.len(), 1);
    assert_eq!(parsed.scripts[0].script_type, ScriptType::HttpResponse);
    assert!(parsed.scripts[0].requires_body);
    assert!(
        parsed
            .complex_protected_hosts
            .contains("api.app.example.com")
    );
    assert!(parsed.mitm_hosts.contains("api.app.example.com"));
    assert!(!parsed.mitm_hosts.contains("*"));
}

#[test]
fn surge_module_parser_drops_unsafe_headers_and_upgrades_reject_200() {
    let src = dummy_adblock_source(
        "surge_mod",
        AdblockSourceRole::ComplexFirst,
        AdblockSourceFormat::SurgeModule,
        160,
    );
    let raw = r#"
#!name=Test Module
[Rule]
DOMAIN,httpdns.bilivideo.com,REJECT,pre-matching
FINAL,DIRECT

[Header Rewrite]
http-response ^https?:\/\/api\.video\.example\.com\/ header-del Content-Length
http-response ^https?:\/\/api\.video\.example\.com\/ header-del Transfer-Encoding
http-request ^https?:\/\/api\.video\.example\.com\/ header-del X-Ad-Token

[URL Rewrite]
^https?:\/\/api\.video\.example\.com\/ad\/ - reject-200
^https?:\/\/api\.video\.example\.com\/json\/ - reject-dict
^https?:\/\/api\.video\.example\.com\/px\.gif - reject-img
^https?:\/\/api\.video\.example\.com\/track$ _ reject

[Body Rewrite]
http-response-jq ^https?:\/\/api\.video\.example\.com\/v2\/feed 'del(.data?.ad_info?)'

[Map Local]
^https?:\/\/api\.video\.example\.com\/splash$ data-type=json data="{}" status-code=200

[Script]
feed_cleaner = type=http-response,pattern=^https?://api\.video\.example\.com/v2/feed$,requires-body=1,script-path=https://raw.githubusercontent.com/example/feed.js

[MITM]
hostname = %APPEND% api.video.example.com, *.googlevideo.com, *.com
"#;

    let parsed =
        parse_adblock_source(&src, raw.as_bytes()).expect("Surge module parse should succeed");

    // FINAL must be skipped; HTTPDNS rule preserved
    assert_eq!(parsed.module_rules.len(), 1);
    assert_eq!(
        parsed.module_rules[0].line,
        "DOMAIN,httpdns.bilivideo.com,REJECT,pre-matching"
    );

    // Content-Length and Transfer-Encoding must be dropped; X-Ad-Token kept
    assert_eq!(parsed.header_rewrites.len(), 1);
    assert_eq!(parsed.header_rewrites[0].field, "X-Ad-Token");

    // reject-200 / reject-dict / reject-img + data-type=json normalized to Map Local; standard reject stays in URL Rewrite
    assert_eq!(parsed.map_locals.len(), 4);
    let json_ml = parsed
        .map_locals
        .iter()
        .find(|m| m.pattern.contains("splash$"))
        .expect("data-type=json Map Local should be normalized");
    assert_eq!(json_ml.data_type, MapLocalDataType::Text);
    assert_eq!(
        json_ml.header.as_deref(),
        Some("Content-Type: application/json; charset=utf-8")
    );
    assert_eq!(parsed.url_rewrites.len(), 1);
    assert_eq!(parsed.url_rewrites[0].mode, UrlRewriteMode::Reject);

    // http-response-jq preserved
    assert_eq!(parsed.body_rewrites.len(), 1);
    assert_eq!(
        parsed.body_rewrites[0].kind,
        BodyRewriteKind::HttpResponseJq
    );

    // All positive wildcard MITM hosts (`*.googlevideo.com`, `*.com`) must be stripped; only exact domains survive
    assert!(parsed.mitm_hosts.contains("api.video.example.com"));
    assert!(!parsed.mitm_hosts.contains("*.googlevideo.com"));
    assert!(!parsed.mitm_hosts.contains("*.com"));
}

#[test]
fn compiler_enforces_complex_over_host_reserved_cidrs_and_script_precedence() {
    let mut overrides = AdblockOverrides::empty();
    overrides.allow_domains.push(AllowDomainOverride {
        match_type: AllowDomainMatchType::Suffix,
        domain: "apple.com".to_string(),
        rationale: "Apple core services".to_string(),
    });
    overrides
        .protected_apex_domains
        .push(ProtectedApexDomainOverride {
            domain: "bilibili.com".to_string(),
            rationale: "Apex must not be suffix-blocked".to_string(),
        });
    overrides.mitm_excluded_hosts.push(MitmHostOverride {
        pattern: "*.apple.com".to_string(),
        rationale: "Certificate pinning".to_string(),
    });

    overrides.force_rule_set_entries.push(ForceRuleSetOverride {
        target: AdblockRuleTarget::Ad,
        kind: "DOMAIN-SUFFIX".to_string(),
        value: "doubleclick.net".to_string(),
        rationale: "Tier-P0b pure ad network keeps suffix over child entries".to_string(),
    });

    // Complex source intercepts api.bilibili.com and deduplicates conflicting script trigger
    let mut complex_src = ParsedAdblockSource::default();
    complex_src
        .complex_protected_hosts
        .insert("api.bilibili.com".to_string());
    complex_src
        .mitm_hosts
        .insert("api.bilibili.com".to_string());
    complex_src.mitm_hosts.insert("push.apple.com".to_string());
    complex_src
        .mitm_hosts
        .insert("push.apple.com.*".to_string());
    complex_src.scripts.push(ScriptRule {
        name: "low_prio".to_string(),
        script_type: ScriptType::HttpResponse,
        pattern: r"^https?://api\.bilibili\.com/x/v2/feed$".to_string(),
        script_path: "https://example.com/low.js".to_string(),
        requires_body: true,
        binary_body_mode: false,
        full_header_mode: false,
        max_size: Some(0),
        timeout: None,
        argument: None,
        engine: None,
        weight: 100,
    });
    complex_src.scripts.push(ScriptRule {
        name: "high_prio".to_string(),
        script_type: ScriptType::HttpResponse,
        pattern: r"^https?://api\.bilibili\.com/x/v2/feed$".to_string(),
        script_path: "https://example.com/high.js".to_string(),
        requires_body: true,
        binary_body_mode: false,
        full_header_mode: false,
        max_size: Some(0),
        timeout: None,
        argument: None,
        engine: None,
        weight: 180,
    });
    complex_src.remove_params.push(RemoveParamRule {
        host_scope: "*".to_string(),
        param: "utm_source".to_string(),
        weight: 150,
    });

    // Fallback host feed tries to block api.bilibili.com, bilibili.com, apple.com, doubleclick.net, and LAN/Tailscale CIDRs
    let mut fallback_src = ParsedAdblockSource::default();
    fallback_src
        .ruleset_domains
        .insert("api.bilibili.com".to_string());
    fallback_src
        .ruleset_suffixes
        .insert("bilibili.com".to_string());
    fallback_src
        .ruleset_suffixes
        .insert("apple.com".to_string());
    fallback_src
        .ruleset_suffixes
        .insert("doubleclick.net".to_string());
    fallback_src
        .ruleset_domains
        .insert("ad.doubleclick.net".to_string());
    fallback_src
        .ruleset_cidrs_v4
        .insert("100.64.0.0/10".parse::<Ipv4Net>().unwrap());
    fallback_src
        .ruleset_cidrs_v4
        .insert("192.168.1.0/24".parse::<Ipv4Net>().unwrap());
    fallback_src
        .ruleset_cidrs_v4
        .insert("198.51.100.0/24".parse::<Ipv4Net>().unwrap());
    fallback_src
        .ruleset_cidrs_v4
        .insert("8.8.4.0/24".parse::<Ipv4Net>().unwrap());
    fallback_src
        .ruleset_cidrs_v4
        .insert("104.16.0.0/12".parse::<Ipv4Net>().unwrap());
    fallback_src
        .ruleset_cidrs_v4
        .insert("45.33.32.0/24".parse::<Ipv4Net>().unwrap());
    fallback_src
        .ruleset_cidrs_v6
        .insert("fd7a:115c:a1e0::/48".parse::<Ipv6Net>().unwrap());

    let compiled = compile_adblock(&[complex_src, fallback_src], &overrides, 2, 2);

    // Ruleset assertions
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN-SUFFIX,doubleclick.net\n"),
        "expected pure ad suffix doubleclick.net"
    );
    assert!(
        !compiled.ruleset_text.contains("ad.doubleclick.net"),
        "child domain ad.doubleclick.net should be subsumed by doubleclick.net"
    );
    assert!(
        !compiled.ruleset_text.contains("api.bilibili.com"),
        "complex-protected host api.bilibili.com must not be blocked in Adblock.list"
    );
    assert!(
        !compiled.ruleset_text.contains("bilibili.com"),
        "protected apex bilibili.com must not be blocked"
    );
    assert!(
        !compiled.ruleset_text.contains("apple.com"),
        "allowlisted apple.com must not be blocked"
    );
    assert!(
        !compiled.ruleset_text.contains("100.64.0.0")
            && !compiled.ruleset_text.contains("192.168.1.0")
            && !compiled.ruleset_text.contains("198.51.100.0")
            && !compiled.ruleset_text.contains("8.8.4.0")
            && !compiled.ruleset_text.contains("104.16.0.0")
            && !compiled.ruleset_text.contains("fd7a:115c:a1e0"),
        "reserved/LAN/Tailscale/documentation and shared-CDN/public-DNS CIDRs must be stripped"
    );
    assert!(
        compiled
            .ruleset_text
            .contains("IP-CIDR,45.33.32.0/24,no-resolve\n"),
        "public non-CDN IP-CIDR should remain with no-resolve"
    );

    // Module assertions
    assert!(compiled.module_text.contains("high_prio ="));
    assert!(!compiled.module_text.contains("low_prio ="));
    let high_pos = compiled.module_text.find("high_prio =").unwrap();
    let rp_pos = compiled.module_text.find("surge-removeparam =").unwrap();
    assert!(
        high_pos < rp_pos,
        "surge-removeparam must come strictly last"
    );

    // Excluded apple MITM host must appear as -*.apple.com strictly before positives, and push.apple.com dropped
    let mitm_line = compiled
        .module_text
        .lines()
        .find(|l| l.starts_with("hostname = "))
        .expect("expected MITM hostname line");
    assert!(mitm_line.starts_with("hostname = %INSERT% -*.apple.com"));
    assert!(!mitm_line.contains("push.apple.com"));
    assert!(mitm_line.contains("api.bilibili.com"));

    // Verify module passes Surge verifier
    let (scripts, mitm_hosts) =
        verify_module_text(&compiled.module_text).expect("compiled module must pass verifier");
    assert_eq!(scripts, 2);
    assert_eq!(mitm_hosts, 1);

    // Also test full directory verifier + negative overlap/corruption checks
    let tmp = TempDir::new().unwrap();
    let adblock_min_ruleset = compiled.ruleset_text.clone();
    let padded_ad_ruleset = format!(
        "{}DOMAIN-SUFFIX,googlesyndication.com\nDOMAIN-SUFFIX,pangolin-sdk-toutiao.com\nDOMAIN-SUFFIX,mobads.baidu.com\nDOMAIN-SUFFIX,pos.baidu.com\n",
        adblock_min_ruleset
    );
    let padded_priv_ruleset =
        "DOMAIN,app-measurement.com\nDOMAIN-SUFFIX,scorecardresearch.com\nDOMAIN,hm.baidu.com\n";
    fs::write(tmp.path().join("Adblock.list"), &padded_ad_ruleset).unwrap();
    fs::write(tmp.path().join("Privacy.list"), padded_priv_ruleset).unwrap();
    fs::write(tmp.path().join("Adblock.sgmodule"), &compiled.module_text).unwrap();

    let report = verify_adblock_dir(tmp.path(), &overrides, 5, 3)
        .expect("directory verification should pass");
    assert_eq!(report.module_scripts, 2);
    assert_eq!(report.privacy_ruleset_total, 3);

    // Injecting an overlapping domain/subdomain into Privacy.list must fail disjointness check
    fs::write(
        tmp.path().join("Privacy.list"),
        format!("{}DOMAIN,sub.doubleclick.net\n", padded_priv_ruleset),
    )
    .unwrap();
    assert!(
        verify_adblock_dir(tmp.path(), &overrides, 0, 0).is_err(),
        "overlapping domain hierarchy across Adblock.list and Privacy.list must fail verifier"
    );
    fs::write(tmp.path().join("Privacy.list"), padded_priv_ruleset).unwrap();

    // Corrupting Adblock.list with a policy token must fail verification
    fs::write(
        tmp.path().join("Adblock.list"),
        "DOMAIN,bad.example.com,REJECT\n",
    )
    .unwrap();
    assert!(
        verify_adblock_dir(tmp.path(), &overrides, 0, 0).is_err(),
        "RULE-SET with policy column must fail verifier"
    );

    // Corrupting Adblock.sgmodule with unsafe wildcard / %APPEND% / unquoted comma / webview / max-size=-1 / timeout=60 must fail verifier
    assert!(verify_module_text("[MITM]\nhostname = %INSERT% *\n").is_err());
    assert!(verify_module_text("[MITM]\nhostname = %APPEND% api.example.com\n").is_err());
    assert!(
        verify_module_text("[MITM]\nhostname = %INSERT% a.example.com, -b.example.com\n").is_err()
    );
    assert!(
        verify_module_text(
            "#!name=T\n#!desc=T\n#!requirement=CORE_VERSION>=20\n[Script]\nbad = type=http-response,pattern=^https://a\\.example\\.com/v{1,4}$,script-path=https://example.com/s.js,requires-body=true,max-size=524288,engine=jsc\n[MITM]\nhostname = %INSERT% a.example.com\n"
        )
        .is_err()
    );
    assert!(
        verify_module_text(
            "#!name=T\n#!desc=T\n#!requirement=CORE_VERSION>=20\n[Script]\nsurge-removeparam = type=http-request,pattern=^https?://[^?#]+\\?(?:[^#]*&)?(?:utm_source)=,script-path=https://example.com/rp.js,engine=webview\n[MITM]\nhostname = %INSERT% a.example.com\n"
        )
        .is_err()
    );
    assert!(
        verify_module_text(
            "#!name=T\n#!desc=T\n#!requirement=CORE_VERSION>=20\n[Script]\nunbounded = type=http-response,pattern=^https://a\\.example\\.com/v1$,script-path=https://example.com/s.js,requires-body=true,max-size=-1,engine=jsc\n[MITM]\nhostname = %INSERT% a.example.com\n"
        )
        .is_err()
    );
    assert!(
        verify_module_text(
            "#!name=T\n#!desc=T\n#!requirement=CORE_VERSION>=20\n[Script]\nslow = type=http-response,pattern=^https://a\\.example\\.com/v1$,script-path=https://example.com/s.js,requires-body=true,max-size=524288,timeout=60,engine=jsc\n[MITM]\nhostname = %INSERT% a.example.com\n"
        )
        .is_err()
    );

    // [Map Local] allows remote HTTPS URLs for `data-type=file`, rejects local unresolved paths
    let valid_remote_map = "#!name=Test\n#!desc=Test\n#!requirement=CORE_VERSION>=20\n[Map Local]\n^https?://api\\.example\\.com/cfg$ data-type=file data=\"https://example.com/cfg.json\" status-code=200\n[MITM]\nhostname = %INSERT% api.example.com\n";
    assert!(verify_module_text(valid_remote_map).is_ok());
    let invalid_local_map = "#!name=Test\n#!desc=Test\n#!requirement=CORE_VERSION>=20\n[Map Local]\n^https?://api\\.example\\.com/cfg$ data-type=file data=\"local/cfg.json\" status-code=200\n[MITM]\nhostname = %INSERT% api.example.com\n";
    assert!(verify_module_text(invalid_local_map).is_err());
}

#[test]
fn reserved_cidr_guards_reject_lan_and_virtual_mesh_ranges() {
    assert!(overlaps_reserved_v4("10.0.0.0/8".parse().unwrap()));
    assert!(overlaps_reserved_v4("172.16.0.0/12".parse().unwrap()));
    assert!(overlaps_reserved_v4("192.168.0.0/16".parse().unwrap()));
    assert!(overlaps_reserved_v4("100.64.0.0/10".parse().unwrap()));
    assert!(overlaps_reserved_v4("198.18.0.0/15".parse().unwrap()));
    assert!(!overlaps_reserved_v4("1.1.1.0/24".parse().unwrap()));

    assert!(overlaps_reserved_v6("fc00::/7".parse().unwrap()));
    assert!(overlaps_reserved_v6("fe80::/10".parse().unwrap()));
    assert!(!overlaps_reserved_v6("2606:4700::/32".parse().unwrap()));

    assert!(!is_valid_mitm_host("*"));
    assert!(!is_valid_mitm_host("*.com"));
    assert!(!is_valid_mitm_host("*.*.cn"));
    assert!(is_valid_mitm_host("*.example.com"));
    assert!(is_valid_domain("ads.example.com"));
    assert!(normalize_surge_regex("^https?://.*").is_none());
}

#[test]
fn scoped_abp_and_fallback_paths_do_not_pollute_mitm_or_suppress_forced_ad_domains() {
    // 1. Browser fallback feed with $domain=-scoped redirect & path rules must not pollute [Map Local] / [URL Rewrite] / [MITM]
    let fallback_src = dummy_adblock_source(
        "browser_fallback",
        AdblockSourceRole::RulesetFallback,
        AdblockSourceFormat::AbpFilter,
        90,
    );
    let fallback_raw = r#"
||googlesyndication.com/pagead/js/adsbygoogle.js$script,redirect=noopjs,domain=mitly.us
||publisher.example.com/ads/banner.js
||googlesyndication.com^
"#;
    let parsed_fallback =
        parse_adblock_source(&fallback_src, fallback_raw.as_bytes()).expect("fallback parse ok");
    assert!(
        parsed_fallback
            .ruleset_suffixes
            .contains("googlesyndication.com"),
        "pure suffix googlesyndication.com must survive"
    );
    assert!(
        parsed_fallback.map_locals.is_empty(),
        "$domain= scoped redirect in RulesetFallback must not emit global Map Local"
    );
    assert!(
        parsed_fallback.url_rewrites.is_empty(),
        "path rules in RulesetFallback must not pollute URL Rewrite"
    );
    assert!(
        parsed_fallback.complex_protected_hosts.is_empty(),
        "RulesetFallback scoped redirects/paths must not protect ad domains"
    );
    assert!(
        parsed_fallback.mitm_hosts.is_empty(),
        "RulesetFallback scoped redirects/paths must not pollute MITM hosts"
    );

    // 2. ComplexFirst ABP feed with bare `$removeparam=srsltid` emits wildcard scope without complex_protected_hosts pollution
    let complex_src = dummy_adblock_source(
        "tracking_params",
        AdblockSourceRole::ComplexFirst,
        AdblockSourceFormat::AbpFilter,
        95,
    );
    let complex_raw = "$removeparam=srsltid\n";
    let parsed_complex =
        parse_adblock_source(&complex_src, complex_raw.as_bytes()).expect("removeparam parse ok");
    assert_eq!(parsed_complex.remove_params.len(), 1);
    assert_eq!(parsed_complex.remove_params[0].host_scope, "*");
    assert_eq!(parsed_complex.remove_params[0].param, "srsltid");
    assert!(parsed_complex.complex_protected_hosts.is_empty());

    // 3. ForceRuleSetOverride beats complex_protected_hosts (e.g. pubads.g.doubleclick.net -> doubleclick.net),
    //    while AllowDomainOverride ALWAYS beats ForceRuleSetOverride.
    let mut overrides = AdblockOverrides::empty();
    overrides.allow_domains.push(AllowDomainOverride {
        match_type: AllowDomainMatchType::Suffix,
        domain: "apple.com".to_string(),
        rationale: "Apple core must stay allowed".to_string(),
    });
    overrides.force_rule_set_entries.push(ForceRuleSetOverride {
        target: AdblockRuleTarget::Ad,
        kind: "DOMAIN-SUFFIX".to_string(),
        value: "doubleclick.net".to_string(),
        rationale: "Force pure ad domain even if a submodule references a child path".to_string(),
    });
    overrides.force_rule_set_entries.push(ForceRuleSetOverride {
        target: AdblockRuleTarget::Ad,
        kind: "DOMAIN-SUFFIX".to_string(),
        value: "apple.com".to_string(),
        rationale: "Conflict check: allowlist must still beat forceRuleSetEntries".to_string(),
    });

    let mut compiled_complex = ParsedAdblockSource::default();
    compiled_complex
        .complex_protected_hosts
        .insert("pubads.g.doubleclick.net".to_string());

    let compiled = compile_adblock(
        &[parsed_fallback, parsed_complex, compiled_complex],
        &overrides,
        3,
        3,
    );
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN-SUFFIX,doubleclick.net\n"),
        "forced DOMAIN-SUFFIX,doubleclick.net must survive child complex_protected_hosts"
    );
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN-SUFFIX,googlesyndication.com\n"),
        "googlesyndication.com must remain blocked"
    );
    assert!(
        !compiled.ruleset_text.contains("apple.com"),
        "allow_domains must always beat forceRuleSetEntries"
    );
    assert!(
        compiled.module_text.contains("srsltid"),
        "bare $removeparam=srsltid should compile into surge-removeparam"
    );
}

#[test]
fn script_quoting_and_mitm_excluded_https_pruning_preserve_domain_protection() {
    let mut overrides = AdblockOverrides::empty();
    overrides.mitm_excluded_hosts.push(MitmHostOverride {
        pattern: "api.biliapi.net".to_string(),
        rationale: "Pinned TLS API".to_string(),
    });

    let mut src = ParsedAdblockSource::default();
    // Script with quantifier comma `{1,4}` on non-excluded host -> must be quoted and pass verify
    src.scripts.push(ScriptRule {
        name: "comma_quant".to_string(),
        script_type: ScriptType::HttpResponse,
        pattern: r"^https?://ads\.example\.com/v\d{1,4}/feed$".to_string(),
        script_path: "https://example.com/feed.js".to_string(),
        requires_body: true,
        binary_body_mode: false,
        full_header_mode: false,
        max_size: Some(0),
        timeout: None,
        argument: None,
        engine: None,
        weight: 150,
    });
    // HTTPS script on MITM-excluded host -> script pruned, yet complex_protected_hosts still protects host
    src.complex_protected_hosts
        .insert("api.biliapi.net".to_string());
    src.scripts.push(ScriptRule {
        name: "pinned_https".to_string(),
        script_type: ScriptType::HttpResponse,
        pattern: r"^https?://api\.biliapi\.net/x/v2/splash$".to_string(),
        script_path: "https://example.com/bili.js".to_string(),
        requires_body: true,
        binary_body_mode: false,
        full_header_mode: false,
        max_size: Some(0),
        timeout: None,
        argument: None,
        engine: None,
        weight: 150,
    });
    // Plain HTTP rule on MITM-excluded host is NOT pruned (no MITM required)
    src.url_rewrites
        .push(surge_rules::adblock::model::UrlRewriteRule {
            pattern: r"^http://api\.biliapi\.net/http-only$".to_string(),
            replacement: "_".to_string(),
            mode: UrlRewriteMode::Reject,
            weight: 150,
        });
    // Try blocking api.biliapi.net in fallback ruleset
    src.ruleset_domains.insert("api.biliapi.net".to_string());

    let compiled = compile_adblock(&[src], &overrides, 1, 1);
    assert!(
        compiled
            .module_text
            .contains("pattern=\"^https?://ads\\\\.example\\\\.com/v\\\\d{1,4}/feed$\""),
        "comma-bearing pattern must be double-quoted with escaped backslashes"
    );
    assert!(!compiled.module_text.contains("pinned_https ="));
    assert!(
        compiled
            .module_text
            .contains("^http://api\\.biliapi\\.net/http-only$")
    );
    assert!(!compiled.ruleset_text.contains("api.biliapi.net"));
    verify_module_text(&compiled.module_text).expect("quoted script module must verify");
}

#[test]
fn removeparam_separates_safe_global_and_scoped_webview_scripts() {
    let overrides = AdblockOverrides::empty();
    let mut src = ParsedAdblockSource::default();
    src.remove_params.extend([
        RemoveParamRule {
            host_scope: "*".to_string(),
            param: "utm_source".to_string(),
            weight: 100,
        },
        RemoveParamRule {
            host_scope: "*".to_string(),
            param: "id".to_string(),
            weight: 100,
        },
        RemoveParamRule {
            host_scope: "*".to_string(),
            param: "from".to_string(),
            weight: 100,
        },
        RemoveParamRule {
            host_scope: "shop.example.com".to_string(),
            param: "id".to_string(),
            weight: 120,
        },
    ]);

    let compiled = compile_adblock(&[src], &overrides, 1, 1);
    verify_module_text(&compiled.module_text).expect("split removeparam module must verify");
    let script_lines: Vec<&str> = compiled
        .module_text
        .lines()
        .skip_while(|l| *l != "[Script]")
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .collect();
    assert_eq!(script_lines.len(), 2);

    let global_line = script_lines
        .iter()
        .copied()
        .find(|l| l.starts_with("surge-removeparam ="))
        .expect("missing surge-removeparam");
    assert!(global_line.contains("engine=jsc"));
    assert!(global_line.contains("utm_source"));
    assert!(!global_line.contains("from"));
    assert!(!global_line.contains("*=id"));

    let scoped_line = script_lines
        .iter()
        .copied()
        .find(|l| l.starts_with("surge-removeparam-scoped ="))
        .expect("missing surge-removeparam-scoped");
    assert!(scoped_line.contains("engine=jsc"));
    assert!(scoped_line.contains("shop\\.example\\.com"));
    assert!(scoped_line.contains("shop.example.com=id"));
}

#[test]
fn adguard_corelibs_modifiers_compile_and_fallback_prunes_already_blocked_hosts() {
    assert!(overlaps_shared_cdn_or_dns_v4(
        "104.16.0.0/12".parse().unwrap()
    ));
    assert!(overlaps_shared_cdn_or_dns_v4("1.1.1.0/24".parse().unwrap()));
    assert!(overlaps_shared_cdn_or_dns_v4("8.8.8.0/24".parse().unwrap()));
    assert!(overlaps_shared_cdn_or_dns_v6(
        "2606:4700::/32".parse().unwrap()
    ));

    let complex_cfg = dummy_adblock_source(
        "corelibs_complex",
        AdblockSourceRole::ComplexFirst,
        AdblockSourceFormat::AbpFilter,
        145,
    );
    let complex_raw = r#"
example.com#%#//scriptlet('set-constant', 'ads', 'false')
example.com#@%#//scriptlet('set-constant', 'ads', 'false')
||api.stream.example.com/v1/manifest$jsonprune=\$..[ad_pods\, ad_slots]
||api.stream.example.com/v1/config$jsonprune=\$.experiments["ad/banner"].enabled
||cdn.stream.example.com/app.js$replace=/("ad_enabled"\s*:\s*)true/\$1false/i
||live.stream.example.com/playlist.m3u8$hls=/#UPLYNK-SEGMENT:.*\,ad/t
||dash.stream.example.com/mpd$xmlprune=//*[name()="Period"][.//*[@value="Ad"]] | //*[name()="Period"]/@start[boolean(//*[@value="Ad"])]
||api.stream.example.com/v1/init$removeheader=request:X-Ad-Client
||api.stream.example.com/v1/init$removeheader=Set-Cookie
$removeparam=/^utm_[a-z0-9_]+$/i
||shop.stream.example.com^$removeparam=/^spm_[a-z0-9_]+$/i
@@||exempt.stream.example.com^$removeparam
"#;
    let parsed_complex =
        parse_adblock_source(&complex_cfg, complex_raw.as_bytes()).expect("corelibs complex parse");
    assert!(parsed_complex.ruleset_domains.is_empty());
    assert!(parsed_complex.ruleset_suffixes.is_empty());
    assert_eq!(parsed_complex.header_rewrites.len(), 2);
    assert!(
        parsed_complex
            .body_rewrites
            .iter()
            .any(|b| b.expression == r#"del(.experiments?["ad/banner"]?.enabled?)"#),
        "bracketed key jsonprune should transpile to native jq Body Rewrite"
    );
    assert_eq!(
        parsed_complex.adguard_transforms.len(),
        4,
        "recursive jsonprune + multiline/backref replace + hls + xmlprune should emit AdguardTransformRule"
    );

    // RulesetFallback source:
    // 1. `googlesyndication.com` is ALSO blocked as `||googlesyndication.com^` -> fallback redirect MUST be pruned!
    // 2. `player.mixed-site.org` is NOT blocked in Adblock.list -> fallback $hls rule MUST survive into Adblock.sgmodule!
    let fallback_cfg = dummy_adblock_source(
        "corelibs_fallback",
        AdblockSourceRole::RulesetFallback,
        AdblockSourceFormat::AbpFilter,
        95,
    );
    let fallback_raw = r#"
||googlesyndication.com^
||googlesyndication.com/pagead/js/adsbygoogle.js$redirect=googlesyndication-adsbygoogle
||player.mixed-site.org/live/*.m3u8$hls=/#EXT-X-CUE-OUT/
"#;
    let parsed_fallback = parse_adblock_source(&fallback_cfg, fallback_raw.as_bytes())
        .expect("corelibs fallback parse");

    let overrides = AdblockOverrides::empty();
    let compiled = compile_adblock(&[parsed_complex, parsed_fallback], &overrides, 2, 2);

    verify_module_text(&compiled.module_text).expect("CoreLibs compiled module must pass verifier");

    assert!(
        !compiled.module_text.contains("googlesyndication"),
        "fallback redirect on already-blocked googlesyndication.com must be pruned from module & MITM"
    );
    assert!(
        compiled.module_text.contains("player\\.mixed-site\\.org")
            && compiled.module_text.contains("player.mixed-site.org"),
        "fallback $hls rule on unblocked mixed host must be promoted into module & MITM"
    );
    assert!(
        compiled.module_text.contains("surge-adguard-1 =")
            && compiled
                .module_text
                .contains("https://rule-set.ygxz.de/surge-adguard.js")
            && compiled.module_text.contains("argument=\"u:"),
        "expected surge-adguard webview runtime scripts with percent-encoded JSON ops"
    );
    assert!(
        compiled
            .module_text
            .contains("-exempt.stream.example.com=*"),
        "expected @@$removeparam exemption in surge-removeparam argument"
    );
}

#[test]
fn four_tier_precedence_protects_canaries_from_noisy_upstream_allowlists() {
    let mut overrides = AdblockOverrides::empty();
    // P0a: Human Allow ALWAYS wins (even over P0b Force)
    overrides.allow_domains.push(AllowDomainOverride {
        match_type: AllowDomainMatchType::Suffix,
        domain: "openai.com".to_string(),
        rationale: "AI service domain must never be blocked in Adblock.list".to_string(),
    });
    overrides.force_rule_set_entries.push(ForceRuleSetOverride {
        target: AdblockRuleTarget::Ad,
        kind: "DOMAIN-SUFFIX".to_string(),
        value: "openai.com".to_string(),
        rationale: "Verify P0a Human Allow beats P0b Force".to_string(),
    });
    // P0b: Human Force beats P1 Upstream Allowlist (e.g. affiliate allowlist unblocking doubleclick)
    overrides.force_rule_set_entries.push(ForceRuleSetOverride {
        target: AdblockRuleTarget::Ad,
        kind: "DOMAIN-SUFFIX".to_string(),
        value: "doubleclick.net".to_string(),
        rationale: "Pure ad canary must stay blocked".to_string(),
    });

    let mut noisy_upstream_allow = ParsedAdblockSource::default();
    noisy_upstream_allow
        .allow_suffix_domains
        .insert("doubleclick.net".to_string());
    noisy_upstream_allow
        .allow_suffix_domains
        .insert("legit-cdn.example.net".to_string());

    let mut upstream_block = ParsedAdblockSource::default();
    upstream_block
        .ruleset_suffixes
        .insert("openai.com".to_string());
    upstream_block
        .ruleset_suffixes
        .insert("doubleclick.net".to_string());
    upstream_block
        .ruleset_suffixes
        .insert("legit-cdn.example.net".to_string());
    upstream_block
        .ruleset_suffixes
        .insert("ad-tracker.example.org".to_string());

    let compiled = compile_adblock(&[noisy_upstream_allow, upstream_block], &overrides, 2, 2);
    assert!(
        !compiled.ruleset_text.contains("openai.com"),
        "P0a Human Allow must beat P0b Force and P3 Upstream Block"
    );
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN-SUFFIX,doubleclick.net\n"),
        "P0b Human Force must beat noisy P1 Upstream Allowlist"
    );
    assert!(
        !compiled.ruleset_text.contains("legit-cdn.example.net"),
        "P1 Upstream Allowlist must suppress P3 Upstream Block"
    );
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN-SUFFIX,ad-tracker.example.org\n"),
        "P3 Upstream Block must remain active when uncontested"
    );
}

#[test]
fn round2_script_performance_subsumption_and_dialect_guards() {
    // 1. Generic host regex & multipart public suffix MITM wildcard must be rejected
    assert!(
        normalize_surge_regex(
            r"^https?://[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+){1,3}(:\d+)?/api/v\d/movie/index_recommend"
        )
        .is_none()
    );
    assert!(!is_valid_mitm_host("*.com.cn"));
    assert!(!is_valid_mitm_host("*.co.uk"));

    // 2. Surge module parser: drops engine=webview, clamps max-size=-1/0 and timeout=60, preserves {1,4} comma regex
    let mod_src = dummy_adblock_source(
        "perf_mod",
        AdblockSourceRole::ComplexFirst,
        AdblockSourceFormat::SurgeModule,
        94,
    );
    let mod_raw = r#"
#!name=Perf Test
[Map Local]
^https?://api\.zhihu\.com/commercial_api/real_time_launch_v2 data-type=text data="{}" status-code=200

[Script]
webview_heavy = type=http-response,pattern=^https?://api\.heavy\.example\.com/v1/feed$,requires-body=1,engine=webview,script-path=https://example.com/heavy.js
unbounded_json = type=http-response,pattern=^https?://api\.feed\.example\.com/v\d{1,4}/plaza\?,requires-body=1,max-size=-1,timeout=60,script-path=https://example.com/plaza_high.js
unbounded_proto = type=http-response,pattern=^https://proto\.feed\.example\.com/v1/(browse|next),requires-body=1,binary-body-mode=1,max-size=0,timeout=45,script-path=https://example.com/proto.js
shadowed_by_maplocal = type=http-response,pattern=^https://api\.zhihu\.com/commercial_api/real_time_launch_v2,requires-body=1,max-size=-1,script-path=https://example.com/launch.js
"#;
    let parsed_high = parse_adblock_source(&mod_src, mod_raw.as_bytes()).unwrap();
    assert_eq!(
        parsed_high.scripts.len(),
        3,
        "engine=webview script must be dropped at parse time"
    );

    // Lower-weight aggregator module with near-duplicate / narrower scripts
    let low_mod_src = dummy_adblock_source(
        "agg_mod",
        AdblockSourceRole::ComplexFirst,
        AdblockSourceFormat::SurgeModule,
        85,
    );
    let low_mod_raw = r#"
#!name=Agg Test
[Script]
dup_plaza = type=http-response,pattern=^https://api\.feed\.example\.com/v1/plaza\?,requires-body=1,max-size=0,script-path=https://example.com/plaza_low.js
broader_proto = type=http-response,pattern=^https?://proto\.feed\.example\.com/v1/(browse|next|player|search),requires-body=1,binary-body-mode=1,max-size=-1,script-path=https://example.com/proto_all.js
"#;
    let parsed_low = parse_adblock_source(&low_mod_src, low_mod_raw.as_bytes()).unwrap();

    let compiled = compile_adblock(&[parsed_high, parsed_low], &AdblockOverrides::empty(), 2, 2);
    verify_module_text(&compiled.module_text).expect("optimized module must pass strict verifier");
    assert!(!compiled.module_text.contains("max-size=-1"));
    assert!(!compiled.module_text.contains("max-size=0"));
    assert!(!compiled.module_text.contains("timeout=60"));
    assert!(!compiled.module_text.contains("engine=webview"));
    assert!(compiled.module_text.contains("max-size=524288"));
    assert!(compiled.module_text.contains("max-size=1048576"));
    assert!(compiled.module_text.contains("timeout=10"));
    assert!(
        !compiled.module_text.contains("dup_plaza ="),
        "narrower lower-weight v1/plaza script must be subsumed by v\\d{{1,4}}/plaza"
    );
    assert!(
        !compiled.module_text.contains("shadowed_by_maplocal ="),
        "http-response script shadowed by equal/higher-weight Map Local must be pruned"
    );
    assert!(
        compiled.module_text.contains("broader_proto ="),
        "lower-weight script with extra un-matched branches (player|search) must remain reachable"
    );

    // 3. Domain list `# Syntax: Domains (without subdomains)` & ABP first-party `$domain=` allowlist
    let mut tif_src = dummy_adblock_source(
        "tif_mini",
        AdblockSourceRole::RulesetFallback,
        AdblockSourceFormat::DomainList,
        90,
    );
    tif_src.endpoints = vec![EndpointConfig::Direct {
        url: "https://example.com/wildcard/tif.mini-onlydomains.txt".to_string(),
    }];
    let tif_raw = "# Syntax: Domains (without subdomains)\nsub.sharedhost.example.org\n*.wholebad.example.org\n";
    let parsed_tif = parse_adblock_source(&tif_src, tif_raw.as_bytes()).unwrap();
    assert!(
        parsed_tif
            .ruleset_domains
            .contains("sub.sharedhost.example.org")
    );
    assert!(
        !parsed_tif
            .ruleset_suffixes
            .contains("sub.sharedhost.example.org")
    );
    assert!(parsed_tif.ruleset_suffixes.contains("wholebad.example.org"));

    let allow_src = dummy_adblock_source(
        "cn_allow",
        AdblockSourceRole::Allowlist,
        AdblockSourceFormat::AbpFilter,
        96,
    );
    let allow_raw = "@@||console.bce.baidu.com^$domain=console.bce.baidu.com\n@@||coolapk.com\n";
    let parsed_allow = parse_adblock_source(&allow_src, allow_raw.as_bytes()).unwrap();
    assert!(
        parsed_allow
            .allow_exact_domains
            .contains("console.bce.baidu.com")
    );
    assert!(parsed_allow.allow_suffix_domains.contains("coolapk.com"));
}

fn arb_label() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9-]{1,7}".prop_filter("no trailing dash", |s| !s.ends_with('-'))
}

fn arb_domain() -> impl Strategy<Value = String> {
    (
        arb_label(),
        arb_label(),
        prop_oneof![Just("com"), Just("net"), Just("org"), Just("cn")],
    )
        .prop_map(|(sub, root, tld)| format!("{}.{}.{}", sub, root, tld))
}

fn arb_field() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{0,8}".prop_map(String::from)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    // Property 1: Complex-protected hosts & allowlisted domains NEVER match compiled Adblock.list,
    // and DomainTrie exactness/subsumption holds across arbitrary candidate domain sets.
    #[test]
    fn prop_domain_trie_and_complex_host_protection(
        ads in prop::collection::vec(arb_domain(), 1..25),
        protected in prop::collection::vec(arb_domain(), 1..10),
        complex in prop::collection::vec(arb_domain(), 1..10),
    ) {
        let mut overrides = AdblockOverrides::empty();
        for p in &protected {
            overrides.allow_domains.push(AllowDomainOverride {
                match_type: AllowDomainMatchType::Suffix,
                domain: p.clone(),
                rationale: "prop test".to_string(),
            });
        }

        let mut src = ParsedAdblockSource::default();
        for d in &ads {
            src.ruleset_suffixes.insert(d.clone());
            // Also inject a redundant subdomain to exercise trie subsumption
            src.ruleset_domains.insert(format!("sub.{}", d));
        }
        for c in &complex {
            src.complex_protected_hosts.insert(c.clone());
            // Also try blocking complex host as both exact and suffix
            src.ruleset_domains.insert(c.clone());
        }
        for p in &protected {
            src.ruleset_suffixes.insert(p.clone());
            src.ruleset_domains.insert(format!("inner.{}", p));
        }

        let compiled = compile_adblock(&[src], &overrides, 1, 1);
        let mut trie = DomainTrie::default();
        for line in compiled.ruleset_text.lines() {
            if let Some(d) = line.strip_prefix("DOMAIN,") {
                trie.insert_exact(d);
            } else if let Some(s) = line.strip_prefix("DOMAIN-SUFFIX,") {
                trie.insert_suffix(s);
            }
        }

        // Invariant A: no allowlisted domain or its subdomains ever match
        for p in &protected {
            let inner = format!("inner.{}", p);
            prop_assert!(!trie.matches_domain(p));
            prop_assert!(!trie.matches_domain(&inner));
        }

        // Invariant B: no complex-protected host is whole-domain blocked
        for c in &complex {
            prop_assert!(!trie.matches_domain(c));
        }

        // Invariant C: child-over-parent specificity — unforced parent `DOMAIN-SUFFIX,d` yields to
        // strict child `DOMAIN,sub.d`, so `d` itself is never whole-domain blocked while `sub.d` is blocked
        // (unless `d` or `sub.d` was suppressed by `protected` or `complex`).
        for d in &ads {
            let sub = format!("sub.{}", d);
            prop_assert!(
                !compiled
                    .ruleset_text
                    .lines()
                    .any(|l| l == format!("DOMAIN-SUFFIX,{}", d)),
                "unforced parent DOMAIN-SUFFIX,{} should yield to strict child {}",
                d,
                sub
            );
        }
    }

    // Property 2: ABP cosmetic rules, scriptlets, $domain= rules, and $badfilter pairs never leak domain blocks.
    #[test]
    fn prop_abp_cosmetic_and_scoped_rules_never_leak(
        hosts in prop::collection::vec(arb_domain(), 1..15),
        selectors in prop::collection::vec("[a-z0-9_-]{2,12}", 1..15),
    ) {
        let src = dummy_adblock_source(
            "abp_pbt",
            AdblockSourceRole::ComplexFirst,
            AdblockSourceFormat::AbpFilter,
            100,
        );
        let mut lines = Vec::new();
        for (h, sel) in hosts.iter().zip(selectors.iter()) {
            lines.push(format!("{}##.{}", h, sel));
            lines.push(format!("{}#@#.{}", h, sel));
            lines.push(format!("{}#?#.{}", h, sel));
            lines.push(format!("{}#+js({})", h, sel));
            lines.push(format!("||{}/ads/$domain={}", h, sel));
            lines.push(format!("||{}^", h));
            lines.push(format!("||{}^$badfilter", h));
        }
        let raw = lines.join("\n");
        let parsed = parse_adblock_source(&src, raw.as_bytes()).unwrap();
        prop_assert!(parsed.ruleset_domains.is_empty());
        prop_assert!(parsed.ruleset_suffixes.is_empty());
        prop_assert!(parsed.ruleset_keywords.is_empty());
        prop_assert!(parsed.ruleset_wildcards.is_empty());
    }

    // Property 3: Valid dotted/array JSON paths transpile to balanced del(...) expressions with no Surge-breaking chars.
    #[test]
    fn prop_jsonprune_transpiles_to_balanced_jq(
        paths in prop::collection::vec(prop::collection::vec(arb_field(), 1..5), 1..4),
        as_array in prop::collection::vec(any::<bool>(), 1..5),
    ) {
        let mut tokens = Vec::new();
        for fields in &paths {
            let mut segs = Vec::new();
            for (idx, f) in fields.iter().enumerate() {
                if as_array.get(idx).copied().unwrap_or(false) {
                    segs.push(format!("{}[]", f));
                } else {
                    segs.push(f.clone());
                }
            }
            tokens.push(format!(r"\$.{}", segs.join(".")));
        }
        let expr_in = tokens.join(" ");
        let jq = transpile_jsonprune_to_jq(&expr_in);
        prop_assert!(jq.is_some(), "expected '{}' to transpile", expr_in);
        let s = jq.unwrap();
        prop_assert!(s.starts_with("del(") && s.ends_with(')'));
        prop_assert!(!s.contains('\'') && !s.contains('\n') && !s.contains('\r'));
        let open_b = s.matches('[').count();
        let close_b = s.matches(']').count();
        prop_assert_eq!(open_b, close_b);
    }

    // Property 4: Compiled modules with arbitrary scripts, trigger collisions, and MITM hosts/exclusions
    // always pass Surge module verification cleanly.
    #[test]
    fn prop_compiled_module_always_passes_surge_verifier(
        hosts in prop::collection::vec(arb_domain(), 1..12),
        exclusions in prop::collection::vec(arb_domain(), 0..5),
        weights in prop::collection::vec(10u16..200u16, 1..12),
    ) {
        let mut overrides = AdblockOverrides::empty();
        for ex in &exclusions {
            overrides.mitm_excluded_hosts.push(MitmHostOverride {
                pattern: ex.clone(),
                rationale: "pbt exclusion".to_string(),
            });
        }

        let mut src = ParsedAdblockSource::default();
        for (idx, (host, weight)) in hosts.iter().zip(weights.iter()).enumerate() {
            // Deliberately create colliding triggers on shared hosts using modulo
            let pat = format!("^https?://{}/v1/api$", hosts[idx % hosts.len()]);
            src.scripts.push(ScriptRule {
                name: format!("scr_{}", idx),
                script_type: if idx % 2 == 0 {
                    ScriptType::HttpResponse
                } else {
                    ScriptType::HttpRequest
                },
                pattern: pat,
                script_path: format!("https://example.com/s{}.js", idx),
                requires_body: idx % 2 == 0,
                binary_body_mode: false,
                full_header_mode: false,
                max_size: Some(0),
                timeout: None,
                argument: None,
                engine: None,
                weight: *weight,
            });
            src.mitm_hosts.insert(host.clone());
            // Also sprinkle invalid MITM patterns to verify sanitization
            src.mitm_hosts.insert("*".to_string());
            src.mitm_hosts.insert("*.com".to_string());
        }

        let compiled = compile_adblock(&[src], &overrides, 1, 1);
        let verify_res = verify_module_text(&compiled.module_text);
        prop_assert!(
            verify_res.is_ok(),
            "compiled module failed verifier: {:?}\n{}",
            verify_res,
            compiled.module_text
        );

        // Excluded hosts must never also appear as positive MITM items
        if let Some(mitm_line) = compiled
            .module_text
            .lines()
            .find(|l| l.starts_with("hostname = "))
        {
            let rest = mitm_line.trim_start_matches("hostname = %INSERT% ");
            for ex in &exclusions {
                prop_assert!(
                    !rest.split(',').map(str::trim).any(|item| item == ex),
                    "excluded host '{}' leaked as positive MITM host",
                    ex
                );
            }
        }
    }

    // Property 5: RemoveParamRule inputs separate safe global trackers (`surge-removeparam`) from
    // host-scoped trackers (`surge-removeparam-scoped`), never emit generic unsafe params under `*`,
    // always run with `engine=webview`, and add scoped hosts to MITM.
    #[test]
    fn prop_removeparam_compilation_preserves_host_scopes_and_mitm(
        safe_globals in prop::collection::vec(
            prop_oneof![
                Just("utm_source".to_string()),
                Just("utm_medium".to_string()),
                Just("fbclid".to_string()),
                Just("srsltid".to_string()),
            ],
            1..5
        ),
        unsafe_globals in prop::collection::vec(
            prop_oneof![
                Just("id".to_string()),
                Just("from".to_string()),
                Just("key".to_string()),
                Just("ad".to_string()),
            ],
            0..4
        ),
        scoped_rules in prop::collection::vec((arb_domain(), arb_field(), 50u16..180u16), 1..10)
    ) {
        let overrides = AdblockOverrides::empty();
        let mut src = ParsedAdblockSource::default();
        for p in &safe_globals {
            src.remove_params.push(RemoveParamRule {
                host_scope: "*".to_string(),
                param: p.clone(),
                weight: 100,
            });
        }
        for p in &unsafe_globals {
            src.remove_params.push(RemoveParamRule {
                host_scope: "*".to_string(),
                param: p.clone(),
                weight: 120,
            });
        }
        for (host, param, weight) in &scoped_rules {
            src.remove_params.push(RemoveParamRule {
                host_scope: host.clone(),
                param: param.clone(),
                weight: *weight,
            });
        }
        // Also add an unrelated higher-weight http-request script to check ordering
        src.scripts.push(ScriptRule {
            name: "app_specific".to_string(),
            script_type: ScriptType::HttpRequest,
            pattern: r"^https?://specific\.example\.com/init$".to_string(),
            script_path: "https://example.com/init.js".to_string(),
            requires_body: false,
            binary_body_mode: false,
            full_header_mode: false,
            max_size: None,
            timeout: None,
            argument: None,
            engine: None,
            weight: 180,
        });

        let compiled = compile_adblock(&[src], &overrides, 1, 1);
        prop_assert!(verify_module_text(&compiled.module_text).is_ok());

        let script_lines: Vec<&str> = compiled
            .module_text
            .lines()
            .skip_while(|l| *l != "[Script]")
            .skip(1)
            .take_while(|l| !l.trim().is_empty())
            .collect();
        prop_assert_eq!(script_lines.len(), 3);
        prop_assert!(script_lines[0].starts_with("app_specific ="));
        prop_assert!(script_lines[1].starts_with("surge-removeparam ="));
        prop_assert!(script_lines[2].starts_with("surge-removeparam-scoped ="));

        let global_line = script_lines[1];
        prop_assert!(global_line.contains("engine=jsc"));
        for p in &safe_globals {
            prop_assert!(global_line.contains(p.as_str()));
        }
        let global_arg = global_line.split("argument=").nth(1).unwrap_or("");
        for p in &unsafe_globals {
            let pat_token = format!("|{}|", p);
            let pat_start = format!("*={}", p);
            prop_assert!(
                !global_arg.contains(&pat_token)
                    && !global_arg.starts_with(&format!("\"{}|", pat_start))
                    && !global_arg.contains(&format!("=\"{}\"", p)),
                "unsafe global param '{}' leaked into '{}'",
                p,
                global_line
            );
        }

        let scoped_line = script_lines[2];
        prop_assert!(scoped_line.contains("engine=jsc"));
        for (host, param, _) in &scoped_rules {
            prop_assert!(
                scoped_line.contains(param.as_str()),
                "expected scoped param '{}' in '{}'",
                param,
                scoped_line
            );
            prop_assert!(
                compiled.module_text.contains(host.as_str()),
                "expected non-wildcard host '{}' in [MITM]",
                host
            );
        }
    }

    // Property 6: 4-tier precedence (`Human Allow [P0a] > Human Force [P0b] > Upstream Allow [P1] > Upstream Block [P3]`)
    // and AdGuard CoreLibs modifier compilation always produce Surge-valid rulesets and modules.
    #[test]
    fn prop_four_tier_precedence_and_adguard_transforms_verify(
        human_allows in prop::collection::vec(arb_domain(), 1..8),
        human_forces in prop::collection::vec(arb_domain(), 1..8),
        upstream_allows in prop::collection::vec(arb_domain(), 1..8),
        upstream_blocks in prop::collection::vec(arb_domain(), 1..15),
        transform_hosts in prop::collection::vec(arb_domain(), 1..6),
        fields in prop::collection::vec(arb_field(), 1..6),
    ) {
        let mut overrides = AdblockOverrides::empty();
        for ha in &human_allows {
            overrides.allow_domains.push(AllowDomainOverride {
                match_type: AllowDomainMatchType::Suffix,
                domain: ha.clone(),
                rationale: "pbt human allow".to_string(),
            });
        }
        for hf in &human_forces {
            overrides.force_rule_set_entries.push(ForceRuleSetOverride {
                target: AdblockRuleTarget::Ad,
                kind: "DOMAIN-SUFFIX".to_string(),
                value: hf.clone(),
                rationale: "pbt human force".to_string(),
            });
        }

        let cfg = dummy_adblock_source(
            "pbt_corelibs",
            AdblockSourceRole::ComplexFirst,
            AdblockSourceFormat::AbpFilter,
            140,
        );
        let mut raw_lines = Vec::new();
        for (h, f) in transform_hosts.iter().zip(fields.iter()) {
            raw_lines.push(format!(r"||{}/api$jsonprune=\$..{}", h, f));
            raw_lines.push(format!(r"||{}/live.m3u8$hls=/#UPLYNK-SEGMENT:.*\,{}/t", h, f));
            raw_lines.push(format!(r"||{}/app.js$replace=/({}=)true/\$1false/i", h, f));
        }
        let mut parsed = parse_adblock_source(&cfg, raw_lines.join("\n").as_bytes()).unwrap();
        for ua in &upstream_allows {
            parsed.allow_suffix_domains.insert(ua.clone());
        }
        for ub in &upstream_blocks {
            parsed.ruleset_suffixes.insert(ub.clone());
        }

        let compiled = compile_adblock(&[parsed], &overrides, 1, 1);
        prop_assert!(
            verify_module_text(&compiled.module_text).is_ok(),
            "CoreLibs PBT module failed verifier:\n{}",
            compiled.module_text
        );

        let mut trie = DomainTrie::default();
        for line in compiled.ruleset_text.lines() {
            if let Some(d) = line.strip_prefix("DOMAIN,") {
                trie.insert_exact(d);
            } else if let Some(s) = line.strip_prefix("DOMAIN-SUFFIX,") {
                trie.insert_suffix(s);
            }
        }

        // P0a: Human Allow never matches compiled ruleset (even if also in Human Force)
        for ha in &human_allows {
            prop_assert!(!trie.matches_domain(ha));
        }

        // P0b: Human Force always matches unless overridden by P0a Human Allow
        for hf in &human_forces {
            let covered_by_human_allow = human_allows
                .iter()
                .any(|ha| hf == ha || hf.ends_with(&format!(".{}", ha)) || ha.ends_with(&format!(".{}", hf)));
            if !covered_by_human_allow {
                prop_assert!(
                    trie.matches_domain(hf),
                    "P0b forced domain '{}' should be blocked even if in upstream allowlist",
                    hf
                );
            }
        }

        // P1: Upstream Allow never matches unless overridden by P0b Human Force
        for ua in &upstream_allows {
            let covered_by_force = human_forces
                .iter()
                .any(|hf| ua == hf || ua.ends_with(&format!(".{}", hf)));
            if !covered_by_force {
                prop_assert!(
                    !trie.matches_domain(ua),
                    "P1 upstream allow '{}' leaked into ruleset without P0b force",
                    ua
                );
            }
        }
    }
}

#[test]
fn advanced_header_modifiers_compile_with_full_header_mode_and_zero_body_buffering() {
    let mut cfg = dummy_adblock_source(
        "adguard_hdr_test",
        AdblockSourceRole::ComplexFirst,
        AdblockSourceFormat::AbpFilter,
        92,
    );
    cfg.extract_complex_network_rules = true;

    let raw = "\
$cookie=__obref\n\
$cookie=/^_sp_id/\n\
$cookie=keep_session;maxAge=3600\n\
||news.example.com^$cookie=_pc_private\n\
@@||outlook.live.com^$cookie=__obref\n\
@@||proton.me^$cookie\n\
||news.example.com^$csp=script-src 'self' 'unsafe-inline'\n\
||badcsp.example.com^$csp=report-uri /csp-report\n\
/.*/$permissions=browsing-topics=(),document\n\
/.*/$permissions=identity-credentials-get=(),document\n\
@@||shopify.com/authentication/$permissions=browsing-topics=()\n";

    let parsed = parse_adblock_source(&cfg, raw.as_bytes()).unwrap();
    // Modifier-specific `@@` rules must NOT leak into whole-domain DNS allowlists
    assert!(!parsed.allow_suffix_domains.contains("outlook.live.com"));
    assert!(!parsed.allow_suffix_domains.contains("proton.me"));
    // `;maxAge=` cookie storage adjustments and `report-uri` CSP and `identity-credentials-get` FedCM must be rejected
    assert!(
        !parsed
            .header_mods
            .iter()
            .any(|m| m.spec.contains("keep_session"))
    );
    assert!(
        !parsed
            .header_mods
            .iter()
            .any(|m| m.spec.contains("report-uri"))
    );
    assert!(
        !parsed
            .header_mods
            .iter()
            .any(|m| m.spec.contains("identity-credentials-get"))
    );

    let compiled = compile_adblock(&[parsed], &AdblockOverrides::empty(), 1, 1);
    verify_module_text(&compiled.module_text).unwrap();

    // Header modifier scripts must specify full-header-mode=true, engine=jsc, and NO requires-body=true
    let header_scripts: Vec<&str> = compiled
        .module_text
        .lines()
        .filter(|l| {
            l.starts_with("surge-adguard-cookie-")
                || l.starts_with("surge-adguard-policy-")
                || l.starts_with("surge-adguard-global-")
        })
        .collect();
    assert!(
        header_scripts.len() >= 4,
        "expected scoped + global header modifier scripts, got: {:?}",
        header_scripts
    );
    for line in header_scripts {
        assert!(
            line.contains("full-header-mode=true"),
            "missing full-header-mode: {}",
            line
        );
        assert!(line.contains("engine=jsc"), "missing engine=jsc: {}", line);
        assert!(
            !line.contains("requires-body=true"),
            "header script must not buffer body: {}",
            line
        );
    }
}

#[test]
fn ad_and_privacy_split_enforces_scoped_allowlists_conflict_precedence_and_disjointness() {
    let mut overrides = AdblockOverrides::empty();
    // P0a human allow protects both sides
    overrides.allow_domains.push(AllowDomainOverride {
        match_type: AllowDomainMatchType::Suffix,
        domain: "safe-os.example.com".to_string(),
        rationale: "OS functional endpoint".to_string(),
    });
    // P0b forced Privacy beats Ad allowlist and AdMixed
    overrides.force_rule_set_entries.push(ForceRuleSetOverride {
        target: AdblockRuleTarget::Privacy,
        kind: "DOMAIN".to_string(),
        value: "app-measurement.com".to_string(),
        rationale: "Forced analytics canary".to_string(),
    });

    // Global unbreak allowlist (`Both`) protects both Ad and Privacy
    let mut allow_both = ParsedAdblockSource {
        category: AdblockCategory::Both,
        lineage: "unbreak_both".to_string(),
        weight: 99,
        ..Default::default()
    };
    allow_both
        .allow_suffix_domains
        .insert("unbreak-shared.example.org".to_string());

    // Ad-only allowlist (`Ad`) suppresses Ad & AdMixed, NOT dedicated Privacy
    let mut allow_ad = ParsedAdblockSource {
        category: AdblockCategory::Ad,
        lineage: "easylist_allow".to_string(),
        weight: 96,
        ..Default::default()
    };
    allow_ad
        .allow_suffix_domains
        .insert("pure-tracker-unblocked-by-ad-allow.example.net".to_string());
    allow_ad
        .allow_suffix_domains
        .insert("legit-ad-cdn.example.net".to_string());

    // Privacy-only allowlist (`Privacy`, e.g. ethical analytics) suppresses Privacy & AdMixed, NOT dedicated Ad
    let mut allow_priv = ParsedAdblockSource {
        category: AdblockCategory::Privacy,
        lineage: "ethical_allow".to_string(),
        weight: 95,
        ..Default::default()
    };
    allow_priv
        .allow_suffix_domains
        .insert("plausible-like.example.io".to_string());
    allow_priv
        .allow_suffix_domains
        .insert("pure-ad-unblocked-by-referral-allow.example.net".to_string());

    // Dedicated Ad feed
    let mut src_ad = ParsedAdblockSource {
        category: AdblockCategory::Ad,
        lineage: "adguard_base".to_string(),
        weight: 93,
        ..Default::default()
    };
    src_ad.ruleset_suffixes.extend([
        "pure-ad.example.com".to_string(),
        "pure-ad-unblocked-by-referral-allow.example.net".to_string(),
        "legit-ad-cdn.example.net".to_string(),
        "unbreak-shared.example.org".to_string(),
        "safe-os.example.com".to_string(),
    ]);
    src_ad
        .ruleset_cidrs_v4
        .insert("45.33.40.0/25".parse().unwrap());

    // Dedicated Privacy feed
    let mut src_priv = ParsedAdblockSource {
        category: AdblockCategory::Privacy,
        lineage: "easyprivacy".to_string(),
        weight: 92,
        ..Default::default()
    };
    src_priv.ruleset_suffixes.extend([
        "pure-tracker.example.com".to_string(),
        "pure-tracker-unblocked-by-ad-allow.example.net".to_string(),
        "plausible-like.example.io".to_string(),
        "unbreak-shared.example.org".to_string(),
        "safe-os.example.com".to_string(),
    ]);
    src_priv
        .ruleset_cidrs_v4
        .insert("45.33.40.128/25".parse().unwrap());
    src_priv
        .ruleset_cidrs_v4
        .insert("45.33.50.0/24".parse().unwrap());

    // Mixed aggregate bundle (`AdMixed`) claiming trackers, ethical analytics, and fallback domains
    let mut src_mixed = ParsedAdblockSource {
        category: AdblockCategory::AdMixed,
        lineage: "hagezi_ultimate".to_string(),
        weight: 91,
        ..Default::default()
    };
    src_mixed.ruleset_suffixes.extend([
        "pure-tracker.example.com".to_string(),
        "plausible-like.example.io".to_string(),
        "mixed-only-ad.example.com".to_string(),
    ]);
    // Child domain of pure-ad.example.com claimed by Privacy -> must be subsumed by unified trie without overlap
    src_priv
        .ruleset_domains
        .insert("pixel.pure-ad.example.com".to_string());

    let compiled = compile_adblock(
        &[
            allow_both, allow_ad, allow_priv, src_ad, src_priv, src_mixed,
        ],
        &overrides,
        6,
        6,
    );

    // 1. Dedicated Privacy wins over AdMixed on pure-tracker.example.com
    assert!(
        compiled
            .privacy_ruleset_text
            .contains("DOMAIN-SUFFIX,pure-tracker.example.com\n")
    );
    assert!(!compiled.ruleset_text.contains("pure-tracker.example.com"));

    // 2. Mixed-only rule stays in Adblock.list (zero rule loss)
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN-SUFFIX,mixed-only-ad.example.com\n")
    );
    assert!(
        !compiled
            .privacy_ruleset_text
            .contains("mixed-only-ad.example.com")
    );

    // 3. Scoped allowlist isolation:
    //    - Ad allowlist does NOT suppress dedicated Privacy tracker
    assert!(
        compiled
            .privacy_ruleset_text
            .contains("DOMAIN-SUFFIX,pure-tracker-unblocked-by-ad-allow.example.net\n")
    );
    //    - Privacy allowlist does NOT suppress dedicated Ad domain
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN-SUFFIX,pure-ad-unblocked-by-referral-allow.example.net\n")
    );
    //    - Privacy allowlist DOES suppress both Privacy and AdMixed for ethical analytics (`plausible-like.example.io`)
    assert!(!compiled.ruleset_text.contains("plausible-like.example.io"));
    assert!(
        !compiled
            .privacy_ruleset_text
            .contains("plausible-like.example.io")
    );
    //    - Ad allowlist suppresses Ad (`legit-ad-cdn.example.net`), Both allowlist & Human allowlist suppress both
    assert!(!compiled.ruleset_text.contains("legit-ad-cdn.example.net"));
    assert!(!compiled.ruleset_text.contains("unbreak-shared.example.org"));
    assert!(
        !compiled
            .privacy_ruleset_text
            .contains("unbreak-shared.example.org")
    );
    assert!(!compiled.ruleset_text.contains("safe-os.example.com"));
    assert!(
        !compiled
            .privacy_ruleset_text
            .contains("safe-os.example.com")
    );

    // 4. Forced Privacy entry lands in Privacy.list
    assert!(
        compiled
            .privacy_ruleset_text
            .contains("DOMAIN,app-measurement.com\n")
    );
    assert!(!compiled.ruleset_text.contains("app-measurement.com"));

    // 5. Child-over-parent specificity & CIDR aggregation produce zero overlap:
    //    unforced parent `pure-ad.example.com` yields to strict child `pixel.pure-ad.example.com`
    assert!(
        compiled
            .privacy_ruleset_text
            .contains("DOMAIN,pixel.pure-ad.example.com\n"),
        "strict child domain must take precedence over unforced parent suffix"
    );
    assert!(
        !compiled.ruleset_text.contains("pure-ad.example.com"),
        "unforced parent suffix must be ignored when strict child rule exists"
    );
    assert!(
        compiled
            .ruleset_text
            .contains("IP-CIDR,45.33.40.0/24,no-resolve\n"),
        "adjacent /25s coalesce into /24 and tie-break to Ad"
    );
    assert!(!compiled.privacy_ruleset_text.contains("45.33.40."));
    assert!(
        compiled
            .privacy_ruleset_text
            .contains("IP-CIDR,45.33.50.0/24,no-resolve\n")
    );
}

#[test]
fn telemetry_guard_prevents_conflicts_with_privacy_and_adblock_and_verifier_enforces_it() {
    let overrides = AdblockOverrides::empty();
    let telemetry_raw = "\
# Telemetry.list fixture\n\
DOMAIN,browser-intake-us5-datadoghq.com\n\
DOMAIN-SUFFIX,ipinfo.io,extended-matching\n\
DOMAIN-SUFFIX,arkoselabs.com,extended-matching\n";
    let tguard = TelemetryProtectionSet::from_ruleset_text(telemetry_raw);

    let mut src_ad = ParsedAdblockSource {
        category: AdblockCategory::Ad,
        lineage: "ad_feed".to_string(),
        weight: 90,
        ..Default::default()
    };
    src_ad.ruleset_domains.insert("api.ipinfo.io".to_string());
    src_ad
        .ruleset_suffixes
        .insert("doubleclick.net".to_string());

    let mut src_priv = ParsedAdblockSource {
        category: AdblockCategory::Privacy,
        lineage: "priv_feed".to_string(),
        weight: 91,
        ..Default::default()
    };
    src_priv
        .ruleset_domains
        .insert("browser-intake-us5-datadoghq.com".to_string());
    src_priv.ruleset_suffixes.insert("ipinfo.io".to_string());
    src_priv
        .ruleset_domains
        .insert("client-api.arkoselabs.com".to_string());
    src_priv
        .ruleset_suffixes
        .insert("scorecardresearch.com".to_string());

    let compiled =
        compile_adblock_with_telemetry_guard(&[src_ad, src_priv], &overrides, Some(&tguard), 2, 2);

    assert!(!compiled.ruleset_text.contains("ipinfo.io"));
    assert!(!compiled.privacy_ruleset_text.contains("ipinfo.io"));
    assert!(
        !compiled
            .privacy_ruleset_text
            .contains("browser-intake-us5-datadoghq.com")
    );
    assert!(!compiled.privacy_ruleset_text.contains("arkoselabs.com"));
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN-SUFFIX,doubleclick.net\n")
    );
    assert!(
        compiled
            .privacy_ruleset_text
            .contains("DOMAIN-SUFFIX,scorecardresearch.com\n")
    );

    // Verify directory passes when Telemetry.list and Privacy.list / Adblock.list are disjoint,
    // and fails immediately if Privacy.list blocks any Telemetry.list domain or subdomain.
    let tmp = TempDir::new().unwrap();
    fs::write(tmp.path().join("Telemetry.list"), telemetry_raw).unwrap();
    fs::write(tmp.path().join("Adblock.list"), &compiled.ruleset_text).unwrap();
    fs::write(
        tmp.path().join("Privacy.list"),
        &compiled.privacy_ruleset_text,
    )
    .unwrap();
    fs::write(tmp.path().join("Adblock.sgmodule"), &compiled.module_text).unwrap();

    verify_adblock_dir(tmp.path(), &overrides, 0, 0)
        .expect("disjoint Telemetry.list + Privacy.list + Adblock.list must pass");

    fs::write(
        tmp.path().join("Privacy.list"),
        format!("{}DOMAIN,v.ipinfo.io\n", compiled.privacy_ruleset_text),
    )
    .unwrap();
    assert!(
        verify_adblock_dir(tmp.path(), &overrides, 0, 0).is_err(),
        "Privacy.list subdomain colliding with Telemetry.list suffix must fail verifier"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(192))]

    // Property 7: Splitting Adblock into Adblock.list and Privacy.list produces strictly disjoint
    // rule sets (syntactically and hierarchically) while conserving 100% of pre-split blocked hosts.
    #[test]
    fn prop_ad_and_privacy_split_is_disjoint_and_never_loses_pre_split_rules(
        ad_doms in prop::collection::vec(arb_domain(), 1..15),
        priv_doms in prop::collection::vec(arb_domain(), 1..15),
        mixed_doms in prop::collection::vec(arb_domain(), 1..15),
        both_allows in prop::collection::vec(arb_domain(), 0..5),
        ad_allows in prop::collection::vec(arb_domain(), 0..5),
        priv_allows in prop::collection::vec(arb_domain(), 0..5),
    ) {
        let overrides = AdblockOverrides::empty();

        let mut src_both_allow = ParsedAdblockSource {
            category: AdblockCategory::Both,
            lineage: "both_allow".to_string(),
            weight: 98,
            ..Default::default()
        };
        src_both_allow.allow_suffix_domains.extend(both_allows.iter().cloned());

        let mut src_ad_allow = ParsedAdblockSource {
            category: AdblockCategory::Ad,
            lineage: "ad_allow".to_string(),
            weight: 96,
            ..Default::default()
        };
        src_ad_allow.allow_suffix_domains.extend(ad_allows.iter().cloned());

        let mut src_priv_allow = ParsedAdblockSource {
            category: AdblockCategory::Privacy,
            lineage: "priv_allow".to_string(),
            weight: 96,
            ..Default::default()
        };
        src_priv_allow.allow_suffix_domains.extend(priv_allows.iter().cloned());

        let mut src_ad = ParsedAdblockSource {
            category: AdblockCategory::Ad,
            lineage: "pure_ad".to_string(),
            weight: 92,
            ..Default::default()
        };
        for d in &ad_doms {
            src_ad.ruleset_suffixes.insert(d.clone());
        }

        let mut src_priv = ParsedAdblockSource {
            category: AdblockCategory::Privacy,
            lineage: "pure_priv".to_string(),
            weight: 91,
            ..Default::default()
        };
        for d in &priv_doms {
            src_priv.ruleset_suffixes.insert(d.clone());
            src_priv.ruleset_domains.insert(format!("trk.{}", d));
        }

        let mut src_mixed = ParsedAdblockSource {
            category: AdblockCategory::AdMixed,
            lineage: "mixed_bundle".to_string(),
            weight: 88,
            ..Default::default()
        };
        for d in &mixed_doms {
            src_mixed.ruleset_suffixes.insert(d.clone());
        }

        let split = compile_adblock(
            &[
                src_both_allow.clone(),
                src_ad_allow.clone(),
                src_priv_allow.clone(),
                src_ad.clone(),
                src_priv.clone(),
                src_mixed.clone(),
            ],
            &overrides,
            6,
            6,
        );

        // Build pooled pre-split equivalent (where all allowlists apply globally)
        let mut pooled_ad = src_ad;
        pooled_ad.category = AdblockCategory::AdMixed;
        let mut pooled_priv = src_priv;
        pooled_priv.category = AdblockCategory::AdMixed;
        let pre_split = compile_adblock(
            &[
                src_both_allow,
                src_ad_allow,
                src_priv_allow,
                pooled_ad,
                pooled_priv,
                src_mixed,
            ],
            &overrides,
            6,
            6,
        );

        let parse_trie_and_domains = |txt: &str| -> (DomainTrie, Vec<String>) {
            let mut t = DomainTrie::default();
            let mut ds = Vec::new();
            for line in txt.lines() {
                if let Some(d) = line.strip_prefix("DOMAIN,") {
                    t.insert_exact(d);
                    ds.push(d.to_string());
                } else if let Some(s) = line.strip_prefix("DOMAIN-SUFFIX,") {
                    t.insert_suffix(s);
                    ds.push(s.to_string());
                }
            }
            (t, ds)
        };

        let (ad_trie, ad_list) = parse_trie_and_domains(&split.ruleset_text);
        let (priv_trie, priv_list) = parse_trie_and_domains(&split.privacy_ruleset_text);
        let (_pre_trie, pre_list) = parse_trie_and_domains(&pre_split.ruleset_text);

        // Invariant A: Strict mutual disjointness (neither exact nor ancestor/descendant overlap)
        for d in &ad_list {
            prop_assert!(!priv_trie.matches_domain(d), "Ad domain '{}' overlapped Privacy", d);
        }
        for d in &priv_list {
            prop_assert!(!ad_trie.matches_domain(d), "Privacy domain '{}' overlapped Ad", d);
        }

        // Invariant B: Zero rule loss relative to pre-split (every pre-split rule is matched by Ad XOR Privacy)
        for d in &pre_list {
            let in_ad = ad_trie.matches_domain(d);
            let in_priv = priv_trie.matches_domain(d);
            prop_assert!(
                in_ad ^ in_priv,
                "pre-split domain '{}' must match exactly one of Ad ({}) or Privacy ({})",
                d,
                in_ad,
                in_priv
            );
        }
    }
}

#[test]
fn clean_egress_protection_guards_payment_and_ai() {
    use surge_rules::adblock::verify::render_adblock_release_notes;

    let overrides = AdblockOverrides::empty();
    let telemetry_raw = "\
# Telemetry.list fixture\n\
DOMAIN-SUFFIX,arkoselabs.com,extended-matching\n";
    let payment_raw = "\
# Payment.list fixture\n\
DOMAIN,forms.cybersource.com\n\
DOMAIN-SUFFIX,stripe.com,extended-matching\n";
    let ai_raw = "\
# AI.list fixture\n\
DOMAIN,ab.chatgpt.com\n\
DOMAIN-SUFFIX,chatgpt.com,extended-matching\n";

    let mut guard = TelemetryProtectionSet::default();
    guard.ingest_ruleset_text(telemetry_raw);
    guard.ingest_ruleset_text(payment_raw);
    guard.ingest_ruleset_text(ai_raw);

    let mut src_ad = ParsedAdblockSource {
        category: AdblockCategory::Ad,
        lineage: "phishing_feed".to_string(),
        weight: 91,
        ..Default::default()
    };
    src_ad
        .ruleset_domains
        .insert("forms.cybersource.com".to_string());
    src_ad.ruleset_domains.insert("m.stripe.com".to_string());
    src_ad
        .ruleset_suffixes
        .insert("doubleclick.net".to_string());

    let mut src_priv = ParsedAdblockSource {
        category: AdblockCategory::Privacy,
        lineage: "cname_feed".to_string(),
        weight: 90,
        ..Default::default()
    };
    src_priv
        .ruleset_domains
        .insert("ab.chatgpt.com".to_string());
    src_priv
        .ruleset_domains
        .insert("client-api.arkoselabs.com".to_string());
    src_priv
        .ruleset_suffixes
        .insert("scorecardresearch.com".to_string());

    let compiled =
        compile_adblock_with_telemetry_guard(&[src_ad, src_priv], &overrides, Some(&guard), 2, 2);

    for protected in [
        "forms.cybersource.com",
        "stripe.com",
        "ab.chatgpt.com",
        "chatgpt.com",
        "arkoselabs.com",
    ] {
        assert!(!compiled.ruleset_text.contains(protected));
        assert!(!compiled.privacy_ruleset_text.contains(protected));
    }
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN-SUFFIX,doubleclick.net\n")
    );
    assert!(
        compiled
            .privacy_ruleset_text
            .contains("DOMAIN-SUFFIX,scorecardresearch.com\n")
    );

    let tmp = TempDir::new().unwrap();
    fs::write(tmp.path().join("Telemetry.list"), telemetry_raw).unwrap();
    fs::write(tmp.path().join("Payment.list"), payment_raw).unwrap();
    fs::write(tmp.path().join("AI.list"), ai_raw).unwrap();
    fs::write(tmp.path().join("Adblock.list"), &compiled.ruleset_text).unwrap();
    fs::write(
        tmp.path().join("Privacy.list"),
        &compiled.privacy_ruleset_text,
    )
    .unwrap();
    fs::write(tmp.path().join("Adblock.sgmodule"), &compiled.module_text).unwrap();

    let report = verify_adblock_dir(tmp.path(), &overrides, 0, 0)
        .expect("disjoint Telemetry/Payment/AI + Adblock/Privacy must pass");
    let notes = render_adblock_release_notes(&report, 2, 2, 4, 0);
    assert!(notes.contains("https://rule-set.ygxz.de/Adblock.list"));
    assert!(notes.contains("https://rule-set.ygxz.de/Privacy.list"));
    assert!(notes.contains("https://rule-set.ygxz.de/Adblock.sgmodule"));
    assert!(!notes.contains("releases/latest/download"));

    // Collisions against Payment.list or AI.list must fail verify_adblock_dir immediately.
    fs::write(
        tmp.path().join("Adblock.list"),
        format!("{}DOMAIN,m.stripe.com\n", compiled.ruleset_text),
    )
    .unwrap();
    assert!(
        verify_adblock_dir(tmp.path(), &overrides, 0, 0).is_err(),
        "Adblock.list blocking Payment.list subdomain must fail verifier"
    );

    fs::write(tmp.path().join("Adblock.list"), &compiled.ruleset_text).unwrap();
    fs::write(
        tmp.path().join("Privacy.list"),
        format!("{}DOMAIN,ab.chatgpt.com\n", compiled.privacy_ruleset_text),
    )
    .unwrap();
    assert!(
        verify_adblock_dir(tmp.path(), &overrides, 0, 0).is_err(),
        "Privacy.list blocking AI.list domain must fail verifier"
    );
}

#[test]
fn dedicated_web3_and_threat_converters_normalize_subtract_and_skip_cloud_buckets() {
    // 1. json_domain_array (`scamsniffer_domains`)
    let mut ss_src = dummy_adblock_source(
        "scamsniffer_domains",
        AdblockSourceRole::RulesetFallback,
        AdblockSourceFormat::JsonDomainArray,
        88,
    );
    ss_src.filter_direct_collisions = true;
    let ss_raw = r#"[
        "Evil-Drainer.XYZ.",
        "xn--80ak6aa92e.com",
        "localhost",
        "127.0.0.1",
        "pages.dev",
        "github.com",
        "𝗼𝘀𝗺𝗼𝗵𝘂𝗯.𝗰𝗼𝗺"
    ]"#;
    let ss_parsed =
        parse_adblock_source(&ss_src, ss_raw.as_bytes()).expect("json_domain_array should parse");
    assert!(ss_parsed.filter_direct_collisions);
    assert!(ss_parsed.ruleset_domains.contains("evil-drainer.xyz"));
    assert!(ss_parsed.ruleset_domains.contains("xn--80ak6aa92e.com"));
    assert!(ss_parsed.ruleset_suffixes.is_empty());
    assert!(!ss_parsed.ruleset_domains.contains("localhost"));
    assert!(!ss_parsed.ruleset_domains.contains("pages.dev"));

    let mut overrides = AdblockOverrides::empty();
    overrides
        .protected_apex_domains
        .push(ProtectedApexDomainOverride {
            domain: "github.com".to_string(),
            rationale: "Protected developer apex".to_string(),
        });
    let ss_compiled = compile_adblock(&[ss_parsed], &overrides, 1, 1);
    assert!(
        ss_compiled
            .ruleset_text
            .contains("DOMAIN,evil-drainer.xyz\n")
    );
    assert!(!ss_compiled.ruleset_text.contains("github.com"));

    // 2. polkadot_phishing_json (`polkadot_js_phishing`) — subtracts allow[] exact & wildcard suffixes
    let pk_src = dummy_adblock_source(
        "polkadot_js_phishing",
        AdblockSourceRole::RulesetFallback,
        AdblockSourceFormat::PolkadotPhishingJson,
        89,
    );
    let pk_raw = r#"{
        "allow": ["*.fleek.co", "pages.dev", "duckdns.org"],
        "deny": [
            "0-chain-scam.com",
            "0000deadburn.pages.dev",
            "app.fleek.co",
            "fleek.co",
            "09sync00.duckdns.org",
            "0kxwallet-fake.org"
        ],
        "denySub": ["twitter.com/AcalaNetworks"]
    }"#;
    let pk_parsed = parse_adblock_source(&pk_src, pk_raw.as_bytes())
        .expect("polkadot_phishing_json should parse");
    assert_eq!(pk_parsed.ruleset_domains.len(), 2);
    assert!(pk_parsed.ruleset_domains.contains("0-chain-scam.com"));
    assert!(pk_parsed.ruleset_domains.contains("0kxwallet-fake.org"));
    assert!(!pk_parsed.ruleset_domains.contains("0000deadburn.pages.dev"));
    assert!(!pk_parsed.ruleset_domains.contains("app.fleek.co"));
    assert!(!pk_parsed.ruleset_domains.contains("09sync00.duckdns.org"));

    // 3. metamask_config_json (`metamask_eth_phishing`) — subtracts whitelist[] & ignores fuzzylist[]
    let mm_src = dummy_adblock_source(
        "metamask_eth_phishing",
        AdblockSourceRole::RulesetFallback,
        AdblockSourceFormat::MetamaskConfigJson,
        91,
    );
    let mm_raw = r#"{
        "version": 2,
        "tolerance": 1,
        "fuzzylist": ["metamask.io", "opensea.io", "etherscan.io"],
        "whitelist": ["metamask.io", "walletconnect.org"],
        "blacklist": [
            "opencea.mom",
            "metamask.io",
            "ten.metamask.io",
            "relay.walletconnect.org",
            "fake-metamask-claim.top"
        ]
    }"#;
    let mm_parsed = parse_adblock_source(&mm_src, mm_raw.as_bytes())
        .expect("metamask_config_json should parse");
    assert_eq!(mm_parsed.ruleset_domains.len(), 2);
    assert!(mm_parsed.ruleset_domains.contains("opencea.mom"));
    assert!(
        mm_parsed
            .ruleset_domains
            .contains("fake-metamask-claim.top")
    );
    assert!(!mm_parsed.ruleset_domains.contains("metamask.io"));
    assert!(!mm_parsed.ruleset_domains.contains("ten.metamask.io"));
    assert!(
        !mm_parsed
            .ruleset_domains
            .contains("relay.walletconnect.org")
    );
    assert!(!mm_parsed.ruleset_domains.contains("opensea.io"));

    // 4. tweetfeed_csv (`tweetfeed_domains`) — keeps col[2]=="domain" and skips shared cloud buckets
    let tf_src = dummy_adblock_source(
        "tweetfeed_domains",
        AdblockSourceRole::RulesetFallback,
        AdblockSourceFormat::TweetfeedCsv,
        87,
    );
    let tf_raw = "\
2026-11-11 00:40:02,scanmalware,domain,vexolunara.cfd,#phishing,https://x.com/s/1\n\
2026-11-11 00:40:02,scanmalware,url,https://vexolunara.cfd/login,#phishing,https://x.com/s/1\n\
2026-11-11 01:00:00,res,ip,198.51.100.7,#c2,https://x.com/s/2\n\
2026-11-11 01:10:00,res,domain,09rzc45a.s3.us-east-1.amazonaws.com,#phishing,https://x.com/s/3\n\
2026-11-11 01:11:00,res,domain,badbucket.s3.amazonaws.com,#phishing,https://x.com/s/4\n\
2026-11-11 01:12:00,res,domain,badbucket.s3-us-west-2.amazonaws.com,#phishing,https://x.com/s/5\n\
2026-11-11 01:13:00,res,domain,storage.googleapis.com,#phishing,https://x.com/s/6\n\
2026-11-11 01:14:00,res,domain,mal.blob.core.windows.net,#phishing,https://x.com/s/7\n\
2026-11-11 01:15:00,res,domain,pub-0d275574d4.r2.dev,#phishing,https://x.com/s/8\n\
2026-11-11 01:16:00,res,domain,org-apex.workers.dev,#phishing,https://x.com/s/9\n\
2026-11-11 01:17:00,res,domain,c2-worker.evil-actor.workers.dev,#c2,https://x.com/s/10\n";
    let tf_parsed =
        parse_adblock_source(&tf_src, tf_raw.as_bytes()).expect("tweetfeed_csv should parse");
    assert_eq!(tf_parsed.ruleset_domains.len(), 2);
    assert!(tf_parsed.ruleset_domains.contains("vexolunara.cfd"));
    assert!(
        tf_parsed
            .ruleset_domains
            .contains("c2-worker.evil-actor.workers.dev")
    );
    assert!(
        !tf_parsed
            .ruleset_domains
            .contains("09rzc45a.s3.us-east-1.amazonaws.com")
    );
    assert!(!tf_parsed.ruleset_domains.contains("org-apex.workers.dev"));

    // 5. c2intel_domain_csv (`drb_ra_c2_domains`) — skips Domain Fronting CDNs
    let c2_src = dummy_adblock_source(
        "drb_ra_c2_domains",
        AdblockSourceRole::RulesetFallback,
        AdblockSourceFormat::C2intelDomainCsv,
        88,
    );
    let c2_raw = "\
#domain,ioc\n\
api.baidubce.com,Possible Cobalt Strike C2 Fronting Domain\n\
at1.227api.com,Possible Cobalt Strike C2 Domain\n\
bad.s3.amazonaws.com,Possible Cobalt Strike C2 Domain\n";
    let c2_parsed =
        parse_adblock_source(&c2_src, c2_raw.as_bytes()).expect("c2intel_domain_csv should parse");
    assert_eq!(c2_parsed.ruleset_domains.len(), 1);
    assert!(c2_parsed.ruleset_domains.contains("at1.227api.com"));
    assert!(!c2_parsed.ruleset_domains.contains("api.baidubce.com"));
}

#[test]
fn structured_tracker_databases_enforce_strict_category_and_portal_exclusions() {
    // 1. adguard_companiesdb_json (`adguard_companiesdb` + `adguard_companiesdb_analytics` + Allowlist guard mode)
    let cdb_raw = r#"{
        "timeUpdated": "2026-11-16T10:08:27.301Z",
        "categories": {
            "2": "customer_interaction",
            "3": "pornvertising",
            "4": "advertising",
            "5": "essential",
            "6": "site_analytics",
            "9": "cdn",
            "10": "hosting",
            "11": "unknown",
            "15": "telemetry",
            "99": "online_payment"
        },
        "trackers": {
            "criteo": { "name": "Criteo", "categoryId": 4, "url": "https://www.criteo.com/", "companyId": "criteo" },
            "exoclick": { "name": "ExoClick", "categoryId": 3, "url": "https://exoclick.com/", "companyId": "exoclick" },
            "hotjar": { "name": "Hotjar", "categoryId": 6, "url": "https://www.hotjar.com/", "companyId": "hotjar" },
            "adobe_aam": { "name": "Adobe Audience Manager", "categoryId": 4, "url": "https://www.adobe.com/", "companyId": "adobe" },
            "adobe_cdn": { "name": "Adobe CDN", "categoryId": 9, "url": "https://www.adobe.com/", "companyId": "adobe" },
            "digicert": { "name": "DigiCert", "categoryId": 5, "companyId": "digicert" },
            "stripe_pay": { "name": "Stripe", "categoryId": 99, "companyId": "stripe" },
            "aws_host": { "name": "AWS", "categoryId": 10, "companyId": "amazon" },
            "intercom": { "name": "Intercom", "categoryId": 2, "companyId": "intercom" },
            "mystery": { "name": "Mystery", "categoryId": 11 }
        },
        "trackerDomains": {
            "criteo.com": "criteo",
            "exoclick.com": "exoclick",
            "hotjar.com": "hotjar",
            "demdex.net": "adobe_aam",
            "adobe.com": "adobe_aam",
            "adobedtm-cdn.example.net": "adobe_cdn",
            "ocsp.digicert.com": "digicert",
            "hooks.stripe.com": "stripe_pay",
            "compute.amazonaws.com": "aws_host",
            "widget.intercom.io": "intercom",
            "unk-domain.net": "mystery"
        }
    }"#;

    let cdb_ad_src = dummy_adblock_source(
        "adguard_companiesdb",
        AdblockSourceRole::RulesetFallback,
        AdblockSourceFormat::AdguardCompaniesdbJson,
        86,
    );
    let cdb_ad = parse_adblock_source(&cdb_ad_src, cdb_raw.as_bytes()).expect("cdb ad parse");
    assert!(cdb_ad.ruleset_domains.contains("criteo.com"));
    assert!(cdb_ad.ruleset_domains.contains("exoclick.com"));
    assert!(cdb_ad.ruleset_domains.contains("demdex.net"));
    assert!(!cdb_ad.ruleset_domains.contains("hotjar.com"));
    assert!(!cdb_ad.ruleset_domains.contains("adobe.com"));
    assert!(!cdb_ad.ruleset_domains.contains("adobedtm-cdn.example.net"));
    assert!(!cdb_ad.ruleset_domains.contains("ocsp.digicert.com"));
    assert!(!cdb_ad.ruleset_domains.contains("hooks.stripe.com"));
    assert!(!cdb_ad.ruleset_domains.contains("widget.intercom.io"));
    assert!(!cdb_ad.ruleset_domains.contains("unk-domain.net"));

    let mut cdb_priv_src = dummy_adblock_source(
        "adguard_companiesdb_analytics",
        AdblockSourceRole::RulesetFallback,
        AdblockSourceFormat::AdguardCompaniesdbJson,
        86,
    );
    cdb_priv_src.category = AdblockCategory::Privacy;
    let cdb_priv = parse_adblock_source(&cdb_priv_src, cdb_raw.as_bytes()).expect("cdb priv parse");
    assert_eq!(cdb_priv.ruleset_domains.len(), 1);
    assert!(cdb_priv.ruleset_domains.contains("hotjar.com"));

    let cdb_allow_src = dummy_adblock_source(
        "adguard_companiesdb_guard",
        AdblockSourceRole::Allowlist,
        AdblockSourceFormat::AdguardCompaniesdbJson,
        95,
    );
    let cdb_allow =
        parse_adblock_source(&cdb_allow_src, cdb_raw.as_bytes()).expect("cdb allow parse");
    assert!(
        cdb_allow
            .allow_exact_domains
            .contains("adobedtm-cdn.example.net")
    );
    assert!(cdb_allow.allow_exact_domains.contains("ocsp.digicert.com"));
    assert!(cdb_allow.allow_exact_domains.contains("hooks.stripe.com"));
    assert!(!cdb_allow.allow_exact_domains.contains("criteo.com"));

    // 2. ddg_tds_json — keeps default=="block", skips default=="ignore" & portals
    let mut ddg_src = dummy_adblock_source(
        "ddg_tracker_radar",
        AdblockSourceRole::RulesetFallback,
        AdblockSourceFormat::DdgTdsJson,
        88,
    );
    ddg_src.category = AdblockCategory::Privacy;
    let ddg_raw = r#"{
        "trackers": {
            "33across.com": { "domain": "33across.com", "default": "block" },
            "cloudflare.com": { "domain": "cloudflare.com", "default": "ignore" },
            "bing.com": { "domain": "bing.com", "default": "block" },
            "ad-company.example": { "domain": "ad-company.example", "default": "block" }
        }
    }"#;
    let ddg_parsed = parse_adblock_source(&ddg_src, ddg_raw.as_bytes()).expect("ddg parse");
    assert_eq!(ddg_parsed.ruleset_domains.len(), 1);
    assert!(ddg_parsed.ruleset_domains.contains("33across.com"));

    // 3. disconnect_services_json — extracts Advertising vs Analytics/Fingerprinting, subtracts Social/Content
    let disc_raw = r#"{
        "categories": {
            "Advertising": [
                { "AdNet": { "https://adnet.io/": ["ads.adnet.io", "tiktok.com"] } }
            ],
            "Analytics": [
                { "TrackerCo": { "https://trackerco.io/": ["metrics.trackerco.io", "cdn.contentco.net"] } }
            ],
            "FingerprintingInvasive": [
                { "FP": { "https://fp.io/": ["fp-probe.io"] } }
            ],
            "Content": [
                { "ContentCo": { "https://contentco.net/": ["contentco.net"] } }
            ],
            "Social": [
                { "ByteDance": { "https://bytedance.com/": ["tiktok.com"] } }
            ]
        }
    }"#;
    let disc_ad_src = dummy_adblock_source(
        "disconnect_advertising",
        AdblockSourceRole::RulesetFallback,
        AdblockSourceFormat::DisconnectServicesJson,
        88,
    );
    let disc_ad = parse_adblock_source(&disc_ad_src, disc_raw.as_bytes()).expect("disc ad parse");
    assert_eq!(disc_ad.ruleset_domains.len(), 1);
    assert!(disc_ad.ruleset_domains.contains("ads.adnet.io"));
    assert!(!disc_ad.ruleset_domains.contains("tiktok.com"));

    let mut disc_priv_src = dummy_adblock_source(
        "disconnect_tracking",
        AdblockSourceRole::RulesetFallback,
        AdblockSourceFormat::DisconnectServicesJson,
        88,
    );
    disc_priv_src.category = AdblockCategory::Privacy;
    let disc_priv =
        parse_adblock_source(&disc_priv_src, disc_raw.as_bytes()).expect("disc priv parse");
    assert_eq!(disc_priv.ruleset_domains.len(), 2);
    assert!(disc_priv.ruleset_domains.contains("metrics.trackerco.io"));
    assert!(disc_priv.ruleset_domains.contains("fp-probe.io"));
    assert!(!disc_priv.ruleset_domains.contains("cdn.contentco.net"));

    // 4. ghostery_trackerdb_json — extracts whole-domain filters ONLY from pure tracker categories
    let gh_raw = r#"{
        "patterns": {
            "ebay": { "category": "advertising", "domains": ["ebay.com"], "filters": ["||rover.ebay.com^$3p"] },
            "facebook": { "category": "advertising", "domains": ["facebook.com"], "filters": ["||facebook.com/tr"] },
            "mmtro": { "category": "site_analytics", "domains": ["mmtro.com"], "filters": ["||mmtro.com^$3p"] },
            "jwplayer": { "category": "audio_video_player", "domains": ["jwpcdn.com"], "filters": ["||jwpcdn.com^$3p"] }
        }
    }"#;
    let gh_ad_src = dummy_adblock_source(
        "ghostery_trackerdb_ads",
        AdblockSourceRole::RulesetFallback,
        AdblockSourceFormat::GhosteryTrackerdbJson,
        87,
    );
    let gh_ad = parse_adblock_source(&gh_ad_src, gh_raw.as_bytes()).expect("ghostery ad parse");
    assert_eq!(gh_ad.ruleset_domains.len(), 1);
    assert!(gh_ad.ruleset_domains.contains("rover.ebay.com"));
    assert!(!gh_ad.ruleset_domains.contains("ebay.com"));
    assert!(!gh_ad.ruleset_domains.contains("facebook.com"));
    assert!(!gh_ad.ruleset_domains.contains("jwpcdn.com"));

    let mut gh_priv_src = dummy_adblock_source(
        "ghostery_trackerdb_privacy",
        AdblockSourceRole::RulesetFallback,
        AdblockSourceFormat::GhosteryTrackerdbJson,
        87,
    );
    gh_priv_src.category = AdblockCategory::Privacy;
    let gh_priv =
        parse_adblock_source(&gh_priv_src, gh_raw.as_bytes()).expect("ghostery priv parse");
    assert_eq!(gh_priv.ruleset_domains.len(), 1);
    assert!(gh_priv.ruleset_domains.contains("mmtro.com"));
}

#[test]
fn direct_collision_guard_suppresses_community_fps_and_preserves_lineage_budget() {
    use rustc_hash::FxHashSet;

    let direct_raw = "\
# Direct.list fixture\n\
DOMAIN,pay.domestic-portal.com\n\
DOMAIN-SUFFIX,psbc.com,extended-matching\n\
DOMAIN-SUFFIX,cn,extended-matching\n";
    let dguard = DirectProtectionSet::from_ruleset_text(direct_raw);

    // Community Web3 feed with `filter_direct_collisions = true`
    let mut web3_feed = ParsedAdblockSource {
        category: AdblockCategory::Ad,
        lineage: "scamsniffer".to_string(),
        weight: 88,
        filter_direct_collisions: true,
        ..Default::default()
    };
    web3_feed
        .ruleset_domains
        .insert("shop.psbc.com".to_string());
    web3_feed
        .ruleset_domains
        .insert("card.szu.edu.cn".to_string());
    web3_feed
        .ruleset_domains
        .insert("pay.domestic-portal.com".to_string());
    web3_feed
        .ruleset_domains
        .insert("wallet-drainer.xyz".to_string());

    // Dedicated domestic adblock feed (`filter_direct_collisions = false`) must still block domestic ad hosts
    let mut cn_ad_feed = ParsedAdblockSource {
        category: AdblockCategory::Ad,
        lineage: "anti_ad".to_string(),
        weight: 90,
        filter_direct_collisions: false,
        ..Default::default()
    };
    cn_ad_feed
        .ruleset_domains
        .insert("adtracker.example.cn".to_string());

    let mut overrides = AdblockOverrides::empty();
    overrides.force_rule_set_entries.push(ForceRuleSetOverride {
        target: AdblockRuleTarget::Ad,
        kind: "DOMAIN".to_string(),
        value: "forced-ad.psbc.com".to_string(),
        rationale: "Human force entry always overrides DirectProtectionSet".to_string(),
    });

    let compiled = compile_adblock_with_guards(
        &[web3_feed, cn_ad_feed],
        &overrides,
        None,
        Some(&dguard),
        2,
        2,
    );

    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN,wallet-drainer.xyz\n")
    );
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN,adtracker.example.cn\n")
    );
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN,forced-ad.psbc.com\n")
    );
    assert!(!compiled.ruleset_text.contains("shop.psbc.com"));
    assert!(!compiled.ruleset_text.contains("card.szu.edu.cn"));
    assert!(!compiled.ruleset_text.contains("pay.domestic-portal.com"));

    // Verify catalog lineage bitmask budget remains well below 256 (`< 256`)
    let catalog =
        AdblockSourceCatalog::load_from_path(Path::new("sources/generated/adblock-sources.json"))
            .expect("catalog should load");
    let bitmask_lineages: FxHashSet<&str> = catalog
        .sources
        .iter()
        .filter(|s| {
            s.role != AdblockSourceRole::Allowlist
                && matches!(s.category, AdblockCategory::Ad | AdblockCategory::Privacy)
        })
        .map(|s| s.lineage.as_str())
        .collect();
    let total_lineages: FxHashSet<&str> =
        catalog.sources.iter().map(|s| s.lineage.as_str()).collect();
    assert!(
        bitmask_lineages.len() <= 80 && total_lineages.len() < 256,
        "expected bitmask lineages <= 80 and total lineages < 256, got bitmask={} total={}",
        bitmask_lineages.len(),
        total_lineages.len()
    );
}

#[test]
fn mitm_strips_all_positive_wildcards_and_only_includes_on_demand_exact_domains() {
    // 1. Positive MITM host validator rejects all wildcards, raw IPs, port 0, and placeholders
    assert!(is_valid_positive_mitm_host("api.weibo.cn"));
    assert!(is_valid_positive_mitm_host("yuudnn.lz-qs.com:9220"));
    assert!(!is_valid_positive_mitm_host("*.iqiyi.com"));
    assert!(!is_valid_positive_mitm_host("rr*.googlevideo.com"));
    assert!(!is_valid_positive_mitm_host("pic?.ajkimg.com"));
    assert!(!is_valid_positive_mitm_host("101.201.175.228"));
    assert!(!is_valid_positive_mitm_host("<ip-address>"));
    assert!(!is_valid_positive_mitm_host("api.weibo.cn:0"));
    assert!(!is_valid_positive_mitm_host("com.cn"));

    // Surge module verifier rejects any positive wildcard in [MITM] while permitting `-` wildcard exclusions
    assert!(
        verify_module_text(
            "#!name=T\n#!desc=T\n#!requirement=CORE_VERSION>=20\n[MITM]\nhostname = %INSERT% -*.apple.com, *.iqiyi.com\n"
        )
        .is_err()
    );
    assert!(
        verify_module_text(
            "#!name=T\n#!desc=T\n#!requirement=CORE_VERSION>=20\n[MITM]\nhostname = %INSERT% -*.apple.com, api.iqiyi.com\n"
        )
        .is_ok()
    );

    // 2. Regex host extractor expands finite alternations, optional groups, char classes, (?i), and (:\d+)?
    let alt_info = extract_hosts_from_regex(r"(?i)^https?://(gw|heic)\.alicdn\.com(:\d+)?/ad/v1");
    assert_eq!(
        alt_info.positive_mitm_hosts,
        vec!["gw.alicdn.com".to_string(), "heic.alicdn.com".to_string()]
    );

    let opt_info = extract_hosts_from_regex(r"^https?://www\.flyert(rip)?\.com(\.cn)?/ad");
    assert_eq!(opt_info.positive_mitm_hosts.len(), 4);
    assert!(
        opt_info
            .positive_mitm_hosts
            .contains(&"www.flyertrip.com.cn".to_string())
    );

    let cls_info = extract_hosts_from_regex(r"^https://ap[ip]\.bilibili\.com/x/v2/feed");
    assert_eq!(
        cls_info.positive_mitm_hosts,
        vec![
            "api.bilibili.com".to_string(),
            "app.bilibili.com".to_string()
        ]
    );

    let wild_info =
        extract_hosts_from_regex(r"^https?://rr[\w-]+\.googlevideo\.com/initplayback\?");
    assert!(
        wild_info.positive_mitm_hosts.is_empty(),
        "wildcard regex must never emit positive MITM hosts"
    );
    assert!(
        wild_info
            .mitm_patterns
            .contains(&"*.googlevideo.com".to_string()),
        "wildcard scope should remain in mitm_patterns for exclusion checks"
    );

    // 3. End-to-end compilation: orphan upstream MITM hosts, disabled rules, HTTP-only rules,
    //    pre-matching [Rule] rejects, and bulk $cookie sites must NOT enter [MITM].
    let mut overrides = AdblockOverrides::empty();
    overrides.mitm_excluded_hosts.push(MitmHostOverride {
        pattern: "api.bilibili.com".to_string(),
        rationale: "TLS pinned".to_string(),
    });
    overrides.mitm_excluded_hosts.push(MitmHostOverride {
        pattern: "app.bilibili.com".to_string(),
        rationale: "TLS pinned".to_string(),
    });
    overrides.mitm_excluded_hosts.push(MitmHostOverride {
        pattern: "*.tenpay.com".to_string(),
        rationale: "Payment TLS pinned".to_string(),
    });
    overrides
        .disabled_url_patterns
        .push("/amdc/mobileDispatch".to_string());
    overrides.force_rule_set_entries.push(ForceRuleSetOverride {
        target: AdblockRuleTarget::Ad,
        kind: "DOMAIN".to_string(),
        value: "forced-blocked.example.com".to_string(),
        rationale: "Forced ruleset block drops domain before MITM".to_string(),
    });

    let src_cfg = dummy_adblock_source(
        "mod_on_demand",
        AdblockSourceRole::ComplexFirst,
        AdblockSourceFormat::SurgeModule,
        150,
    );
    let raw_mod = r#"
#!name=OnDemandTest
[Rule]
DOMAIN,httpdns.bilivideo.com,REJECT,pre-matching

[URL Rewrite]
^https?://cupid\.iqiyi\.com/mixer\? _ reject
^https?://amdc\.m\.taobao\.com/amdc/mobileDispatch _ reject
^http://plain-http-only\.example\.com/ad _ reject
(?i)^https://ccmsupport-sz\.tenpay\.com/cgi-bin/ad _ reject
^https://ap[ip]\.bilibili\.com/x/v2/splash _ reject
^https://.+\.gamersky\.com/v1/statisticAd _ reject
^https?://rr[\w-]+\.googlevideo\.com/initplayback\? _ reject
^https?://forced-blocked\.example\.com/ad _ reject
^https?://vip\d\.kuwo\.cn/vip/v2/ad _ reject

[MITM]
hostname = %INSERT% *.iqiyi.com, rr*.googlevideo.com, cupid.iqiyi.com, orphan.unused.example.org, raw.githubusercontent.com, amdc.m.taobao.com, plain-http-only.example.com, httpdns.bilivideo.com, forced-blocked.example.com, vip1.kuwo.cn, 101.201.175.228
"#;

    let mut parsed_mod = parse_adblock_source(&src_cfg, raw_mod.as_bytes()).unwrap();
    // Inject >32 scoped $cookie hosts to trigger bulk_mode and verify zero MITM expansion
    for idx in 0..40 {
        parsed_mod
            .header_mods
            .push(surge_rules::adblock::model::HeaderModRule {
                kind: surge_rules::adblock::model::HeaderModKind::Cookie,
                host_scope: format!("site{}.bulk-cookie.example.net", idx),
                spec: "_trk".to_string(),
                weight: 90,
            });
    }
    parsed_mod
        .header_mods
        .push(surge_rules::adblock::model::HeaderModRule {
            kind: surge_rules::adblock::model::HeaderModKind::Cookie,
            host_scope: "cupid.iqiyi.com".to_string(),
            spec: "_trk".to_string(),
            weight: 90,
        });

    let compiled = compile_adblock(&[parsed_mod], &overrides, 1, 1);
    let (_, pos_count) =
        verify_module_text(&compiled.module_text).expect("compiled module must verify");

    let mitm_line = compiled
        .module_text
        .lines()
        .find(|l| l.starts_with("hostname = %INSERT% "))
        .unwrap();

    // Only `cupid.iqiyi.com` (direct rule) and `vip1.kuwo.cn` (bounded regex hint for `vip\d\.kuwo\.cn`) need MITM!
    assert_eq!(pos_count, 2, "unexpected MITM line: {}", mitm_line);
    assert!(mitm_line.contains("cupid.iqiyi.com"));
    assert!(mitm_line.contains("vip1.kuwo.cn"));
    assert!(!mitm_line.contains("*.iqiyi.com"));
    assert!(!mitm_line.contains("googlevideo.com"));
    assert!(!mitm_line.contains("orphan.unused.example.org"));
    assert!(!mitm_line.contains("raw.githubusercontent.com"));
    assert!(!mitm_line.contains("amdc.m.taobao.com"));
    assert!(!mitm_line.contains("plain-http-only.example.com"));
    assert!(!mitm_line.contains("httpdns.bilivideo.com"));
    assert!(!mitm_line.contains("forced-blocked.example.com"));
    assert!(!mitm_line.contains("bulk-cookie.example.net"));
    assert!(!mitm_line.contains("101.201.175.228"));

    // Plain HTTP rule and `https?://` fallback rule remain; pinned HTTPS & unbacked `https://` wildcard rules are pruned
    assert!(compiled.module_text.contains("plain-http-only"));
    assert!(!compiled.module_text.contains("ccmsupport-sz"));
    assert!(!compiled.module_text.contains("ap[ip]"));
    assert!(!compiled.module_text.contains("gamersky"));
}

#[test]
fn routing_exact_domains_auto_allowlisted_across_all_lists_while_ignoring_non_exact_routing_rules()
{
    use surge_rules::adblock::model::ModuleRuleLine;

    let overrides = AdblockOverrides::empty();

    let proxy_raw = "\
# Proxy.list fixture\n\
DOMAIN,account.bandainamcoid.com\n\
DOMAIN,bandainamcoid.com\n\
DOMAIN,nekopoi.click.com,extended-matching\n\
DOMAIN-SUFFIX,proxy-broad.com,extended-matching\n\
DOMAIN-WILDCARD,*.proxy-wc.net,extended-matching\n\
DOMAIN-KEYWORD,proxykw,extended-matching\n";

    let direct_raw = "\
# Direct.list fixture\n\
DOMAIN,beacons.gvt2.com\n\
DOMAIN,portal.domestic-biz.cn\n\
DOMAIN-SUFFIX,direct-broad.cn\n\
DOMAIN-WILDCARD,*.direct-wc.cn\n\
DOMAIN-KEYWORD,directkw\n";

    let payment_raw = "DOMAIN,checkout.bank-pay.com\n";
    let ai_raw = "DOMAIN,api.ai-app.io\n";
    let telemetry_raw = "DOMAIN,challenge.risk-check.net\n";

    let mut guard = TelemetryProtectionSet::default();
    for clean_txt in [telemetry_raw, payment_raw, ai_raw] {
        guard.ingest_ruleset_text(clean_txt);
    }
    for exact_txt in [direct_raw, proxy_raw, ai_raw, payment_raw, telemetry_raw] {
        guard.ingest_exact_domains_from_ruleset_text(exact_txt);
    }

    // Ensure non-exact rules from Proxy.list and Direct.list were NOT ingested into guard
    assert!(!guard.suffix_domains.contains("proxy-broad.com"));
    assert!(!guard.suffix_domains.contains("direct-broad.cn"));
    assert!(!guard.exact_domains.contains("proxy-broad.com"));

    let mut src_ad = ParsedAdblockSource {
        category: AdblockCategory::Ad,
        lineage: "ad_feed".to_string(),
        weight: 92,
        filter_direct_collisions: false,
        ..Default::default()
    };
    // Rules colliding with exact DOMAINs in Proxy/Direct/Payment/AI/Telemetry -> must be suppressed
    src_ad
        .ruleset_suffixes
        .insert("bandainamcoid.com".to_string());
    src_ad
        .ruleset_domains
        .insert("portal.domestic-biz.cn".to_string());
    src_ad
        .ruleset_wildcards
        .insert("beacons*.gvt?.com".to_string());
    src_ad
        .ruleset_wildcards
        .insert("*.domestic-biz.cn".to_string());
    src_ad.ruleset_keywords.insert("domestic-biz".to_string());
    src_ad
        .ruleset_domains
        .insert("checkout.bank-pay.com".to_string());
    src_ad.module_rules.push(ModuleRuleLine {
        line: "DOMAIN,portal.domestic-biz.cn,REJECT,pre-matching".to_string(),
        weight: 95,
    });
    // Sibling/subdomain ad rules that do NOT match exact routing domains -> must SURVIVE
    src_ad
        .ruleset_domains
        .insert("ads.bandainamcoid.com".to_string());
    src_ad
        .ruleset_suffixes
        .insert("ad-sdk.bandainamcoid.com".to_string());
    // Rules under Proxy/Direct non-exact suffix/wildcard/keyword -> must SURVIVE
    src_ad
        .ruleset_domains
        .insert("ads.proxy-broad.com".to_string());
    src_ad
        .ruleset_domains
        .insert("ads.proxy-wc.net".to_string());
    src_ad.ruleset_domains.insert("ad-proxykw.com".to_string());
    src_ad
        .ruleset_domains
        .insert("ads.direct-broad.cn".to_string());
    src_ad
        .ruleset_domains
        .insert("ads.direct-wc.cn".to_string());
    src_ad.ruleset_domains.insert("ad-directkw.cn".to_string());

    let mut src_priv = ParsedAdblockSource {
        category: AdblockCategory::Privacy,
        lineage: "priv_feed".to_string(),
        weight: 91,
        ..Default::default()
    };
    // Privacy suffix `click.com` would block `nekopoi.click.com` in Proxy.list -> must be suppressed
    src_priv.ruleset_suffixes.insert("click.com".to_string());
    src_priv.ruleset_domains.insert("api.ai-app.io".to_string());
    src_priv
        .ruleset_domains
        .insert("challenge.risk-check.net".to_string());
    // Unrelated tracker under click.com -> must SURVIVE
    src_priv.ruleset_domains.insert("trk.click.com".to_string());

    let dguard = DirectProtectionSet::from_ruleset_text(direct_raw);
    let compiled = compile_adblock_with_guards(
        &[src_ad, src_priv],
        &overrides,
        Some(&guard),
        Some(&dguard),
        2,
        2,
    );

    // Suppressed exact/ancestor/wildcard/keyword collisions
    assert!(
        !compiled
            .ruleset_text
            .contains("DOMAIN-SUFFIX,bandainamcoid.com\n")
    );
    assert!(!compiled.ruleset_text.contains("portal.domestic-biz.cn"));
    assert!(!compiled.ruleset_text.contains("beacons*.gvt?.com"));
    assert!(!compiled.ruleset_text.contains("*.domestic-biz.cn"));
    assert!(
        !compiled
            .ruleset_text
            .contains("DOMAIN-KEYWORD,domestic-biz\n")
    );
    assert!(!compiled.ruleset_text.contains("checkout.bank-pay.com"));
    assert!(!compiled.module_text.contains("portal.domestic-biz.cn"));
    assert!(
        !compiled
            .privacy_ruleset_text
            .contains("DOMAIN-SUFFIX,click.com\n")
    );
    assert!(!compiled.privacy_ruleset_text.contains("api.ai-app.io"));
    assert!(
        !compiled
            .privacy_ruleset_text
            .contains("challenge.risk-check.net")
    );

    // Preserved ad subdomains and non-exact routing rule neighbors
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN,ads.bandainamcoid.com\n")
    );
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN-SUFFIX,ad-sdk.bandainamcoid.com\n")
    );
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN,ads.proxy-broad.com\n")
    );
    assert!(compiled.ruleset_text.contains("DOMAIN,ads.proxy-wc.net\n"));
    assert!(compiled.ruleset_text.contains("DOMAIN,ad-proxykw.com\n"));
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN,ads.direct-broad.cn\n")
    );
    assert!(compiled.ruleset_text.contains("DOMAIN,ads.direct-wc.cn\n"));
    assert!(compiled.ruleset_text.contains("DOMAIN,ad-directkw.cn\n"));
    assert!(
        compiled
            .privacy_ruleset_text
            .contains("DOMAIN,trk.click.com\n")
    );

    // Full artifact directory verification must pass
    let tmp = TempDir::new().unwrap();
    fs::write(tmp.path().join("Proxy.list"), proxy_raw).unwrap();
    fs::write(tmp.path().join("Direct.list"), direct_raw).unwrap();
    fs::write(tmp.path().join("Payment.list"), payment_raw).unwrap();
    fs::write(tmp.path().join("AI.list"), ai_raw).unwrap();
    fs::write(tmp.path().join("Telemetry.list"), telemetry_raw).unwrap();
    fs::write(tmp.path().join("Adblock.list"), &compiled.ruleset_text).unwrap();
    fs::write(
        tmp.path().join("Privacy.list"),
        &compiled.privacy_ruleset_text,
    )
    .unwrap();
    fs::write(tmp.path().join("Adblock.sgmodule"), &compiled.module_text).unwrap();

    verify_adblock_dir(tmp.path(), &overrides, 0, 0)
        .expect("exact routing allowlist protection must satisfy verify_adblock_dir");

    // Verifier must reject Adblock.list suffix/wildcard/keyword blocking a Proxy.list exact DOMAIN
    fs::write(
        tmp.path().join("Adblock.list"),
        format!("{}DOMAIN-SUFFIX,bandainamcoid.com\n", compiled.ruleset_text),
    )
    .unwrap();
    assert!(
        verify_adblock_dir(tmp.path(), &overrides, 0, 0).is_err(),
        "Adblock.list suffix matching Proxy.list exact DOMAIN must fail verifier"
    );

    fs::write(
        tmp.path().join("Adblock.list"),
        format!(
            "{}DOMAIN-WILDCARD,*.bandainamcoid.com\n",
            compiled.ruleset_text
        ),
    )
    .unwrap();
    assert!(
        verify_adblock_dir(tmp.path(), &overrides, 0, 0).is_err(),
        "Adblock.list wildcard matching Proxy.list exact DOMAIN must fail verifier"
    );
}

#[test]
fn human_force_ruleset_beats_auto_routing_exact_allowlist_while_human_allow_beats_force() {
    let proxy_raw = "DOMAIN,sub.forced-adnet.com\nDOMAIN,safe.forced-adnet.com\n";
    let guard = TelemetryProtectionSet::from_exact_domains_ruleset_text(proxy_raw);

    let mut overrides = AdblockOverrides::empty();
    overrides.force_rule_set_entries.push(ForceRuleSetOverride {
        target: AdblockRuleTarget::Ad,
        kind: "DOMAIN-SUFFIX".to_string(),
        value: "forced-adnet.com".to_string(),
        rationale: "Explicit human Tier-P0b force block beats auto-imported routing exact domain"
            .to_string(),
    });

    let compiled = compile_adblock_with_guards(&[], &overrides, Some(&guard), None, 1, 1);
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN-SUFFIX,forced-adnet.com\n")
    );

    let tmp = TempDir::new().unwrap();
    fs::write(tmp.path().join("Proxy.list"), proxy_raw).unwrap();
    fs::write(tmp.path().join("Adblock.list"), &compiled.ruleset_text).unwrap();
    fs::write(
        tmp.path().join("Privacy.list"),
        &compiled.privacy_ruleset_text,
    )
    .unwrap();
    fs::write(tmp.path().join("Adblock.sgmodule"), &compiled.module_text).unwrap();
    verify_adblock_dir(tmp.path(), &overrides, 0, 0).expect(
        "human forced suffix must remain valid even when Proxy.list contains a child exact domain",
    );

    // Adding a human Tier-P0a allowDomain overrides Tier-P0b forceRuleSetEntries
    overrides.allow_domains.push(AllowDomainOverride {
        match_type: AllowDomainMatchType::Exact,
        domain: "safe.forced-adnet.com".to_string(),
        rationale: "Human P0a allow overrides P0b force".to_string(),
    });
    let compiled2 = compile_adblock_with_guards(&[], &overrides, Some(&guard), None, 1, 1);
    assert!(
        !compiled2
            .ruleset_text
            .contains("DOMAIN-SUFFIX,forced-adnet.com\n")
    );
}

#[test]
fn child_subdomain_rules_override_unforced_parent_suffix_wildcard_and_root_domain() {
    use surge_rules::adblock::model::ModuleRuleLine;

    let mut overrides = AdblockOverrides::empty();
    overrides.force_rule_set_entries.push(ForceRuleSetOverride {
        target: AdblockRuleTarget::Ad,
        kind: "DOMAIN-SUFFIX".to_string(),
        value: "doubleclick.net".to_string(),
        rationale: "Human-forced pure ad suffix retains whole-suffix block".to_string(),
    });

    let mut src_aggressive = ParsedAdblockSource {
        category: AdblockCategory::Ad,
        lineage: "aggressive_feed".to_string(),
        weight: 85,
        ..Default::default()
    };
    // Multi-tenant platform where aggressive feed blocked whole suffix/root/wildcard
    src_aggressive
        .ruleset_suffixes
        .insert("webflow.io".to_string());
    src_aggressive
        .ruleset_domains
        .insert("webflow.io".to_string());
    src_aggressive
        .ruleset_wildcards
        .insert("*.webflow.io".to_string());
    src_aggressive.module_rules.push(ModuleRuleLine {
        line: "DOMAIN-SUFFIX,webflow.io,REJECT,pre-matching".to_string(),
        weight: 90,
    });
    // Multi-level hierarchy (`daraz.com` -> `net.daraz.com` -> `phish.net.daraz.com` + `.net.daraz.`)
    src_aggressive
        .ruleset_suffixes
        .insert("daraz.com".to_string());
    src_aggressive
        .ruleset_suffixes
        .insert("net.daraz.com".to_string());
    src_aggressive
        .ruleset_keywords
        .insert(".net.daraz.".to_string());
    // Parent suffixes whose children are patterned wildcards or child-suffix keywords
    src_aggressive
        .ruleset_suffixes
        .insert("ettoday.net".to_string());
    src_aggressive
        .ruleset_suffixes
        .insert("ixigua.com".to_string());
    // Leaf-only domain claimed in multiple formats (`DOMAIN-SUFFIX`, `DOMAIN-WILDCARD`, `DOMAIN`) with NO child rules
    src_aggressive
        .ruleset_suffixes
        .insert("leaf-only-ad.com".to_string());

    let mut src_surgical = ParsedAdblockSource {
        category: AdblockCategory::Ad,
        lineage: "surgical_feed".to_string(),
        weight: 95,
        ..Default::default()
    };
    src_surgical
        .ruleset_domains
        .insert("evil-phish.webflow.io".to_string());
    src_surgical
        .ruleset_domains
        .insert("phish.net.daraz.com".to_string());
    src_surgical
        .ruleset_wildcards
        .insert("ad*.ettoday.net".to_string());
    src_surgical
        .ruleset_keywords
        .insert("-ad.ixigua.com".to_string());
    // Same-level different formats on `leaf-only-ad.com` + `wildcard-only-parent.org`
    src_surgical
        .ruleset_domains
        .insert("leaf-only-ad.com".to_string());
    src_surgical
        .ruleset_wildcards
        .insert("*.leaf-only-ad.com".to_string());
    src_surgical
        .ruleset_wildcards
        .insert("*.wildcard-only-parent.org".to_string());
    // Child under forced `doubleclick.net` -> must still be subsumed by forced suffix
    src_surgical
        .ruleset_domains
        .insert("ad.doubleclick.net".to_string());

    let compiled = compile_adblock(&[src_aggressive, src_surgical], &overrides, 2, 2);

    // 1. Unforced parent suffixes, catch-all `*.parent`, TLD-wildcard `.parent.`, and root `DOMAIN` are ignored
    assert!(!compiled.ruleset_text.contains("DOMAIN-SUFFIX,webflow.io\n"));
    assert!(!compiled.ruleset_text.contains("DOMAIN,webflow.io\n"));
    assert!(
        !compiled
            .ruleset_text
            .contains("DOMAIN-WILDCARD,*.webflow.io\n")
    );
    assert!(!compiled.module_text.contains("webflow.io"));
    assert!(!compiled.ruleset_text.contains("DOMAIN-SUFFIX,daraz.com\n"));
    assert!(
        !compiled
            .ruleset_text
            .contains("DOMAIN-SUFFIX,net.daraz.com\n")
    );
    assert!(
        !compiled
            .ruleset_text
            .contains("DOMAIN-KEYWORD,.net.daraz.\n")
    );
    assert!(
        !compiled
            .ruleset_text
            .contains("DOMAIN-SUFFIX,ettoday.net\n")
    );
    assert!(!compiled.ruleset_text.contains("DOMAIN-SUFFIX,ixigua.com\n"));

    // 2. Specific child rules survive intact
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN,evil-phish.webflow.io\n")
    );
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN,phish.net.daraz.com\n")
    );
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN-WILDCARD,ad*.ettoday.net\n")
    );
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN-KEYWORD,-ad.ixigua.com\n")
    );

    // 3. Leaf-only parent rules (with zero strict child rules, even across suffix/wildcard/exact formats) stay intact
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN-SUFFIX,leaf-only-ad.com\n")
    );
    assert!(!compiled.ruleset_text.contains("DOMAIN,leaf-only-ad.com\n"));
    assert!(
        !compiled
            .ruleset_text
            .contains("DOMAIN-WILDCARD,*.leaf-only-ad.com\n")
    );
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN-WILDCARD,*.wildcard-only-parent.org\n")
    );

    // 4. Human-forced `doubleclick.net` keeps full suffix and subsumes child `ad.doubleclick.net`
    assert!(
        compiled
            .ruleset_text
            .contains("DOMAIN-SUFFIX,doubleclick.net\n")
    );
    assert!(
        !compiled
            .ruleset_text
            .contains("DOMAIN,ad.doubleclick.net\n")
    );

    // 5. Verifier passes on clean output and rejects coexisting parent + strict child rules
    let tmp = TempDir::new().unwrap();
    fs::write(tmp.path().join("Adblock.list"), &compiled.ruleset_text).unwrap();
    fs::write(
        tmp.path().join("Privacy.list"),
        &compiled.privacy_ruleset_text,
    )
    .unwrap();
    fs::write(tmp.path().join("Adblock.sgmodule"), &compiled.module_text).unwrap();
    verify_adblock_dir(tmp.path(), &overrides, 0, 0)
        .expect("child-over-parent output must pass verify_adblock_dir");

    fs::write(
        tmp.path().join("Adblock.list"),
        format!("{}DOMAIN-SUFFIX,webflow.io\n", compiled.ruleset_text),
    )
    .unwrap();
    assert!(
        verify_adblock_dir(tmp.path(), &overrides, 0, 0).is_err(),
        "coexisting parent DOMAIN-SUFFIX and strict child DOMAIN must fail verifier"
    );

    fs::write(
        tmp.path().join("Adblock.list"),
        format!("{}DOMAIN,webflow.io\n", compiled.ruleset_text),
    )
    .unwrap();
    assert!(
        verify_adblock_dir(tmp.path(), &overrides, 0, 0).is_err(),
        "coexisting unforced parent root DOMAIN and strict child DOMAIN must fail verifier"
    );
}
