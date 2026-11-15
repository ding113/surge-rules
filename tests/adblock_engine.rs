use std::fs;
use std::path::Path;

use ipnet::{Ipv4Net, Ipv6Net};
use proptest::prelude::*;
use tempfile::TempDir;

use surge_rules::adblock::compiler::{
    DomainTrie, compile_adblock, overlaps_reserved_v4, overlaps_reserved_v6,
};
use surge_rules::adblock::config::{
    AdblockOverrides, AdblockPlatformScope, AdblockSourceCatalog, AdblockSourceConfig,
    AdblockSourceFormat, AdblockSourceRole, AllowDomainMatchType, AllowDomainOverride,
    ForceRuleSetOverride, MitmHostOverride, ProtectedApexDomainOverride,
};
use surge_rules::adblock::jq_transpile::transpile_jsonprune_to_jq;
use surge_rules::adblock::model::{
    BodyRewriteKind, ParsedAdblockSource, RemoveParamRule, ScriptRule, ScriptType, UrlRewriteMode,
};
use surge_rules::adblock::parsers::parse_adblock_source;
use surge_rules::adblock::regex_util::{
    is_valid_domain, is_valid_mitm_host, normalize_surge_regex,
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
        format,
        platform: AdblockPlatformScope::Universal,
        lineage: format!("test:{}", id),
        weight,
        core: true,
        extract_complex_network_rules: true,
        extract_fallback_domain_rules: true,
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

    let overrides =
        AdblockOverrides::load_from_path(Path::new("overrides/generated/adblock-overrides.json"))
            .expect("overrides/generated/adblock-overrides.json should load cleanly");
    assert!(
        overrides.allow_domains.len() >= 30,
        "expected curated allowDomains in overrides"
    );
    assert!(
        overrides.protected_apex_domains.len() >= 30,
        "expected curated protectedApexDomains in overrides"
    );
    assert!(
        overrides
            .mitm_excluded_hosts
            .iter()
            .any(|m| m.pattern.contains("apple.com")),
        "expected Apple certificate-pinned hosts excluded from MITM"
    );
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

    // reject-200 / reject-dict / reject-img upgraded to Map Local; standard reject stays in URL Rewrite
    assert_eq!(parsed.map_locals.len(), 3);
    assert_eq!(parsed.url_rewrites.len(), 1);
    assert_eq!(parsed.url_rewrites[0].mode, UrlRewriteMode::Reject);

    // http-response-jq preserved
    assert_eq!(parsed.body_rewrites.len(), 1);
    assert_eq!(
        parsed.body_rewrites[0].kind,
        BodyRewriteKind::HttpResponseJq
    );

    // Unsafe `*.com` must be stripped from MITM
    assert!(parsed.mitm_hosts.contains("api.video.example.com"));
    assert!(parsed.mitm_hosts.contains("*.googlevideo.com"));
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

    // Complex source intercepts api.bilibili.com and deduplicates conflicting script trigger
    let mut complex_src = ParsedAdblockSource::default();
    complex_src
        .complex_protected_hosts
        .insert("api.bilibili.com".to_string());
    complex_src
        .mitm_hosts
        .insert("api.bilibili.com".to_string());
    complex_src.mitm_hosts.insert("push.apple.com".to_string());
    complex_src.scripts.push(ScriptRule {
        name: "low_prio".to_string(),
        script_type: ScriptType::HttpResponse,
        pattern: r"^https?://api\.bilibili\.com/x/v2/feed$".to_string(),
        script_path: "https://example.com/low.js".to_string(),
        requires_body: true,
        binary_body_mode: false,
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
            && !compiled.ruleset_text.contains("fd7a:115c:a1e0"),
        "reserved/LAN/Tailscale/documentation CIDRs must be stripped"
    );
    assert!(
        compiled
            .ruleset_text
            .contains("IP-CIDR,8.8.4.0/24,no-resolve\n"),
        "public IP-CIDR should remain with no-resolve"
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

    // Also test full directory verifier + negative corruption checks
    let tmp = TempDir::new().unwrap();
    let adblock_min_ruleset = compiled.ruleset_text.clone();
    // Inject required PURE_AD_CANARIES so verify_adblock_dir can run full canary suite on small test fixture
    let padded_ruleset = format!(
        "{}DOMAIN-SUFFIX,googlesyndication.com\nDOMAIN-SUFFIX,app-measurement.com\nDOMAIN-SUFFIX,mobads.baidu.com\nDOMAIN-SUFFIX,pos.baidu.com\n",
        adblock_min_ruleset
    );
    fs::write(tmp.path().join("Adblock.list"), &padded_ruleset).unwrap();
    fs::write(tmp.path().join("Adblock.sgmodule"), &compiled.module_text).unwrap();

    let report =
        verify_adblock_dir(tmp.path(), &overrides, 5).expect("directory verification should pass");
    assert_eq!(report.module_scripts, 2);

    // Corrupting Adblock.list with a policy token must fail verification
    fs::write(
        tmp.path().join("Adblock.list"),
        "DOMAIN,bad.example.com,REJECT\n",
    )
    .unwrap();
    assert!(
        verify_adblock_dir(tmp.path(), &overrides, 0).is_err(),
        "RULE-SET with policy column must fail verifier"
    );

    // Corrupting Adblock.sgmodule with unsafe wildcard / %APPEND% / unquoted comma / jsc must fail verifier
    assert!(verify_module_text("[MITM]\nhostname = %INSERT% *\n").is_err());
    assert!(verify_module_text("[MITM]\nhostname = %APPEND% api.example.com\n").is_err());
    assert!(
        verify_module_text("[MITM]\nhostname = %INSERT% a.example.com, -b.example.com\n").is_err()
    );
    assert!(
        verify_module_text(
            "#!name=T\n#!desc=T\n#!requirement=CORE_VERSION>=20\n[Script]\nbad = type=http-response,pattern=^https://a\\.example\\.com/v{1,4}$,script-path=https://example.com/s.js\n[MITM]\nhostname = %INSERT% a.example.com\n"
        )
        .is_err()
    );
    assert!(
        verify_module_text(
            "#!name=T\n#!desc=T\n#!requirement=CORE_VERSION>=20\n[Script]\nsurge-removeparam = type=http-request,pattern=^https?://[^?#]+\\?(?:[^#]*&)?(?:utm_source)=,script-path=https://example.com/rp.js,engine=jsc\n[MITM]\nhostname = %INSERT% a.example.com\n"
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
        kind: "DOMAIN-SUFFIX".to_string(),
        value: "doubleclick.net".to_string(),
        rationale: "Force pure ad domain even if a submodule references a child path".to_string(),
    });
    overrides.force_rule_set_entries.push(ForceRuleSetOverride {
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
    assert!(global_line.contains("engine=webview"));
    assert!(global_line.contains("utm_source"));
    assert!(!global_line.contains("from"));
    assert!(!global_line.contains("*=id"));

    let scoped_line = script_lines
        .iter()
        .copied()
        .find(|l| l.starts_with("surge-removeparam-scoped ="))
        .expect("missing surge-removeparam-scoped");
    assert!(scoped_line.contains("engine=webview"));
    assert!(scoped_line.contains("shop\\.example\\.com"));
    assert!(scoped_line.contains("shop.example.com=id"));
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

        // Invariant C: redundant child `sub.d` must be subsumed whenever `DOMAIN-SUFFIX,d` survived
        for line in compiled.ruleset_text.lines() {
            if let Some(d) = line.strip_prefix("DOMAIN-SUFFIX,") {
                let redundant = format!("DOMAIN,sub.{}", d);
                prop_assert!(
                    !compiled.ruleset_text.lines().any(|l| l == redundant),
                    "redundant child '{}' was not subsumed by DOMAIN-SUFFIX,{}",
                    redundant,
                    d
                );
            }
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
        prop_assert!(global_line.contains("engine=webview"));
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
        prop_assert!(scoped_line.contains("engine=webview"));
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
}
