use std::collections::HashMap;

use anyhow::{Context, Result};
use rustc_hash::{FxHashMap, FxHashSet};
use serde::Deserialize;
use serde_json::Value;

use crate::adblock::compiler::DomainTrie;
use crate::adblock::config::{AdblockCategory, AdblockSourceConfig, AdblockSourceRole};
use crate::adblock::model::ParsedAdblockSource;
use crate::adblock::parsers::ruleset::is_local_hosts_sentinel;
use crate::adblock::regex_util::is_valid_domain;

/// Returns true if `dom` is a shared object-storage bucket or Cloudflare Workers/R2 shared host
/// that must never be blocked wholesale from community IOC feeds.
pub fn is_shared_cloud_bucket_host(dom: &str) -> bool {
    if dom == "storage.googleapis.com" || dom.ends_with(".storage.googleapis.com") {
        return true;
    }
    if dom == "s3.amazonaws.com" || dom.ends_with(".s3.amazonaws.com") {
        return true;
    }
    if dom.ends_with(".amazonaws.com")
        && (dom.contains(".s3.")
            || dom.starts_with("s3.")
            || dom.contains(".s3-")
            || dom.starts_with("s3-"))
    {
        return true;
    }
    if dom == "blob.core.windows.net" || dom.ends_with(".blob.core.windows.net") {
        return true;
    }
    if dom == "r2.dev" || dom.ends_with(".r2.dev") {
        return true;
    }
    if dom == "workers.dev" {
        return true;
    }
    if dom.ends_with(".workers.dev") && dom.as_bytes().iter().filter(|&&b| b == b'.').count() <= 2 {
        return true;
    }
    false
}

/// Rejects RFC-2606 example/test domains and bare multi-tenant PaaS/CDN apex roots.
fn is_reserved_or_multi_tenant_paas_root(dom: &str) -> bool {
    if dom.ends_with(".example")
        || dom.ends_with(".invalid")
        || dom.ends_with(".test")
        || dom.ends_with(".localhost")
    {
        return true;
    }
    matches!(
        dom,
        "example.com"
            | "example.org"
            | "example.net"
            | "pages.dev"
            | "workers.dev"
            | "r2.dev"
            | "vercel.app"
            | "netlify.app"
            | "github.io"
            | "gitlab.io"
            | "herokuapp.com"
            | "firebaseapp.com"
            | "web.app"
            | "appspot.com"
            | "cloudfront.net"
            | "amazonaws.com"
            | "elasticbeanstalk.com"
            | "azurewebsites.net"
            | "azurefd.net"
            | "googleapis.com"
            | "gstatic.com"
            | "gstatic.cn"
            | "googleusercontent.com"
            | "edgekey.net"
            | "edgesuite.net"
            | "akamaihd.net"
            | "akamaized.net"
            | "fastly.net"
            | "cloudflare.com"
            | "cdn.cloudflare.net"
    )
}

/// Guards structured entity-attribution DBs (`companiesdb`, `disconnect`, `ddg`, `ghostery`)
/// against emitting first-party consumer portals, developer CDNs, or fraud-prevention domains.
fn is_consumer_first_party_portal(dom: &str) -> bool {
    matches!(
        dom,
        "google.com"
            | "google.org"
            | "google.net"
            | "google.me"
            | "googlecode.com"
            | "withgoogle.com"
            | "g.cn"
            | "google.cn"
            | "googleapis.cn"
            | "bing.com"
            | "bing.net"
            | "facebook.com"
            | "facebook.net"
            | "tiktok.com"
            | "ttvnw.net"
            | "twitter.com"
            | "x.com"
            | "ebay.com"
            | "ebay-us.com"
            | "ebayclassifiedsgroup.com"
            | "adobe.com"
            | "wordpress.com"
            | "wp.com"
            | "android.com"
            | "yandex.com"
            | "yandex.net"
            | "yahoo.com"
            | "yahoo.net"
            | "yahooinc.com"
            | "muscache.com"
            | "shopifysvc.com"
            | "getsentry.com"
            | "sentry.io"
            | "line.me"
            | "auth0.com"
            | "baidu.com"
            | "baidustatic.com"
            | "taobao.com"
            | "sina.com.cn"
            | "163.com"
            | "126.net"
            | "qq.com"
            | "apple.com"
            | "icloud.com"
            | "microsoft.com"
            | "amazon.com"
            | "github.com"
            | "iovation.com"
            | "online-metrix.net"
            | "riskified.com"
            | "ipqualityscore.com"
            | "arkoselabs.com"
            | "cybersource.com"
            | "cardinalcommerce.com"
            | "signifyd.com"
            | "perimeterx.net"
            | "datadome.co"
            | "siftscience.com"
            | "forter.com"
            | "maxmind.com"
    )
}

fn normalize_exact_domain(raw: &str) -> Option<String> {
    let dom = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if dom.is_empty()
        || is_local_hosts_sentinel(&dom)
        || is_reserved_or_multi_tenant_paas_root(&dom)
        || !is_valid_domain(&dom)
    {
        return None;
    }
    Some(dom)
}

fn normalize_subtraction_suffix(raw: &str) -> Option<String> {
    let stripped = raw
        .trim()
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if !is_valid_domain(&stripped) {
        return None;
    }
    Some(stripped)
}

fn insert_exact_for_role(dom: String, src: &AdblockSourceConfig, out: &mut ParsedAdblockSource) {
    if src.role == AdblockSourceRole::Allowlist {
        out.allow_exact_domains.insert(dom);
    } else {
        out.ruleset_domains.insert(dom);
    }
}

/// Parses a JSON array of domain strings (`["a.com", "b.net", ...]`), e.g. `scamsniffer/scam-database`.
pub fn parse_json_domain_array(
    text: &str,
    src: &AdblockSourceConfig,
    out: &mut ParsedAdblockSource,
) -> Result<()> {
    let items: Vec<String> = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .with_context(|| format!("failed parsing json_domain_array for '{}'", src.id))?;
    for item in items {
        if let Some(dom) = normalize_exact_domain(&item) {
            insert_exact_for_role(dom, src, out);
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct PolkadotPhishingDoc {
    #[serde(default)]
    allow: Vec<String>,
    deny: Vec<String>,
}

/// Parses `polkadot-js/phishing` `all.json` (`{"allow": [...], "deny": [...]}`),
/// subtracting every exact domain and parent-suffix in `allow[]` from `deny[]`.
pub fn parse_polkadot_phishing_json(
    text: &str,
    src: &AdblockSourceConfig,
    out: &mut ParsedAdblockSource,
) -> Result<()> {
    let doc: PolkadotPhishingDoc = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .with_context(|| format!("failed parsing polkadot_phishing_json for '{}'", src.id))?;

    let mut allow_trie = DomainTrie::default();
    for a in &doc.allow {
        if let Some(clean) = normalize_subtraction_suffix(a) {
            allow_trie.insert_suffix(&clean);
        }
    }

    for d in &doc.deny {
        if let Some(dom) = normalize_exact_domain(d)
            && !allow_trie.matches_domain(&dom)
        {
            insert_exact_for_role(dom, src, out);
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct MetamaskConfigDoc {
    #[serde(default)]
    whitelist: Vec<String>,
    blacklist: Vec<String>,
}

/// Parses `MetaMask/eth-phishing-detect` `src/config.json`, ignoring `fuzzylist`
/// and subtracting `whitelist[]` (exact and suffix) from `blacklist[]`.
pub fn parse_metamask_config_json(
    text: &str,
    src: &AdblockSourceConfig,
    out: &mut ParsedAdblockSource,
) -> Result<()> {
    let doc: MetamaskConfigDoc = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .with_context(|| format!("failed parsing metamask_config_json for '{}'", src.id))?;

    let mut whitelist_trie = DomainTrie::default();
    for w in &doc.whitelist {
        if let Some(clean) = normalize_subtraction_suffix(w) {
            whitelist_trie.insert_suffix(&clean);
        }
    }

    for b in &doc.blacklist {
        if let Some(dom) = normalize_exact_domain(b)
            && !whitelist_trie.matches_domain(&dom)
        {
            insert_exact_for_role(dom, src, out);
        }
    }
    Ok(())
}

/// Parses `0xDanielLopez/TweetFeed` CSV rows (`timestamp,researcher,type,value,tag,url`),
/// keeping rows with `col[2] == "domain"` while stripping shared cloud storage buckets.
pub fn parse_tweetfeed_csv(
    text: &str,
    src: &AdblockSourceConfig,
    out: &mut ParsedAdblockSource,
) -> Result<()> {
    let clean_text = text.trim_start_matches('\u{feff}');
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .comment(Some(b'#'))
        .from_reader(clean_text.as_bytes());

    for rec in rdr.records().flatten() {
        let Some(kind) = rec.get(2) else {
            continue;
        };
        if !kind.trim().eq_ignore_ascii_case("domain") {
            continue;
        }
        let Some(raw_val) = rec.get(3) else {
            continue;
        };
        let stripped = raw_val
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        if let Some(dom) = normalize_exact_domain(stripped)
            && !is_shared_cloud_bucket_host(&dom)
        {
            insert_exact_for_role(dom, src, out);
        }
    }
    Ok(())
}

/// Parses `drb-ra/C2IntelFeeds` CSV (`#domain,ioc`), skipping Domain Fronting CDN rows
/// (`ioc` containing `"fronting domain"`) and shared cloud buckets.
pub fn parse_c2intel_domain_csv(
    text: &str,
    src: &AdblockSourceConfig,
    out: &mut ParsedAdblockSource,
) -> Result<()> {
    let clean_text = text.trim_start_matches('\u{feff}');
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .comment(Some(b'#'))
        .from_reader(clean_text.as_bytes());

    for rec in rdr.records().flatten() {
        let Some(raw_dom) = rec.get(0) else {
            continue;
        };
        if raw_dom.trim().eq_ignore_ascii_case("domain") {
            continue;
        }
        if let Some(ioc_desc) = rec.get(1)
            && ioc_desc.to_ascii_lowercase().contains("fronting domain")
        {
            continue;
        }
        if let Some(dom) = normalize_exact_domain(raw_dom)
            && !is_shared_cloud_bucket_host(&dom)
        {
            insert_exact_for_role(dom, src, out);
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CompaniesDbDoc {
    categories: HashMap<String, String>,
    trackers: HashMap<String, CompaniesDbTracker>,
    tracker_domains: HashMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CompaniesDbTracker {
    category_id: Value,
    #[serde(default)]
    company_id: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CompaniesDbBucket {
    Ad,
    Privacy,
    EssentialOrCdnOrPayment,
    ExcludedOther,
}

fn classify_companiesdb_category(cat_name: &str) -> CompaniesDbBucket {
    match cat_name.trim().to_ascii_lowercase().as_str() {
        "advertising" | "pornvertising" => CompaniesDbBucket::Ad,
        "site_analytics" | "mobile_analytics" | "analytics" | "telemetry" => {
            CompaniesDbBucket::Privacy
        }
        "cdn" | "essential" | "online_payment" | "payment" => {
            CompaniesDbBucket::EssentialOrCdnOrPayment
        }
        // Strictly exclude hosting, customer_interaction, telecom, unknown/unk, social_media,
        // audio_video_player, comments, misc, extensions, email, consent, etc.
        _ => CompaniesDbBucket::ExcludedOther,
    }
}

fn extract_url_apex_host(raw_url: &str) -> Option<String> {
    let rest = raw_url
        .trim()
        .strip_prefix("https://")
        .or_else(|| raw_url.trim().strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority
        .split(':')
        .next()?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let stripped = host.strip_prefix("www.").unwrap_or(&host);
    if is_valid_domain(stripped) {
        Some(stripped.to_string())
    } else {
        None
    }
}

/// Parses `AdguardTeam/companiesdb` (`dist/trackers.json`), extracting ONLY pure `advertising`/`pornvertising`
/// (`Ad`) or `site_analytics`/`mobile_analytics`/`telemetry` (`Privacy`) tracker domains while strictly
/// excluding `cdn`, `essential`, `hosting`, `online_payment`, `customer_interaction`, `telecom`, `unknown`/`unk`,
/// and multi-service first-party portal domains. When configured with `role == Allowlist`, emits
/// `cdn`/`essential`/`online_payment` domains into `allow_exact_domains`.
pub fn parse_adguard_companiesdb_json(
    text: &str,
    src: &AdblockSourceConfig,
    out: &mut ParsedAdblockSource,
) -> Result<()> {
    let doc: CompaniesDbDoc = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .with_context(|| format!("failed parsing adguard_companiesdb_json for '{}'", src.id))?;

    let mut cat_buckets: FxHashMap<String, CompaniesDbBucket> = FxHashMap::default();
    for (cid, cname) in &doc.categories {
        cat_buckets.insert(cid.clone(), classify_companiesdb_category(cname));
    }

    let tracker_bucket = |t: &CompaniesDbTracker| -> CompaniesDbBucket {
        let cid_str = match &t.category_id {
            Value::Number(n) => n.to_string(),
            Value::String(s) => s.clone(),
            _ => String::new(),
        };
        cat_buckets
            .get(&cid_str)
            .copied()
            .unwrap_or(CompaniesDbBucket::ExcludedOther)
    };

    // Identify companies that also operate non-ad/non-analytics infrastructure or consumer products
    let mut multi_service_companies: FxHashSet<&str> = FxHashSet::default();
    for tracker in doc.trackers.values() {
        let bucket = tracker_bucket(tracker);
        if matches!(
            bucket,
            CompaniesDbBucket::EssentialOrCdnOrPayment | CompaniesDbBucket::ExcludedOther
        ) && let Some(cid) = tracker.company_id.as_deref()
        {
            multi_service_companies.insert(cid);
        }
    }

    // Collect guard domains mapped under excluded categories so dual-listed domains never leak
    let mut excluded_domains: FxHashSet<String> = FxHashSet::default();
    let mut allow_guard_domains: FxHashSet<String> = FxHashSet::default();
    for (raw_dom, tid) in &doc.tracker_domains {
        let Some(tracker) = doc.trackers.get(tid) else {
            continue;
        };
        let bucket = tracker_bucket(tracker);
        if matches!(
            bucket,
            CompaniesDbBucket::EssentialOrCdnOrPayment | CompaniesDbBucket::ExcludedOther
        ) && let Some(dom) = normalize_exact_domain(raw_dom)
        {
            if bucket == CompaniesDbBucket::EssentialOrCdnOrPayment {
                allow_guard_domains.insert(dom.clone());
            }
            excluded_domains.insert(dom);
        }
    }

    if src.role == AdblockSourceRole::Allowlist {
        out.allow_exact_domains.extend(allow_guard_domains);
        return Ok(());
    }

    for (raw_dom, tid) in &doc.tracker_domains {
        let Some(tracker) = doc.trackers.get(tid) else {
            continue;
        };
        let bucket = tracker_bucket(tracker);
        let category_matches = match src.category {
            AdblockCategory::Ad => bucket == CompaniesDbBucket::Ad,
            AdblockCategory::Privacy => bucket == CompaniesDbBucket::Privacy,
            AdblockCategory::AdMixed => {
                matches!(bucket, CompaniesDbBucket::Ad | CompaniesDbBucket::Privacy)
            }
            AdblockCategory::Both => false,
        };
        if !category_matches {
            continue;
        }
        let Some(dom) = normalize_exact_domain(raw_dom) else {
            continue;
        };
        if excluded_domains.contains(&dom)
            || is_shared_cloud_bucket_host(&dom)
            || is_consumer_first_party_portal(&dom)
        {
            continue;
        }
        // Skip first-party portal root domains of multi-service companies (e.g. adobe.com, baidu.com, line.me)
        if let Some(cid) = tracker.company_id.as_deref()
            && multi_service_companies.contains(cid)
            && let Some(ref u) = tracker.url
            && let Some(portal_host) = extract_url_apex_host(u)
            && dom == portal_host
        {
            continue;
        }
        out.ruleset_domains.insert(dom);
    }

    Ok(())
}

#[derive(Deserialize)]
struct DdgTdsDoc {
    trackers: HashMap<String, DdgTrackerEntry>,
}

#[derive(Deserialize)]
struct DdgTrackerEntry {
    #[serde(default)]
    default: String,
    #[serde(default)]
    domain: Option<String>,
}

/// Parses DuckDuckGo Tracker Radar (`extension-tds.json` / `tds.json`), keeping ONLY
/// tracker entries with `default == "block"` and strictly skipping `default == "ignore"`.
pub fn parse_ddg_tds_json(
    text: &str,
    src: &AdblockSourceConfig,
    out: &mut ParsedAdblockSource,
) -> Result<()> {
    let doc: DdgTdsDoc = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .with_context(|| format!("failed parsing ddg_tds_json for '{}'", src.id))?;

    for (key, entry) in &doc.trackers {
        if !entry.default.trim().eq_ignore_ascii_case("block") {
            continue;
        }
        let raw_dom = entry.domain.as_deref().unwrap_or(key.as_str());
        if let Some(dom) = normalize_exact_domain(raw_dom)
            && !is_shared_cloud_bucket_host(&dom)
            && !is_consumer_first_party_portal(&dom)
        {
            insert_exact_for_role(dom, src, out);
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct DisconnectServicesDoc {
    categories: HashMap<String, Vec<Value>>,
}

fn collect_disconnect_category_domains(entries: &[Value], into: &mut Vec<String>) {
    for entity_obj in entries {
        let Some(entity_map) = entity_obj.as_object() else {
            continue;
        };
        for prop_val in entity_map.values() {
            let Some(prop_map) = prop_val.as_object() else {
                continue;
            };
            for dom_list_val in prop_map.values() {
                let Some(arr) = dom_list_val.as_array() else {
                    continue;
                };
                for item in arr {
                    if let Some(s) = item.as_str() {
                        into.push(s.to_string());
                    }
                }
            }
        }
    }
}

/// Parses Disconnect / Firefox ETP (`services.json` / `disconnect-blacklist.json`),
/// extracting ONLY `Advertising` and `Cryptomining` (`Ad`) or `Analytics`, `FingerprintingInvasive`,
/// and `FingerprintingGeneral` (`Privacy`), while strictly excluding and subtracting `Content`,
/// `Social`, `Disconnect`, `Anti-fraud`, `ConsentManagers`, and `Email*`.
pub fn parse_disconnect_services_json(
    text: &str,
    src: &AdblockSourceConfig,
    out: &mut ParsedAdblockSource,
) -> Result<()> {
    let doc: DisconnectServicesDoc = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .with_context(|| format!("failed parsing disconnect_services_json for '{}'", src.id))?;

    let mut excluded_trie = DomainTrie::default();
    let mut raw_excluded = Vec::new();
    for (cat_name, entries) in &doc.categories {
        let lower = cat_name.trim().to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "content"
                | "social"
                | "disconnect"
                | "anti-fraud"
                | "consentmanagers"
                | "email"
                | "emailaggressive"
        ) {
            collect_disconnect_category_domains(entries, &mut raw_excluded);
        }
    }
    for d in raw_excluded {
        if let Some(clean) = normalize_subtraction_suffix(&d) {
            excluded_trie.insert_suffix(&clean);
        }
    }

    let mut raw_candidates = Vec::new();
    for (cat_name, entries) in &doc.categories {
        let lower = cat_name.trim().to_ascii_lowercase();
        let wanted = match src.category {
            AdblockCategory::Ad => matches!(lower.as_str(), "advertising" | "cryptomining"),
            AdblockCategory::Privacy => matches!(
                lower.as_str(),
                "analytics" | "fingerprintinginvasive" | "fingerprintinggeneral"
            ),
            AdblockCategory::AdMixed => matches!(
                lower.as_str(),
                "advertising"
                    | "cryptomining"
                    | "analytics"
                    | "fingerprintinginvasive"
                    | "fingerprintinggeneral"
            ),
            AdblockCategory::Both => src.role == AdblockSourceRole::Allowlist && lower == "content",
        };
        if wanted {
            collect_disconnect_category_domains(entries, &mut raw_candidates);
        }
    }

    for raw_dom in raw_candidates {
        if let Some(dom) = normalize_exact_domain(&raw_dom) {
            if src.role == AdblockSourceRole::Allowlist {
                out.allow_exact_domains.insert(dom);
            } else if !excluded_trie.matches_domain(&dom)
                && !is_shared_cloud_bucket_host(&dom)
                && !is_consumer_first_party_portal(&dom)
            {
                out.ruleset_domains.insert(dom);
            }
        }
    }

    Ok(())
}

#[derive(Deserialize)]
struct GhosteryTrackerDbDoc {
    patterns: HashMap<String, GhosteryPattern>,
}

#[derive(Deserialize)]
struct GhosteryPattern {
    #[serde(default)]
    category: String,
    #[serde(default)]
    filters: Vec<String>,
}

fn extract_whole_domain_abp_filter(rule: &str) -> Option<String> {
    let rest = rule.trim().strip_prefix("||")?;
    let (host_part, mods_opt) = match rest.split_once('$') {
        Some((h, m)) => (h, Some(m)),
        None => (rest, None),
    };
    if let Some(mods) = mods_opt {
        for raw_mod in mods.split(',') {
            let m = raw_mod.trim().to_ascii_lowercase();
            if m.is_empty() {
                continue;
            }
            if !matches!(
                m.as_str(),
                "3p" | "third-party" | "all" | "important" | "doc" | "document"
            ) {
                return None;
            }
        }
    }
    let host = host_part.strip_suffix('^')?;
    if host.contains('/') || host.contains('*') || host.contains(':') {
        return None;
    }
    normalize_exact_domain(host)
}

/// Parses Ghostery `trackerdb.json`, extracting whole-domain network filters (`patterns[*].filters`)
/// ONLY from `advertising` / `pornvertising` (`Ad`) or `site_analytics` / `telemetry` (`Privacy`),
/// while strictly excluding `cdn`, `essential`, `hosting`, `customer_interaction`,
/// `audio_video_player`, `comments`, `misc`, `social_media`, `consent`, `extensions`, and `utilities`.
pub fn parse_ghostery_trackerdb_json(
    text: &str,
    src: &AdblockSourceConfig,
    out: &mut ParsedAdblockSource,
) -> Result<()> {
    let doc: GhosteryTrackerDbDoc = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .with_context(|| format!("failed parsing ghostery_trackerdb_json for '{}'", src.id))?;

    for pat in doc.patterns.values() {
        let cat = pat.category.trim().to_ascii_lowercase();
        let wanted = match src.category {
            AdblockCategory::Ad => matches!(cat.as_str(), "advertising" | "pornvertising"),
            AdblockCategory::Privacy => {
                matches!(cat.as_str(), "site_analytics" | "analytics" | "telemetry")
            }
            AdblockCategory::AdMixed => matches!(
                cat.as_str(),
                "advertising" | "pornvertising" | "site_analytics" | "analytics" | "telemetry"
            ),
            AdblockCategory::Both => false,
        };
        if !wanted {
            continue;
        }
        for f in &pat.filters {
            if let Some(dom) = extract_whole_domain_abp_filter(f)
                && !is_shared_cloud_bucket_host(&dom)
                && !is_consumer_first_party_portal(&dom)
            {
                insert_exact_for_role(dom, src, out);
            }
        }
    }

    Ok(())
}
