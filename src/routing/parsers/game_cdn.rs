use crate::adblock::parsers::ruleset::{is_comment_or_empty, strip_inline_comment};
use crate::adblock::parsers::surge_module::split_top_level_commas;
use crate::adblock::regex_util::is_valid_domain;
use crate::routing::config::RoutingRuleKind;
use crate::routing::model::ParsedRoutingSource;

/// Multi-tenant CDN/cloud apexes and `SHARED_INFRA_ROOTS` on which `cn_safe_game_cdn` must NEVER
/// emit `DOMAIN-SUFFIX` or wildcard rules. Concrete 3+-label tenant depot hostnames beneath these
/// parents (after passing the GFW/storefront deny-filter) are emitted strictly as exact `DOMAIN`.
const SHARED_CDN_AND_INFRA_PARENTS: &[&str] = &[
    // Explicit multi-tenant CDN / cloud / GSLB parents
    "akamaized.net",
    "akamaihd.net",
    "akamai.net",
    "akadns.net",
    "edgesuite.net",
    "edgekey.net",
    "srip.net",
    "llnwd.net",
    "vo.llnwd.net",
    "loris-e.llnwd.net",
    "hwcdn.net",
    "footprint.net",
    "secure2.footprint.net",
    "cdn77.org",
    "cdn77.net",
    "fastly.net",
    "fastly-edge.com",
    "cloudfront.net",
    "cloudflare.net",
    "cloudflare.com",
    "amazonaws.com",
    "googleapis.com",
    "gvt1.com",
    "gvt2.com",
    "azureedge.net",
    "azurefd.net",
    "msecnd.net",
    "trafficmanager.net",
    "chinacache.net",
    "cdngslb.com",
    "myqcloud.com",
    "file.myqcloud.com",
    "bscstorage.net",
    "baishancdnx.cn",
    "eccdnx.com",
    "clngaa.com",
    "ksyna.com",
    "eo-edgefunctions7.com",
    "qtlglb.com",
    "cloudn.co.kr",
    "gcdn.cloudn.co.kr",
    "gcdn.co",
    "nsatc.net",
    // Full `SHARED_INFRA_ROOTS` inventory
    "s3.amazonaws.com",
    "cloudflareinsights.com",
    "cloudflarestorage.com",
    "r2.cloudflarestorage.com",
    "azure.com",
    "webpubsub.azure.com",
    "windows.net",
    "core.windows.net",
    "blob.core.windows.net",
    "google.com",
    "gstatic.com",
    "googleusercontent.com",
    "appspot.com",
    "run.app",
    "cloudfunctions.net",
    "firebaseio.com",
    "firebaseapp.com",
    "web.app",
    "microsoft.com",
    "live.com",
    "office.com",
    "office365.com",
    "github.com",
    "githubusercontent.com",
    "githubassets.com",
    "apple.com",
    "icloud.com",
    "mzstatic.com",
    "aaplimg.com",
    "vercel.app",
    "netlify.app",
    "pages.dev",
    "workers.dev",
    "fly.dev",
    "onrender.com",
    "railway.app",
    "supabase.co",
    "sentry.io",
    "ingest.sentry.io",
    "ingest.us.sentry.io",
    "datadoghq.com",
    "browser-intake-datadoghq.com",
    "auth0.com",
    "us.auth0.com",
    "workos.com",
    "clerk.com",
    "clerk.accounts.dev",
    "intercom.io",
    "intercomcdn.com",
    "zendesk.com",
    "statuspage.io",
    "statsig.com",
    "statsigapi.net",
    "growthbook.io",
    "launchdarkly.com",
    "segment.io",
    "segment.com",
    "amplitude.com",
    "posthog.com",
    "mixpanel.com",
    "braze.com",
    "onesignal.com",
    "sendgrid.net",
    "mailgun.org",
    "algolia.net",
    "algolianet.com",
    "imgix.net",
    "cloudinary.com",
    "jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "npmjs.org",
    "pypi.org",
    "crates.io",
    "brew.sh",
    "docker.io",
    "docker.com",
    "amazon.com",
    "aws.amazon.com",
];

/// Substrings indicating overseas-blocked/throttled CDNs, cloud platforms, or storefront/social APIs.
const DENIED_SUBSTRINGS: &[&str] = &[
    "fastly",
    "cloudfront",
    "cloudflare",
    "amazonaws",
    "googleapis",
    "appspot",
    "ggpht",
    "youtube",
    "eshop",
    "steamcommunity",
    "discord",
    "twitch",
];

/// Domain suffixes for Western ISP caches, console storefronts, and overseas login/storefront APIs.
const DENIED_DOMAIN_SUFFIXES: &[&str] = &[
    "gvt1.com",
    "gvt2.com",
    "comcast.net",
    "nintendo.net",
    "nintendo.com",
    "nintendowifi.net",
    "wii.com",
    "steampowered.com",
    "steamgames.com",
    "xboxlive.com",
    "xbox.com",
    "playstation.net",
    "playstation.com",
    "sonyentertainmentnetwork.com",
    "riotgames.com",
    "epicgames.com",
    "epicgamescdn.com",
    "gog.com",
    "lancache.net",
    "uklans.net",
];

/// Dedicated 2-label pure download-depot domains allowed as `DOMAIN-SUFFIX` when upstream requests a suffix.
const DEDICATED_DEPOT_APEXES: &[&str] = &[
    "steamcontent.com",
    "steamserver.net",
    "riotcdn.net",
    "steamchina.com",
];

pub fn parse_cn_safe_game_cdn(text: &str, out: &mut ParsedRoutingSource) {
    for raw_line in text.lines() {
        let stripped = strip_inline_comment(raw_line.trim_start_matches('\u{feff}')).trim();
        if is_comment_or_empty(stripped)
            || stripped.starts_with('!')
            || stripped.starts_with("@@")
            || stripped.starts_with('[')
            || stripped.eq_ignore_ascii_case("payload:")
            || stripped.starts_with("behavior:")
        {
            continue;
        }

        let item = stripped.strip_prefix("- ").unwrap_or(stripped).trim();
        let unquoted = strip_quotes(item).trim();
        if unquoted.is_empty() {
            continue;
        }

        let Some((wants_suffix, raw_host)) = extract_game_cdn_candidate(unquoted) else {
            continue;
        };

        let dom = raw_host
            .trim()
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_ascii_lowercase();

        if dom.is_empty()
            || dom.contains(['*', '?', '/', ':', '$', '|'])
            || dom.chars().any(|c| c.is_whitespace() || c.is_control())
            || !is_valid_domain(&dom)
        {
            continue;
        }

        if is_denied_game_domain(&dom) {
            continue;
        }

        let labels = dom.split('.').count();

        if matches_any_domain_suffix(&dom, SHARED_CDN_AND_INFRA_PARENTS) {
            // Multi-Tenant CDN Apex Guard:
            // 1. Drop exact apexes and ANY wildcard/suffix on a shared CDN/cloud parent.
            // 2. Concrete 3+-label tenant depot hostnames emit strictly as exact `DOMAIN`.
            if SHARED_CDN_AND_INFRA_PARENTS.contains(&dom.as_str()) || wants_suffix || labels < 3 {
                continue;
            }
            out.push_normalized(RoutingRuleKind::Domain, &dom, false);
        } else if wants_suffix {
            // Only allow `DOMAIN-SUFFIX` on 3+-label dedicated CDN subdomains (e.g. `cdn.blizzard.com`,
            // `dyn.riotcdn.net`, `cdn.ubi.com`) or verified pure-depot 2-label domains (`steamcontent.com`).
            if labels >= 3 || DEDICATED_DEPOT_APEXES.contains(&dom.as_str()) {
                out.push_normalized(RoutingRuleKind::DomainSuffix, &dom, false);
            }
        } else if labels >= 3 {
            out.push_normalized(RoutingRuleKind::Domain, &dom, false);
        }
    }
}

fn extract_game_cdn_candidate(line: &str) -> Option<(bool, String)> {
    if line.contains(',') {
        let parts = split_top_level_commas(line);
        if parts.len() < 2 {
            return None;
        }
        let kind = RoutingRuleKind::parse_token(&parts[0])?;
        let val = strip_quotes(parts[1].trim()).trim();
        return match kind {
            RoutingRuleKind::Domain => Some((false, val.to_string())),
            RoutingRuleKind::DomainSuffix => Some((true, val.trim_start_matches("+.").to_string())),
            RoutingRuleKind::DomainWildcard => {
                let rest = val.strip_prefix("*.")?;
                (!rest.contains(['*', '?'])).then(|| (true, rest.to_string()))
            }
            _ => None,
        };
    }

    if let Some(rest) = line.strip_prefix("full:") {
        Some((false, rest.trim().to_string()))
    } else if let Some(rest) = line.strip_prefix("domain:") {
        Some((true, rest.trim().to_string()))
    } else if let Some(rest) = line.strip_prefix("||") {
        Some((
            true,
            rest.strip_suffix('^').unwrap_or(rest).trim().to_string(),
        ))
    } else if let Some(rest) = line.strip_prefix("+.") {
        Some((true, rest.trim().to_string()))
    } else if let Some(rest) = line.strip_prefix("*.") {
        (!rest.contains(['*', '?'])).then(|| (true, rest.trim().to_string()))
    } else if let Some(rest) = line.strip_prefix('.') {
        Some((true, rest.trim().to_string()))
    } else {
        Some((false, line.to_string()))
    }
}

fn is_denied_game_domain(dom: &str) -> bool {
    if DENIED_SUBSTRINGS.iter().any(|sub| dom.contains(sub)) {
        return true;
    }
    if dom.ends_with("gvt1.com") || dom.ends_with("gvt2.com") {
        return true;
    }
    matches_any_domain_suffix(dom, DENIED_DOMAIN_SUFFIXES)
}

fn matches_any_domain_suffix(dom: &str, suffixes: &[&str]) -> bool {
    suffixes.iter().any(|&sfx| {
        dom == sfx
            || (dom.len() > sfx.len()
                && dom.ends_with(sfx)
                && dom.as_bytes()[dom.len() - sfx.len() - 1] == b'.')
    })
}

fn strip_quotes(s: &str) -> &str {
    let trimmed = s.trim();
    if trimmed.len() >= 2
        && ((trimmed.starts_with('\'') && trimmed.ends_with('\''))
            || (trimmed.starts_with('"') && trimmed.ends_with('"')))
    {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    }
}
