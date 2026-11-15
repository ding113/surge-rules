use crate::routing::config::{GeositeTagFilter, RoutingRuleKind};
use crate::routing::model::ParsedRoutingSource;

pub fn parse_geosite(text: &str, filter: GeositeTagFilter, out: &mut ParsedRoutingSource) {
    for raw_line in text.lines() {
        let without_bom = raw_line.trim_start_matches('\u{feff}');
        let code = match without_bom.find('#') {
            Some(idx) => &without_bom[..idx],
            None => without_bom,
        }
        .trim();
        if code.is_empty() {
            continue;
        }

        let mut tokens = code.split_whitespace();
        let Some(entry) = tokens.next() else {
            continue;
        };

        let mut has_ads = false;
        let mut has_cn = false;
        for tag in tokens {
            let lower = tag.to_ascii_lowercase();
            if lower == "@ads" {
                has_ads = true;
            } else if lower == "@cn" {
                has_cn = true;
            }
        }

        if has_ads {
            continue;
        }
        match filter {
            GeositeTagFilter::AllNonAds => {}
            GeositeTagFilter::OnlyCn => {
                if !has_cn {
                    continue;
                }
            }
            GeositeTagFilter::ExcludeCn => {
                if has_cn {
                    continue;
                }
            }
        }

        if let Some(dom) = entry.strip_prefix("full:") {
            out.push_normalized(RoutingRuleKind::Domain, dom, false);
        } else if let Some(dom) = entry.strip_prefix("domain:") {
            out.push_normalized(RoutingRuleKind::DomainSuffix, dom, false);
        } else if let Some(kw) = entry.strip_prefix("keyword:") {
            out.push_normalized(RoutingRuleKind::DomainKeyword, kw, false);
        } else if entry.starts_with("regexp:") || entry.starts_with("include:") {
            continue;
        } else if !entry.contains(':') {
            // In v2fly domain-list-community, bare entries denote domain-suffix semantics.
            out.push_normalized(RoutingRuleKind::DomainSuffix, entry, false);
        }
    }
}
