use crate::adblock::parsers::ruleset::{is_comment_or_empty, strip_inline_comment};
use crate::routing::config::RoutingRuleKind;
use crate::routing::model::ParsedRoutingSource;

pub fn parse_dnsmasq_china(text: &str, out: &mut ParsedRoutingSource) {
    for raw_line in text.lines() {
        let line = strip_inline_comment(raw_line.trim_start_matches('\u{feff}')).trim();
        if is_comment_or_empty(line) {
            continue;
        }
        let body = if let Some(rest) = line.strip_prefix("server=/") {
            rest
        } else if let Some(rest) = line.strip_prefix("local=/") {
            rest
        } else if let Some(rest) = line.strip_prefix("address=/") {
            rest
        } else {
            continue;
        };
        let Some((domain, _resolver)) = body.split_once('/') else {
            continue;
        };
        out.push_normalized(RoutingRuleKind::DomainSuffix, domain, false);
    }
}
