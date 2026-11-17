use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::adblock::compiler::{overlaps_reserved_v4, overlaps_reserved_v6};
use crate::adblock::parsers::ruleset::{
    is_comment_or_empty, parse_canonical_cidr, strip_inline_comment,
};
use crate::adblock::parsers::surge_module::split_top_level_commas;
use crate::routing::config::RoutingRuleKind;
use crate::routing::model::ParsedRoutingSource;

/// Minimum IPv4 prefix length for game/voice CIDR extraction (rejects `/0`–`/21` cloud supernets).
pub const MIN_FILTERED_GAME_IPV4_PREFIX: u8 = 22;
/// Minimum IPv6 prefix length for game/voice CIDR extraction (rejects `/0`–`/39` cloud supernets).
pub const MIN_FILTERED_GAME_IPV6_PREFIX: u8 = 40;

pub fn parse_sstap_filtered_cidr(text: &str, out: &mut ParsedRoutingSource) {
    for raw_line in text.lines() {
        let line = strip_inline_comment(raw_line.trim_start_matches('\u{feff}')).trim();
        // Skips `#...` SSTap metadata header line 1, comments, empty lines, and section markers.
        if is_comment_or_empty(line) || line.starts_with('[') {
            continue;
        }

        // Support `ipset` format (`add <setname> <ip_or_cidr> [-exist ...]`), classical `IP-CIDR,...`,
        // and plain CIDR / SSTap `.rules` lines.
        let owned_comma_candidate: Option<String>;
        let candidate = if let Some(rest) = line.strip_prefix("add ") {
            let mut parts = rest.split_whitespace();
            let _set_name = parts.next();
            parts.next().unwrap_or("")
        } else if line.contains(',') {
            let parts = split_top_level_commas(line);
            owned_comma_candidate = if parts.len() >= 2
                && matches!(
                    RoutingRuleKind::parse_token(&parts[0]),
                    Some(RoutingRuleKind::IpCidr | RoutingRuleKind::IpCidr6)
                ) {
                Some(parts[1].trim().to_string())
            } else {
                parts.first().map(|s| s.trim().to_string())
            };
            owned_comma_candidate.as_deref().unwrap_or("")
        } else {
            line.split_whitespace().next().unwrap_or("")
        };

        let Some(net) = parse_canonical_cidr(candidate) else {
            continue;
        };

        match net {
            IpNet::V4(v4) => {
                if v4.prefix_len() < MIN_FILTERED_GAME_IPV4_PREFIX || is_strict_bogon_v4(v4) {
                    continue;
                }
                out.push_normalized(RoutingRuleKind::IpCidr, &v4.to_string(), false);
            }
            IpNet::V6(v6) => {
                if v6.prefix_len() < MIN_FILTERED_GAME_IPV6_PREFIX || is_strict_bogon_v6(v6) {
                    continue;
                }
                out.push_normalized(RoutingRuleKind::IpCidr6, &v6.to_string(), false);
            }
        }
    }
}

fn is_strict_bogon_v4(net: Ipv4Net) -> bool {
    if overlaps_reserved_v4(net) {
        return true;
    }
    // Additional special-purpose IPv4 ranges (RFC 3068 6to4 relay anycast `192.88.99.0/24`).
    const EXTRA_V4: &[(u32, u8)] = &[(0xC058_6300, 24)];
    let s1 = u32::from(net.network());
    let e1 = u32::from(net.broadcast());
    EXTRA_V4.iter().any(|&(base, pfx)| {
        let mask = u32::MAX << (32 - pfx);
        let s2 = base & mask;
        let e2 = s2 | !mask;
        s1 <= e2 && s2 <= e1
    })
}

fn is_strict_bogon_v6(net: Ipv6Net) -> bool {
    if overlaps_reserved_v6(net) {
        return true;
    }
    // Additional non-global / translation / benchmarking IPv6 ranges:
    // - `64:ff9b::/96` & `64:ff9b:1::/48` (NAT64)
    // - `100::/64` (RFC 6666 Discard-Only)
    // - `2001::/32` (Teredo)
    // - `2001:2::/48` (RFC 5180 Benchmarking)
    // - `2002::/16` (6to4)
    const EXTRA_V6: &[(u128, u8)] = &[
        (0x0064_ff9b_0000_0000_0000_0000_0000_0000, 96),
        (0x0064_ff9b_0001_0000_0000_0000_0000_0000, 48),
        (0x0100_0000_0000_0000_0000_0000_0000_0000, 64),
        (0x2001_0000_0000_0000_0000_0000_0000_0000, 32),
        (0x2001_0002_0000_0000_0000_0000_0000_0000, 48),
        (0x2002_0000_0000_0000_0000_0000_0000_0000, 16),
    ];
    let s1 = u128::from(net.network());
    let e1 = u128::from(net.broadcast());
    EXTRA_V6.iter().any(|&(base, pfx)| {
        let mask = u128::MAX << (128 - pfx);
        let s2 = base & mask;
        let e2 = s2 | !mask;
        s1 <= e2 && s2 <= e1
    })
}
