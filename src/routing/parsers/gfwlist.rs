use anyhow::{Result, bail};

use crate::adblock::parsers::ruleset::parse_canonical_cidr;
use crate::routing::config::RoutingRuleKind;
use crate::routing::model::{ParsedRoutingSource, is_valid_domain_or_tld};

pub fn parse_gfwlist_base64(text: &str, out: &mut ParsedRoutingSource) -> Result<()> {
    let trimmed = text.trim_start_matches('\u{feff}').trim();
    let decoded = if trimmed.starts_with("[AutoProxy") {
        trimmed.to_string()
    } else {
        let bytes = decode_base64_ignore_ws(trimmed)?;
        String::from_utf8_lossy(&bytes).into_owned()
    };

    for raw_line in decoded.lines() {
        let line = raw_line.trim();
        if line.is_empty()
            || line.starts_with('!')
            || line.starts_with('[')
            || line.starts_with('#')
            || line.starts_with("@@")
        {
            // Strictly skip AutoProxy `@@` whitelist lines so China domains do not leak into Proxy.list.
            continue;
        }
        if line.starts_with('/') && line.ends_with('/') {
            continue;
        }

        if let Some(rest) = line.strip_prefix("||") {
            extract_autoproxy_host(rest, true, out);
        } else if let Some(rest) = line.strip_prefix('|') {
            let after_scheme = rest
                .strip_prefix("https://")
                .or_else(|| rest.strip_prefix("http://"))
                .unwrap_or(rest);
            extract_autoproxy_host(after_scheme, true, out);
        } else if let Some(rest) = line.strip_prefix('.') {
            extract_autoproxy_host(rest, true, out);
        } else {
            let without_scheme = line
                .strip_prefix("https://")
                .or_else(|| line.strip_prefix("http://"))
                .unwrap_or(line);
            if without_scheme.starts_with("*.") {
                let candidate = without_scheme.split(['/', '?', '^']).next().unwrap_or("");
                out.push_normalized(RoutingRuleKind::DomainWildcard, candidate, false);
            } else {
                extract_autoproxy_host(without_scheme, true, out);
            }
        }
    }

    Ok(())
}

fn extract_autoproxy_host(rest: &str, as_suffix: bool, out: &mut ParsedRoutingSource) {
    let host_and_port = rest.split(['/', '?', '^', '|']).next().unwrap_or("").trim();
    if host_and_port.is_empty() || host_and_port.contains('%') || host_and_port.contains(' ') {
        return;
    }
    let host = if host_and_port.starts_with('[') {
        host_and_port
            .trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or("")
    } else if let Some((h, port)) = host_and_port.rsplit_once(':')
        && port.chars().all(|c| c.is_ascii_digit())
    {
        h
    } else {
        host_and_port
    };

    if let Some(net) = parse_canonical_cidr(host) {
        match net {
            ipnet::IpNet::V4(v4) => {
                out.push_normalized(RoutingRuleKind::IpCidr, &v4.to_string(), false);
            }
            ipnet::IpNet::V6(v6) => {
                out.push_normalized(RoutingRuleKind::IpCidr6, &v6.to_string(), false);
            }
        }
        return;
    }

    if host.contains('*') || host.contains('?') {
        out.push_normalized(RoutingRuleKind::DomainWildcard, host, false);
        return;
    }

    let cleaned = host.trim_start_matches('.').trim_end_matches('.');
    if is_valid_domain_or_tld(cleaned) {
        let kind = if as_suffix {
            RoutingRuleKind::DomainSuffix
        } else {
            RoutingRuleKind::Domain
        };
        out.push_normalized(kind, cleaned, false);
    }
}

/// Decodes RFC 4648 standard Base64 while ignoring ASCII whitespace.
pub fn decode_base64_ignore_ws(input: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = [0u8; 4];
    let mut buf_len = 0usize;
    let mut pad_count = 0usize;
    let mut seen_padding = false;

    for byte in input.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if seen_padding && byte != b'=' {
            bail!("invalid trailing Base64 data after padding");
        }
        if byte == b'=' {
            seen_padding = true;
            buf[buf_len] = 0;
            buf_len += 1;
            pad_count += 1;
        } else {
            let val = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => bail!("invalid Base64 byte: 0x{:02x}", byte),
            };
            buf[buf_len] = val;
            buf_len += 1;
        }

        if buf_len == 4 {
            out.push((buf[0] << 2) | (buf[1] >> 4));
            if pad_count < 2 {
                out.push((buf[1] << 4) | (buf[2] >> 2));
            }
            if pad_count < 1 {
                out.push((buf[2] << 6) | buf[3]);
            }
            if pad_count > 2 {
                bail!("invalid Base64 padding length");
            }
            buf_len = 0;
            pad_count = 0;
        }
    }

    if buf_len != 0 {
        bail!("truncated Base64 input");
    }

    Ok(out)
}
