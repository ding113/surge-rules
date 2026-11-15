use std::io::Cursor;
use std::net::IpAddr;

use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::Deserialize;

use crate::config::{MetadataRegistry, SourceConfig, normalize_isp_name};
use crate::model::{AsnMetaObs, IsoCode, ObsPayload, ParsedSource, TraitFlags};
use crate::parsers::bgp_rir::is_public_asn;
use crate::parsers::mmdb::parse_asn_str;

pub fn parse_cidr_list(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    let mut out = ParsedSource::new(&src.id);
    let mut p = ObsPayload {
        traits: src.base_traits(),
        ..ObsPayload::default()
    };

    if let Some(ref fc) = src.fixed_country {
        p.country = IsoCode::parse_raw(fc).and_then(|c| metadata.validate_iso(c));
    }
    if let Some(ref f_isp) = src.fixed_isp
        && let Some(norm) = normalize_isp_name(f_isp)
    {
        p.isp = out.intern_str(&norm);
    }

    let Some(pid) = out.intern_payload(p) else {
        return Ok(out);
    };

    let text = String::from_utf8_lossy(bytes);
    for line in text.lines() {
        if let Some(net) = extract_cidr_or_ip_from_line(line) {
            out.push_ipnet(net, pid);
        }
    }

    out.finalize();
    Ok(out)
}

fn extract_cidr_or_ip_from_line(line: &str) -> Option<IpNet> {
    let mut s = line.trim();
    if s.is_empty() || s.starts_with('#') || s.starts_with(';') || s.starts_with("//") {
        return None;
    }
    if let Some((before, _)) = s.split_once('#') {
        s = before.trim();
    }
    if let Some((before, _)) = s.split_once(';') {
        s = before.trim();
    }
    if s.is_empty() {
        return None;
    }

    // Handle Surge / Clash rule lines like `IP-CIDR,1.0.1.0/24,no-resolve` or `IP-CIDR6,2400:3200::/32`
    let candidate = if let Some(rest) = s
        .strip_prefix("IP-CIDR6,")
        .or_else(|| s.strip_prefix("IP-CIDR,"))
        .or_else(|| s.strip_prefix("ip-cidr6,"))
        .or_else(|| s.strip_prefix("ip-cidr,"))
    {
        rest.split(',').next().unwrap_or("").trim()
    } else {
        s.split([',', ' ', '\t']).next().unwrap_or("").trim()
    };

    if let Ok(net) = candidate.parse::<IpNet>() {
        return Some(net.trunc());
    }
    if let Ok(addr) = candidate.parse::<IpAddr>() {
        return Some(IpNet::from(addr));
    }
    None
}

#[derive(Deserialize)]
struct OnionooDoc {
    #[serde(default)]
    relays: Vec<OnionooRelay>,
}

#[derive(Deserialize)]
struct OnionooRelay {
    #[serde(default)]
    a: Vec<String>,
    #[serde(default)]
    or_addresses: Vec<String>,
    #[serde(default)]
    exit_addresses: Vec<String>,
    #[serde(default = "default_true")]
    r: bool,
}

const fn default_true() -> bool {
    true
}

pub fn parse_onionoo_json(src: &SourceConfig, bytes: &[u8]) -> Result<ParsedSource> {
    let doc: OnionooDoc = serde_json::from_slice(bytes)
        .with_context(|| format!("invalid Onionoo JSON in '{}'", src.id))?;
    let mut out = ParsedSource::new(&src.id);
    let Some(pid) = out.intern_payload(ObsPayload {
        traits: src.base_traits().union(TraitFlags(TraitFlags::IS_TOR_EXIT)),
        ..ObsPayload::default()
    }) else {
        return Ok(out);
    };

    for relay in doc.relays {
        if !relay.r {
            continue;
        }
        for raw_addr in relay
            .a
            .iter()
            .chain(relay.or_addresses.iter())
            .chain(relay.exit_addresses.iter())
        {
            if let Some(ip) = parse_host_or_socket_ip(raw_addr) {
                out.push_ip_addr(ip, pid);
            }
        }
    }

    out.finalize();
    Ok(out)
}

fn parse_host_or_socket_ip(raw: &str) -> Option<IpAddr> {
    let s = raw.trim();
    if let Some(rest) = s.strip_prefix('[') {
        let inside = rest.split(']').next()?;
        return inside.parse::<IpAddr>().ok();
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip);
    }
    // Strip `:port` on IPv4 `a.b.c.d:port`
    if let Some((host, _port)) = s.rsplit_once(':')
        && host.contains('.')
    {
        return host.parse::<IpAddr>().ok();
    }
    None
}

pub fn parse_openproxydb_csv(src: &SourceConfig, bytes: &[u8]) -> Result<ParsedSource> {
    let mut out = ParsedSource::new(&src.id);
    let base_traits = src.base_traits();

    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(Cursor::new(bytes));

    let headers = rdr.headers().ok().cloned();
    let header_pos = |names: &[&str]| -> Option<usize> {
        headers.as_ref().and_then(|h| {
            h.iter()
                .position(|c| names.contains(&c.trim().to_ascii_lowercase().as_str()))
        })
    };
    let is_true = |rec: &csv::StringRecord, col: Option<usize>| -> bool {
        col.and_then(|idx| rec.get(idx))
            .is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1"))
    };

    let net_col =
        header_pos(&["cidr", "network", "ip_block", "block", "prefix", "ip"]).unwrap_or(0);
    let anonblock_col = header_pos(&["anonblock"]);
    let proxy_col = header_pos(&["proxy"]);
    let vpn_col = header_pos(&["vpn"]);
    let cdn_col = header_pos(&["cdn"]);
    let public_wifi_col = header_pos(&["public-wifi", "public_wifi"]);
    let rangeblock_col = header_pos(&["rangeblock"]);
    let school_block_col = header_pos(&["school-block", "school_block"]);
    let tor_col = header_pos(&["tor"]);
    let webhost_col = header_pos(&["webhost"]);
    let type_col = header_pos(&["type", "proxy_type", "category", "types"]);

    let has_bool_schema = proxy_col.is_some()
        || vpn_col.is_some()
        || tor_col.is_some()
        || webhost_col.is_some()
        || cdn_col.is_some();

    for rec_res in rdr.records() {
        let Ok(rec) = rec_res else {
            continue;
        };
        let Some(net_str) = rec.get(net_col) else {
            continue;
        };
        let Some(net) = extract_cidr_or_ip_from_line(net_str) else {
            continue;
        };

        let mut traits = if has_bool_schema {
            let anonblock = is_true(&rec, anonblock_col);
            let proxy = is_true(&rec, proxy_col);
            let vpn = is_true(&rec, vpn_col);
            let cdn = is_true(&rec, cdn_col);
            let public_wifi = is_true(&rec, public_wifi_col);
            let rangeblock = is_true(&rec, rangeblock_col);
            let school_block = is_true(&rec, school_block_col);
            let tor = is_true(&rec, tor_col);
            let webhost = is_true(&rec, webhost_col);

            if school_block || public_wifi || rangeblock {
                continue;
            }

            let mut row_traits = TraitFlags::EMPTY;
            if cdn {
                row_traits.insert(TraitFlags::IS_CDN);
            } else {
                let is_single_host = match net {
                    IpNet::V4(n) => n.prefix_len() == 32,
                    IpNet::V6(n) => n.prefix_len() == 128,
                };
                let is_narrow = match net {
                    IpNet::V4(n) => n.prefix_len() >= 24,
                    IpNet::V6(n) => n.prefix_len() >= 64,
                };
                if webhost {
                    row_traits.insert(TraitFlags::IS_HOSTING);
                }
                if tor && is_single_host {
                    row_traits.insert(TraitFlags::IS_TOR_EXIT);
                    row_traits.insert(TraitFlags::IS_ANONYMOUS_PROXY);
                }
                if vpn && !webhost && is_narrow {
                    row_traits.insert(TraitFlags::IS_VPN);
                    row_traits.insert(TraitFlags::IS_ANONYMOUS_PROXY);
                }
                if proxy && !webhost && !anonblock && is_single_host {
                    row_traits.insert(TraitFlags::IS_ANONYMOUS_PROXY);
                }
            }
            if row_traits == TraitFlags::EMPTY {
                continue;
            }
            row_traits
        } else {
            let mut row_traits = base_traits;
            if let Some(tc) = type_col
                && let Some(tval) = rec.get(tc)
            {
                let upper = tval.to_ascii_uppercase();
                if upper.contains("VPN") {
                    row_traits.insert(TraitFlags::IS_VPN);
                }
                if upper.contains("TOR") {
                    row_traits.insert(TraitFlags::IS_TOR_EXIT);
                }
                if upper.contains("PROXY") {
                    row_traits.insert(TraitFlags::IS_ANONYMOUS_PROXY);
                }
            }
            row_traits
        };

        let _ = &mut traits;
        if let Some(pid) = out.intern_payload(ObsPayload {
            traits,
            ..ObsPayload::default()
        }) {
            out.push_ipnet(net, pid);
        }
    }

    out.finalize();
    Ok(out)
}

#[derive(Deserialize)]
struct SatPrefixLine {
    prefix: String,
    #[serde(default)]
    origin_asn: Option<u32>,
    #[serde(default)]
    origin_as_name: Option<String>,
}

pub fn parse_sat_geoip_jsonl(src: &SourceConfig, bytes: &[u8]) -> Result<ParsedSource> {
    let mut out = ParsedSource::new(&src.id);
    let base_traits = src.base_traits();

    let text = String::from_utf8_lossy(bytes);
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || !t.starts_with('{') {
            continue;
        }
        let Ok(item) = serde_json::from_str::<SatPrefixLine>(t) else {
            continue;
        };
        let Ok(net) = item.prefix.trim().parse::<IpNet>() else {
            continue;
        };
        let asn = item.origin_asn.filter(|&a| is_public_asn(a)).unwrap_or(0);
        let as_org = item
            .origin_as_name
            .as_deref()
            .map_or(crate::model::StrId::EMPTY, |s| out.intern_str(s));
        if let Some(pid) = out.intern_payload(ObsPayload {
            asn,
            as_org,
            traits: base_traits,
            ..ObsPayload::default()
        }) {
            out.push_ipnet(net, pid);
        }
    }

    out.finalize();
    Ok(out)
}

pub fn parse_sat_asns_csv(src: &SourceConfig, bytes: &[u8]) -> Result<ParsedSource> {
    let mut out = ParsedSource::new(&src.id);
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(Cursor::new(bytes));

    for rec_res in rdr.records() {
        let Ok(rec) = rec_res else {
            continue;
        };
        if rec.len() < 3 {
            continue;
        }
        let asn = parse_asn_str(&rec[1]);
        if !is_public_asn(asn) {
            continue;
        }
        let name = rec[2].trim();
        out.asn_meta.push(AsnMetaObs {
            asn,
            organization: name.to_string(),
            domain: None,
            country: None,
            traits: TraitFlags(TraitFlags::IS_SATELLITE),
            weight: 70,
        });
    }

    Ok(out)
}

#[derive(Deserialize)]
struct SpamhausDropLine {
    #[serde(default)]
    cidr: Option<String>,
}

pub fn parse_spamhaus_drop(src: &SourceConfig, bytes: &[u8]) -> Result<ParsedSource> {
    let mut out = ParsedSource::new(&src.id);
    let Some(pid) = out.intern_payload(ObsPayload {
        traits: src.base_traits().union(TraitFlags(TraitFlags::IS_MALWARE)),
        ..ObsPayload::default()
    }) else {
        return Ok(out);
    };

    let text = String::from_utf8_lossy(bytes);
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with(';') || t.starts_with('#') {
            continue;
        }
        if t.starts_with('{') {
            if let Ok(item) = serde_json::from_str::<SpamhausDropLine>(t)
                && let Some(c) = item.cidr
                && let Ok(net) = c.trim().parse::<IpNet>()
            {
                out.push_ipnet(net, pid);
            }
        } else if let Some(net) = extract_cidr_or_ip_from_line(t) {
            out.push_ipnet(net, pid);
        }
    }

    out.finalize();
    Ok(out)
}
