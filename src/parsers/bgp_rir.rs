use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use ipnet::{IpNet, Ipv6Net};
use rustc_hash::FxHashMap;
use serde::Deserialize;

use crate::config::{MetadataRegistry, SourceConfig};
use crate::model::{
    AsnMetaObs, IsoCode, ObsPayload, ParsedSource, TraitFlags, effective_prefix_v4,
    effective_prefix_v6,
};
use crate::parsers::mmdb::parse_asn_str;

#[inline]
pub fn is_public_asn(asn: u32) -> bool {
    asn != 0
        && asn != 23456
        && !(64496..=65551).contains(&asn)
        && !(65552..=131071).contains(&asn)
        && !(4_200_000_000..=4_294_967_295).contains(&asn)
}

#[derive(Deserialize)]
struct BgpToolsJsonLine<'a> {
    #[serde(rename = "CIDR")]
    cidr: &'a str,
    #[serde(rename = "ASN")]
    asn: u32,
}

pub fn parse_bgptools_table(src: &SourceConfig, bytes: &[u8]) -> Result<ParsedSource> {
    let mut out = ParsedSource::new(&src.id);
    let base_traits = src.base_traits();
    let mut asn_cache: FxHashMap<u32, u32> = FxHashMap::default();

    let text = String::from_utf8_lossy(bytes);
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let (cidr_str, asn) = if t.starts_with('{') {
            let Ok(parsed) = serde_json::from_str::<BgpToolsJsonLine<'_>>(t) else {
                continue;
            };
            (parsed.cidr, parsed.asn)
        } else {
            let mut parts = t.split_whitespace();
            let Some(c) = parts.next() else {
                continue;
            };
            let Some(a_str) = parts.next() else {
                continue;
            };
            (c, parse_asn_str(a_str))
        };

        if !is_public_asn(asn) {
            continue;
        }
        let Ok(net) = cidr_str.parse::<IpNet>() else {
            continue;
        };
        let pid = *asn_cache.entry(asn).or_insert_with(|| {
            out.intern_payload(ObsPayload {
                asn,
                traits: base_traits,
                ..ObsPayload::default()
            })
            .unwrap()
        });
        out.push_ipnet(net, pid);
    }

    out.finalize();
    Ok(out)
}

pub fn parse_bgptools_asns_csv(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    let mut out = ParsedSource::new(&src.id);
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(Cursor::new(bytes));

    for rec_res in rdr.records() {
        let Ok(rec) = rec_res else {
            continue;
        };
        if rec.len() < 2 {
            continue;
        }
        let asn = parse_asn_str(&rec[0]);
        if !is_public_asn(asn) {
            continue;
        }
        let org = rec[1].trim();
        if org.is_empty() || org.eq_ignore_ascii_case("Unknown") {
            continue;
        }
        let cc = rec
            .get(3)
            .and_then(IsoCode::parse_raw)
            .and_then(|c| metadata.validate_iso(c));
        out.asn_meta.push(AsnMetaObs {
            asn,
            organization: org.to_string(),
            domain: None,
            country: cc,
            traits: TraitFlags::EMPTY,
            weight: 92,
        });
    }

    Ok(out)
}

pub fn parse_ipverse_as_csv(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
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
        let asn = parse_asn_str(&rec[0]);
        if !is_public_asn(asn) {
            continue;
        }
        let desc = rec[2].trim();
        if desc.is_empty() {
            continue;
        }
        let cc = rec
            .get(3)
            .and_then(IsoCode::parse_raw)
            .and_then(|c| metadata.validate_iso(c));
        out.asn_meta.push(AsnMetaObs {
            asn,
            organization: desc.to_string(),
            domain: None,
            country: cc,
            traits: TraitFlags::EMPTY,
            weight: 85,
        });
    }

    Ok(out)
}

pub fn parse_iptoasn_tsv(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    let mut out = ParsedSource::new(&src.id);
    let base_traits = src.base_traits();

    let text = String::from_utf8_lossy(bytes);
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let mut cols = t.splitn(5, '\t');
        let Some(s_ip_str) = cols.next() else {
            continue;
        };
        let Some(e_ip_str) = cols.next() else {
            continue;
        };
        let Some(asn_str) = cols.next() else {
            continue;
        };
        let cc_str = cols.next().unwrap_or("");
        let desc_str = cols.next().unwrap_or("").trim();

        let asn = parse_asn_str(asn_str);
        if !is_public_asn(asn) {
            continue;
        }
        let iso = IsoCode::parse_raw(cc_str).and_then(|c| metadata.validate_iso(c));
        let clean_org = clean_iptoasn_description(desc_str);
        let as_org = if clean_org.is_empty() {
            crate::model::StrId::EMPTY
        } else {
            out.intern_str(clean_org)
        };

        let Some(pid) = out.intern_payload(ObsPayload {
            country: iso,
            asn,
            as_org,
            traits: base_traits,
            ..ObsPayload::default()
        }) else {
            continue;
        };

        match (s_ip_str.parse::<IpAddr>(), e_ip_str.parse::<IpAddr>()) {
            (Ok(IpAddr::V4(s4)), Ok(IpAddr::V4(e4))) => {
                let s = u32::from(s4);
                let e = u32::from(e4);
                out.push_v4(s, e, pid, effective_prefix_v4(s, e));
            }
            (Ok(IpAddr::V6(s6)), Ok(IpAddr::V6(e6))) => {
                let s = u128::from(s6);
                let e = u128::from(e6);
                out.push_v6(s, e, pid, effective_prefix_v6(s, e));
            }
            _ => {}
        }
    }

    out.finalize();
    Ok(out)
}

fn clean_iptoasn_description(desc: &str) -> &str {
    let s = desc.trim();
    if matches!(s, "" | "Not routed" | "None" | "Unknown") {
        return "";
    }
    if let Some((lhs, rhs)) = s.split_once(" - ")
        && !rhs.trim().is_empty()
        && lhs
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-')
    {
        return rhs.trim();
    }
    s
}

pub fn parse_ipscope_csv(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    let mut out = ParsedSource::new(&src.id);
    let base_traits = src.base_traits();

    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(Cursor::new(bytes));

    for rec_res in rdr.records() {
        let Ok(rec) = rec_res else {
            continue;
        };
        if rec.len() < 7 {
            continue;
        }
        let Ok(net) = rec[0].trim().parse::<IpNet>() else {
            continue;
        };
        let asn = parse_asn_str(rec.get(4).unwrap_or(""));
        let asn = if is_public_asn(asn) { asn } else { 0 };
        let org_raw = rec.get(5).unwrap_or("").trim();
        let cc_raw = rec.get(6).unwrap_or("").trim();
        let loc_type = rec.get(7).unwrap_or("").trim();

        let iso = IsoCode::parse_raw(cc_raw).and_then(|c| metadata.validate_iso(c));
        let mut traits = base_traits;
        if loc_type.eq_ignore_ascii_case("anycast") {
            traits.insert(TraitFlags::IS_ANYCAST);
        }
        let as_org = if !org_raw.is_empty() {
            out.intern_str(org_raw)
        } else {
            crate::model::StrId::EMPTY
        };

        if let Some(pid) = out.intern_payload(ObsPayload {
            country: iso,
            asn,
            as_org,
            traits,
            ..ObsPayload::default()
        }) {
            out.push_ipnet(net, pid);
        }
    }

    out.finalize();
    Ok(out)
}

pub fn parse_rir_delegated(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    let mut out = ParsedSource::new(&src.id);
    let base_traits = src.base_traits();
    let mut iso_cache: FxHashMap<IsoCode, u32> = FxHashMap::default();

    let text = String::from_utf8_lossy(bytes);
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = t.split('|').collect();
        if cols.len() < 7 {
            continue;
        }
        let status = cols[6].trim();
        if status != "allocated" && status != "assigned" {
            continue;
        }
        let Some(iso) = IsoCode::parse_raw(cols[1]).and_then(|c| metadata.validate_iso(c)) else {
            continue;
        };
        let rec_type = cols[2].trim();
        if rec_type == "asn" {
            let Ok(start_asn) = cols[3].trim().parse::<u32>() else {
                continue;
            };
            let count = cols[4].trim().parse::<u32>().unwrap_or(1).min(256);
            for offset in 0..count {
                let asn = start_asn.saturating_add(offset);
                if is_public_asn(asn) {
                    out.asn_meta.push(AsnMetaObs {
                        asn,
                        organization: String::new(),
                        domain: None,
                        country: Some(iso),
                        traits: TraitFlags::EMPTY,
                        weight: 70,
                    });
                }
            }
            continue;
        }
        if rec_type != "ipv4" && rec_type != "ipv6" {
            continue;
        }

        let pid = *iso_cache.entry(iso).or_insert_with(|| {
            out.intern_payload(ObsPayload {
                country: Some(iso),
                registered_country: Some(iso),
                traits: base_traits,
                ..ObsPayload::default()
            })
            .unwrap()
        });

        if rec_type == "ipv4" {
            let Ok(start_addr) = cols[3].trim().parse::<Ipv4Addr>() else {
                continue;
            };
            let Ok(count) = cols[4].trim().parse::<u32>() else {
                continue;
            };
            if count == 0 {
                continue;
            }
            let start = u32::from(start_addr);
            let end = start.saturating_add(count - 1);
            out.push_v4(start, end, pid, effective_prefix_v4(start, end));
        } else {
            let Ok(start_addr) = cols[3].trim().parse::<Ipv6Addr>() else {
                continue;
            };
            let Ok(prefix_len) = cols[4].trim().parse::<u8>() else {
                continue;
            };
            if let Ok(net6) = Ipv6Net::new(start_addr, prefix_len) {
                out.push_ipnet(IpNet::V6(net6), pid);
            }
        }
    }

    out.finalize();
    Ok(out)
}
