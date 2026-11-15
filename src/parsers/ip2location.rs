use std::io::Cursor;

use anyhow::{Result, bail};
use rustc_hash::FxHashMap;

use crate::config::{MetadataRegistry, SourceConfig};
use crate::model::{
    COORD_UNSET, IsoCode, ObsPayload, ParsedSource, effective_prefix_v4, effective_prefix_v6,
    quantize_coord,
};

// 1-based column indices in IP2Location BIN by DB type (1..=26), matching official IP2Location specification.
const COUNTRY_POS: [u8; 27] = [
    0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
];
const REGION_POS: [u8; 27] = [
    0, 0, 0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
];
const CITY_POS: [u8; 27] = [
    0, 0, 0, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
];
const LATITUDE_POS: [u8; 27] = [
    0, 0, 0, 0, 0, 5, 5, 0, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
];
const LONGITUDE_POS: [u8; 27] = [
    0, 0, 0, 0, 0, 6, 6, 0, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
];
const ZIPCODE_POS: [u8; 27] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 7, 7, 7, 0, 7, 7, 7, 0, 7, 0, 7, 7, 7, 0, 7, 7, 7,
];

pub fn parse_ip2location_bin(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    if bytes.len() < 64 {
        bail!(
            "IP2Location BIN '{}' too short ({} bytes)",
            src.id,
            bytes.len()
        );
    }

    let db_type = bytes[0] as usize;
    let db_cols = bytes[1] as usize;
    if db_type == 0 || db_type >= COUNTRY_POS.len() || !(2..=32).contains(&db_cols) {
        bail!(
            "unsupported IP2Location BIN header in '{}': type={} cols={}",
            src.id,
            db_type,
            db_cols
        );
    }

    let ipv4_count = u32::from_le_bytes(bytes[5..9].try_into().unwrap()) as usize;
    let ipv4_base_1 = u32::from_le_bytes(bytes[9..13].try_into().unwrap()) as usize;
    let ipv6_count = u32::from_le_bytes(bytes[13..17].try_into().unwrap()) as usize;
    let ipv6_base_1 = u32::from_le_bytes(bytes[17..21].try_into().unwrap()) as usize;

    let mut out = ParsedSource::new(&src.id);
    let base_traits = src.base_traits();
    let payload_bytes_len = (db_cols - 1) * 4;
    let mut row_cache: FxHashMap<Vec<u8>, Option<u32>> = FxHashMap::default();

    // 1. Scan IPv4 table
    if ipv4_count > 1 && ipv4_base_1 > 0 {
        let base = ipv4_base_1 - 1;
        let stride = db_cols * 4;
        if base + ipv4_count * stride <= bytes.len() {
            for i in 0..(ipv4_count - 1) {
                let off = base + i * stride;
                let next_off = off + stride;
                let ip_from = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
                let next_ip_from =
                    u32::from_le_bytes(bytes[next_off..next_off + 4].try_into().unwrap());
                if next_ip_from <= ip_from {
                    continue;
                }
                let ip_to = next_ip_from - 1;
                let col_slice = &bytes[off + 4..off + 4 + payload_bytes_len];
                if let Some(pid) = decode_ip2loc_cols(
                    bytes,
                    col_slice,
                    db_type,
                    base_traits,
                    metadata,
                    &mut out,
                    &mut row_cache,
                ) {
                    out.push_v4(ip_from, ip_to, pid, effective_prefix_v4(ip_from, ip_to));
                }
            }
        }
    }

    // 2. Scan IPv6 table
    if ipv6_count > 1 && ipv6_base_1 > 0 {
        let base = ipv6_base_1 - 1;
        let stride = 16 + payload_bytes_len;
        if base + ipv6_count * stride <= bytes.len() {
            let skip_embedded_v4 = ipv4_count > 1;
            for i in 0..(ipv6_count - 1) {
                let off = base + i * stride;
                let next_off = off + stride;
                let ip_from = u128::from_le_bytes(bytes[off..off + 16].try_into().unwrap());
                let next_ip_from =
                    u128::from_le_bytes(bytes[next_off..next_off + 16].try_into().unwrap());
                if next_ip_from <= ip_from {
                    continue;
                }
                let ip_to = next_ip_from - 1;
                if skip_embedded_v4 && ip_to <= 0x0000_FFFF_FFFF_FFFF {
                    continue;
                }
                let col_slice = &bytes[off + 16..off + 16 + payload_bytes_len];
                if let Some(pid) = decode_ip2loc_cols(
                    bytes,
                    col_slice,
                    db_type,
                    base_traits,
                    metadata,
                    &mut out,
                    &mut row_cache,
                ) {
                    out.push_v6(ip_from, ip_to, pid, effective_prefix_v6(ip_from, ip_to));
                }
            }
        }
    }

    out.finalize();
    Ok(out)
}

fn decode_ip2loc_cols(
    bytes: &[u8],
    col_slice: &[u8],
    db_type: usize,
    base_traits: crate::model::TraitFlags,
    metadata: &MetadataRegistry,
    out: &mut ParsedSource,
    cache: &mut FxHashMap<Vec<u8>, Option<u32>>,
) -> Option<u32> {
    if let Some(&cached) = cache.get(col_slice) {
        return cached;
    }

    let read_col_u32 = |pos_1based: u8| -> Option<u32> {
        if pos_1based < 2 {
            return None;
        }
        let idx = (pos_1based as usize - 2) * 4;
        if idx + 4 <= col_slice.len() {
            Some(u32::from_le_bytes(
                col_slice[idx..idx + 4].try_into().unwrap(),
            ))
        } else {
            None
        }
    };

    let c_ptr = read_col_u32(COUNTRY_POS[db_type])? as usize;
    let cc_str = read_ip2loc_str(bytes, c_ptr)?;
    if matches!(cc_str, "-" | "" | "ZZ") {
        cache.insert(col_slice.to_vec(), None);
        return None;
    }
    let Some(iso) = IsoCode::parse_raw(cc_str).and_then(|c| metadata.validate_iso(c)) else {
        cache.insert(col_slice.to_vec(), None);
        return None;
    };

    let mut p = ObsPayload {
        country: Some(iso),
        traits: base_traits,
        ..ObsPayload::default()
    };

    let reg_str = read_col_u32(REGION_POS[db_type])
        .and_then(|ptr| read_ip2loc_str(bytes, ptr as usize))
        .filter(|s| !matches!(*s, "-" | ""));
    let city_str = read_col_u32(CITY_POS[db_type])
        .and_then(|ptr| read_ip2loc_str(bytes, ptr as usize))
        .filter(|s| !matches!(*s, "-" | ""));

    if iso == IsoCode::CN {
        let (prov, city) =
            metadata.resolve_cn_division(reg_str.unwrap_or(""), city_str.unwrap_or(""));
        if let Some(pm) = prov {
            p.subdiv1_iso = out.intern_str(&pm.iso_code);
            p.subdiv1_en = out.intern_str(&pm.province_en);
            p.subdiv1_zh = out.intern_str(&pm.province_zh);
            p.subdiv1_geoname_id = pm.geoname_id;
        } else if let Some(r) = reg_str {
            p.subdiv1_en = out.intern_str(r);
        }
        if let Some(cm) = city {
            p.city_en = out.intern_str(&cm.city_en);
            p.city_zh = out.intern_str(&cm.city_zh);
            p.city_geoname_id = cm.geoname_id;
        } else if let Some(c) = city_str {
            p.city_en = out.intern_str(c);
        }
    } else {
        if let Some(r) = reg_str {
            p.subdiv1_en = out.intern_str(r);
        }
        if let Some(c) = city_str {
            p.city_en = out.intern_str(c);
        }
    }

    if let (Some(lat_bits), Some(lon_bits)) = (
        read_col_u32(LATITUDE_POS[db_type]),
        read_col_u32(LONGITUDE_POS[db_type]),
    ) {
        let lat = f32::from_bits(lat_bits) as f64;
        let lon = f32::from_bits(lon_bits) as f64;
        let qlat = quantize_coord(lat);
        let qlon = quantize_coord(lon);
        if qlat != 0 || qlon != 0 {
            p.latitude_e5 = qlat;
            p.longitude_e5 = qlon;
        } else {
            p.latitude_e5 = COORD_UNSET;
            p.longitude_e5 = COORD_UNSET;
        }
    }

    if let Some(zip_str) = read_col_u32(ZIPCODE_POS[db_type])
        .and_then(|ptr| read_ip2loc_str(bytes, ptr as usize))
        .filter(|s| !matches!(*s, "-" | ""))
    {
        p.postal_code = out.intern_str(zip_str);
    }

    let pid = out.intern_payload(p);
    cache.insert(col_slice.to_vec(), pid);
    pid
}

#[inline]
fn read_ip2loc_str(bytes: &[u8], ptr: usize) -> Option<&str> {
    if ptr >= bytes.len() {
        return None;
    }
    let len = bytes[ptr] as usize;
    if ptr + 1 + len > bytes.len() {
        return None;
    }
    std::str::from_utf8(&bytes[ptr + 1..ptr + 1 + len]).ok()
}

pub fn parse_ip2location_csv(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    let mut out = ParsedSource::new(&src.id);
    let base_traits = src.base_traits();
    let mut iso_cache: FxHashMap<IsoCode, u32> = FxHashMap::default();

    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(Cursor::new(bytes));

    for rec_res in rdr.records() {
        let Ok(rec) = rec_res else {
            continue;
        };
        if rec.len() < 3 {
            continue;
        }
        let cc = rec[2].trim();
        if matches!(cc, "-" | "" | "country_code") {
            continue;
        }
        let Some(iso) = IsoCode::parse_raw(cc).and_then(|c| metadata.validate_iso(c)) else {
            continue;
        };
        let pid = if let Some(&id) = iso_cache.get(&iso) {
            id
        } else {
            let p = ObsPayload {
                country: Some(iso),
                traits: base_traits,
                ..ObsPayload::default()
            };
            let Some(id) = out.intern_payload(p) else {
                continue;
            };
            iso_cache.insert(iso, id);
            id
        };

        if let (Ok(s4), Ok(e4)) = (rec[0].trim().parse::<u32>(), rec[1].trim().parse::<u32>()) {
            out.push_v4(s4, e4, pid, effective_prefix_v4(s4, e4));
        } else if let (Ok(s6), Ok(e6)) =
            (rec[0].trim().parse::<u128>(), rec[1].trim().parse::<u128>())
        {
            out.push_v6(s6, e6, pid, effective_prefix_v6(s6, e6));
        }
    }

    out.finalize();
    Ok(out)
}
