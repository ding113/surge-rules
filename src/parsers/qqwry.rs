use anyhow::{Result, bail};
use encoding_rs::GB18030;
use rustc_hash::FxHashMap;

use crate::config::{MetadataRegistry, SourceConfig, normalize_isp_name};
use crate::model::{IsoCode, ObsPayload, ParsedSource, effective_prefix_v4};

pub fn parse_qqwry(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    if bytes.len() < 8 {
        bail!("QQWry file '{}' too short ({} bytes)", src.id, bytes.len());
    }
    let first_idx = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    let last_idx = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    if first_idx >= bytes.len() || last_idx + 7 > bytes.len() || first_idx > last_idx {
        bail!(
            "invalid QQWry header offsets in '{}': first={} last={} len={}",
            src.id,
            first_idx,
            last_idx,
            bytes.len()
        );
    }

    let mut out = ParsedSource::new(&src.id);
    let base_traits = src.base_traits();
    let mut pair_cache: FxHashMap<(usize, usize), Option<u32>> = FxHashMap::default();

    let mut idx_pos = first_idx;
    while idx_pos <= last_idx {
        let start_ip = u32::from_le_bytes(bytes[idx_pos..idx_pos + 4].try_into().unwrap());
        let rec_off = u32::from_le_bytes([
            bytes[idx_pos + 4],
            bytes[idx_pos + 5],
            bytes[idx_pos + 6],
            0,
        ]) as usize;
        idx_pos += 7;

        // Skip 255.255.255.0/24 version metadata banner
        if start_ip >= 0xFFFF_FF00 || rec_off + 5 > bytes.len() {
            continue;
        }
        let end_ip = u32::from_le_bytes(bytes[rec_off..rec_off + 4].try_into().unwrap());
        if end_ip < start_ip {
            continue;
        }

        let Some((country_off, area_off)) = resolve_qqwry_string_offsets(bytes, rec_off + 4) else {
            continue;
        };

        let payload_opt = if let Some(&cached) = pair_cache.get(&(country_off, area_off)) {
            cached
        } else {
            let c_str = read_gb18030_cstr(bytes, country_off);
            let a_str = if area_off > 0 {
                read_gb18030_cstr(bytes, area_off)
            } else {
                String::new()
            };
            let built = build_qqwry_payload(&c_str, &a_str, base_traits, metadata, &mut out);
            pair_cache.insert((country_off, area_off), built);
            built
        };

        if let Some(pid) = payload_opt {
            out.push_v4(start_ip, end_ip, pid, effective_prefix_v4(start_ip, end_ip));
        }
    }

    out.finalize();
    Ok(out)
}

fn resolve_qqwry_string_offsets(bytes: &[u8], mut pos: usize) -> Option<(usize, usize)> {
    for _ in 0..8 {
        if pos >= bytes.len() {
            return None;
        }
        match bytes[pos] {
            0x01 => {
                if pos + 4 > bytes.len() {
                    return None;
                }
                pos = read_u24_le(bytes, pos + 1);
            }
            0x02 => {
                if pos + 4 > bytes.len() {
                    return None;
                }
                let country_off = resolve_single_str_offset(bytes, read_u24_le(bytes, pos + 1))?;
                let area_off = resolve_area_offset(bytes, pos + 4).unwrap_or(0);
                return Some((country_off, area_off));
            }
            _ => {
                let country_off = pos;
                let end_c = find_nul(bytes, pos)?;
                let area_off = resolve_area_offset(bytes, end_c + 1).unwrap_or(0);
                return Some((country_off, area_off));
            }
        }
    }
    None
}

fn resolve_single_str_offset(bytes: &[u8], mut pos: usize) -> Option<usize> {
    for _ in 0..8 {
        if pos >= bytes.len() {
            return None;
        }
        match bytes[pos] {
            0x01 | 0x02 => {
                if pos + 4 > bytes.len() {
                    return None;
                }
                pos = read_u24_le(bytes, pos + 1);
            }
            _ => return Some(pos),
        }
    }
    None
}

fn resolve_area_offset(bytes: &[u8], pos: usize) -> Option<usize> {
    if pos >= bytes.len() {
        return None;
    }
    match bytes[pos] {
        0x00 => Some(0),
        0x01 | 0x02 => {
            if pos + 4 > bytes.len() {
                return None;
            }
            let ptr = read_u24_le(bytes, pos + 1);
            if ptr == 0 {
                Some(0)
            } else {
                resolve_single_str_offset(bytes, ptr)
            }
        }
        _ => Some(pos),
    }
}

#[inline]
fn read_u24_le(bytes: &[u8], pos: usize) -> usize {
    (bytes[pos] as usize) | ((bytes[pos + 1] as usize) << 8) | ((bytes[pos + 2] as usize) << 16)
}

#[inline]
fn find_nul(bytes: &[u8], start: usize) -> Option<usize> {
    bytes[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|rel| start + rel)
}

fn read_gb18030_cstr(bytes: &[u8], start: usize) -> String {
    if start == 0 || start >= bytes.len() {
        return String::new();
    }
    let Some(end) = find_nul(bytes, start) else {
        return String::new();
    };
    if end == start {
        return String::new();
    }
    let (cow, _, _) = GB18030.decode(&bytes[start..end]);
    cow.trim().to_string()
}

fn build_qqwry_payload(
    country_str: &str,
    area_str: &str,
    base_traits: crate::model::TraitFlags,
    metadata: &MetadataRegistry,
    out: &mut ParsedSource,
) -> Option<u32> {
    let c = country_str.trim();
    if c.is_empty()
        || c.eq_ignore_ascii_case("IANA")
        || c.contains("保留地址")
        || c.contains("局域网")
        || c.contains("纯真网络")
        || c.eq_ignore_ascii_case("CZ88.NET")
        || c.contains("本机地址")
        || c.contains("同一内部网")
    {
        return None;
    }

    let mut p = ObsPayload {
        traits: base_traits,
        ..ObsPayload::default()
    };

    if c.contains("香港") || area_str.contains("香港") {
        p.country = Some(IsoCode::HK);
    } else if c.contains("澳门") || area_str.contains("澳门") {
        p.country = Some(IsoCode::MO);
    } else if c.contains("台湾") || area_str.contains("台湾") {
        p.country = Some(IsoCode::TW);
    } else if let Some((prov, city)) = metadata.split_cn_location(c) {
        p.country = Some(IsoCode::CN);
        p.subdiv1_iso = out.intern_str(&prov.iso_code);
        p.subdiv1_en = out.intern_str(&prov.province_en);
        p.subdiv1_zh = out.intern_str(&prov.province_zh);
        p.subdiv1_geoname_id = prov.geoname_id;
        if let Some(cm) = city {
            p.city_en = out.intern_str(&cm.city_en);
            p.city_zh = out.intern_str(&cm.city_zh);
            p.city_geoname_id = cm.geoname_id;
            p.latitude_e5 = cm.lat_e5;
            p.longitude_e5 = cm.lon_e5;
        } else {
            p.latitude_e5 = prov.lat_e5;
            p.longitude_e5 = prov.lon_e5;
        }
    } else if let Some(iso) = metadata.resolve_country(c) {
        p.country = Some(iso);
        if iso == IsoCode::CN
            && let Some((prov, city)) = metadata.split_cn_location(area_str)
        {
            p.subdiv1_iso = out.intern_str(&prov.iso_code);
            p.subdiv1_en = out.intern_str(&prov.province_en);
            p.subdiv1_zh = out.intern_str(&prov.province_zh);
            p.subdiv1_geoname_id = prov.geoname_id;
            if let Some(cm) = city {
                p.city_en = out.intern_str(&cm.city_en);
                p.city_zh = out.intern_str(&cm.city_zh);
                p.city_geoname_id = cm.geoname_id;
                p.latitude_e5 = cm.lat_e5;
                p.longitude_e5 = cm.lon_e5;
            }
        }
    }

    if let Some(isp) = normalize_isp_name(area_str) {
        // Only treat normalized well-known ISP or clean carrier token as ISP
        if matches!(
            isp.as_str(),
            "China Telecom"
                | "China Unicom"
                | "China Mobile"
                | "China Broadnet"
                | "CERNET"
                | "CSTNET"
                | "Dr.Peng"
                | "Alibaba Cloud"
                | "Tencent Cloud"
                | "Huawei Cloud"
                | "Baidu"
                | "ByteDance"
                | "JD Cloud"
                | "Kingsoft Cloud"
                | "Meituan"
                | "Chunghwa Telecom"
        ) {
            p.isp = out.intern_str(&isp);
        } else if !area_str.is_empty() && area_str.len() <= 64 {
            p.organization = out.intern_str(area_str);
        }
    }

    out.intern_payload(p)
}
