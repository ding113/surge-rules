use anyhow::{Context, Result, bail};
use rustc_hash::FxHashMap;

use crate::config::{MetadataRegistry, SourceConfig, normalize_isp_name};
use crate::model::{
    IsoCode, ObsPayload, ParsedSource, TraitFlags, effective_prefix_v4, effective_prefix_v6,
};
use crate::parsers::{checked_slice, read_u16_le, read_u32_le, read_u128_be};

const XDB_HEADER_LEN: usize = 256;

pub fn parse_xdb(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    if bytes.len() < XDB_HEADER_LEN {
        bail!(
            "ip2region XDB '{}' too short ({} bytes)",
            src.id,
            bytes.len()
        );
    }

    let start_idx_ptr = read_u32_le(bytes, 8).context("XDB header EOF")? as usize;
    let end_idx_ptr = read_u32_le(bytes, 12).context("XDB header EOF")? as usize;
    let ip_ver_hdr = read_u16_le(bytes, 16).context("XDB header EOF")?;

    if start_idx_ptr < XDB_HEADER_LEN || end_idx_ptr < start_idx_ptr || end_idx_ptr >= bytes.len() {
        bail!(
            "invalid ip2region XDB index pointers in '{}': start={} end={} len={}",
            src.id,
            start_idx_ptr,
            end_idx_ptr,
            bytes.len()
        );
    }

    let span = end_idx_ptr - start_idx_ptr;
    let is_ipv6 = if ip_ver_hdr == 6 {
        true
    } else if ip_ver_hdr == 4 {
        false
    } else {
        span % 38 == 0 && span % 14 != 0
    };

    let stride = if is_ipv6 { 38 } else { 14 };
    if end_idx_ptr
        .checked_add(stride)
        .is_none_or(|end| end > bytes.len())
    {
        bail!("ip2region XDB '{}' truncated at end_idx_ptr", src.id);
    }

    let mut out = ParsedSource::new(&src.id);
    let base_traits = src.base_traits();
    let mut ptr_cache: FxHashMap<(usize, usize), Option<u32>> = FxHashMap::default();

    let mut pos = start_idx_ptr;
    while pos <= end_idx_ptr {
        if is_ipv6 {
            let (Some(start), Some(end), Some(data_len), Some(data_ptr)) = (
                read_u128_be(bytes, pos),
                read_u128_be(bytes, pos + 16),
                read_u16_le(bytes, pos + 32).map(|v| v as usize),
                read_u32_le(bytes, pos + 34).map(|v| v as usize),
            ) else {
                break;
            };
            pos += 38;

            if start > end || data_len == 0 || checked_slice(bytes, data_ptr, data_len).is_none() {
                continue;
            }
            if let Some(pid) = decode_xdb_region(
                bytes,
                data_ptr,
                data_len,
                base_traits,
                metadata,
                &mut out,
                &mut ptr_cache,
            ) {
                out.push_v6(start, end, pid, effective_prefix_v6(start, end));
            }
        } else {
            let (Some(start), Some(end), Some(data_len), Some(data_ptr)) = (
                read_u32_le(bytes, pos),
                read_u32_le(bytes, pos + 4),
                read_u16_le(bytes, pos + 8).map(|v| v as usize),
                read_u32_le(bytes, pos + 10).map(|v| v as usize),
            ) else {
                break;
            };
            pos += 14;

            if start > end || data_len == 0 || checked_slice(bytes, data_ptr, data_len).is_none() {
                continue;
            }
            if let Some(pid) = decode_xdb_region(
                bytes,
                data_ptr,
                data_len,
                base_traits,
                metadata,
                &mut out,
                &mut ptr_cache,
            ) {
                out.push_v4(start, end, pid, effective_prefix_v4(start, end));
            }
        }
    }

    out.finalize();
    Ok(out)
}

fn decode_xdb_region(
    bytes: &[u8],
    data_ptr: usize,
    data_len: usize,
    base_traits: TraitFlags,
    metadata: &MetadataRegistry,
    out: &mut ParsedSource,
    cache: &mut FxHashMap<(usize, usize), Option<u32>>,
) -> Option<u32> {
    if let Some(&cached) = cache.get(&(data_ptr, data_len)) {
        return cached;
    }
    let built = std::str::from_utf8(&bytes[data_ptr..data_ptr + data_len])
        .ok()
        .and_then(|s| build_xdb_payload(s, base_traits, metadata, out));
    cache.insert((data_ptr, data_len), built);
    built
}

fn build_xdb_payload(
    raw: &str,
    base_traits: TraitFlags,
    metadata: &MetadataRegistry,
    out: &mut ParsedSource,
) -> Option<u32> {
    let parts: Vec<&str> = raw.split('|').map(str::trim).collect();
    if parts.len() < 4 {
        return None;
    }

    let c_raw = parts[0];
    if matches!(
        c_raw,
        "" | "0" | "Reserved" | "内网IP" | "局域网" | "保留地址"
    ) {
        return None;
    }

    // Detect v3 `country|province|city|isp|iso_code` vs v2 `country|region|province|city|isp`
    let (prov_raw, city_raw, isp_raw, explicit_iso) = if parts.len() >= 5 {
        if let Some(iso) = IsoCode::parse_raw(parts[4]).and_then(|c| metadata.validate_iso(c)) {
            (parts[1], parts[2], parts[3], Some(iso))
        } else if parts[4] == "0"
            && (parts[3] == "0" || normalize_isp_name(parts[3]).is_some())
            && parts[1] != "0"
        {
            // v3 row with unset iso_code (`0`) at col 4
            (parts[1], parts[2], parts[3], None)
        } else {
            // v2 format: `country|region|province|city|isp`
            (parts[2], parts[3], parts[4], None)
        }
    } else {
        (parts[1], parts[2], parts[3], None)
    };

    let mut p = ObsPayload {
        traits: base_traits,
        ..ObsPayload::default()
    };

    // Enforce HK/MO/TW separation even when upstream writes `中国|香港|...|CN`
    if prov_raw.contains("香港") || city_raw.contains("香港") || c_raw.contains("香港") {
        p.country = Some(IsoCode::HK);
    } else if prov_raw.contains("澳门") || city_raw.contains("澳门") || c_raw.contains("澳门")
    {
        p.country = Some(IsoCode::MO);
    } else if prov_raw.contains("台湾") || city_raw.contains("台湾") || c_raw.contains("台湾")
    {
        p.country = Some(IsoCode::TW);
    } else {
        p.country = explicit_iso.or_else(|| metadata.resolve_country(c_raw));
    }

    if p.country == Some(IsoCode::CN) {
        let (prov, city) = metadata.resolve_cn_division(prov_raw, city_raw);
        if let Some(pm) = prov {
            p.subdiv1_iso = out.intern_str(&pm.iso_code);
            p.subdiv1_en = out.intern_str(&pm.province_en);
            p.subdiv1_zh = out.intern_str(&pm.province_zh);
            p.subdiv1_geoname_id = pm.geoname_id;
            p.latitude_e5 = pm.lat_e5;
            p.longitude_e5 = pm.lon_e5;
        }
        if let Some(cm) = city {
            p.city_en = out.intern_str(&cm.city_en);
            p.city_zh = out.intern_str(&cm.city_zh);
            p.city_geoname_id = cm.geoname_id;
            p.latitude_e5 = cm.lat_e5;
            p.longitude_e5 = cm.lon_e5;
        }
    } else if p.country.is_some() {
        let skip_region_subdiv = matches!(p.country, Some(IsoCode::HK | IsoCode::MO | IsoCode::TW))
            && matches!(
                prov_raw.trim(),
                "香港"
                    | "香港特别行政区"
                    | "澳门"
                    | "澳门特别行政区"
                    | "台湾"
                    | "台湾省"
                    | "Hong Kong"
                    | "Macau"
                    | "Macao"
                    | "Taiwan"
            );
        if !skip_region_subdiv && prov_raw != "0" && !prov_raw.is_empty() {
            if prov_raw.is_ascii() {
                p.subdiv1_en = out.intern_str(prov_raw);
            } else {
                p.subdiv1_zh = out.intern_str(prov_raw);
            }
        }
        if city_raw != "0" && !city_raw.is_empty() {
            if city_raw.is_ascii() {
                p.city_en = out.intern_str(city_raw);
            } else {
                p.city_zh = out.intern_str(city_raw);
            }
        }
    }

    if let Some(isp) = normalize_isp_name(isp_raw) {
        p.isp = out.intern_str(&isp);
    }

    out.intern_payload(p)
}
