use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use rustc_hash::FxHashMap;
use serde::Deserialize;

use crate::config::{MetadataRegistry, SourceConfig, normalize_isp_name};
use crate::model::{
    IsoCode, ObsPayload, ParsedSource, TraitFlags, effective_prefix_v4, effective_prefix_v6,
};

#[derive(Deserialize)]
struct IpdbMeta {
    ip_version: u16,
    node_count: usize,
    fields: Vec<String>,
    languages: HashMap<String, usize>,
}

pub fn parse_ipdb(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    if bytes.len() < 8 {
        bail!("IPDB file '{}' too short", src.id);
    }
    let header_len = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
    if 4 + header_len > bytes.len() {
        bail!("IPDB invalid header_len {} in '{}'", header_len, src.id);
    }

    let meta: IpdbMeta = serde_json::from_slice(&bytes[4..4 + header_len])
        .with_context(|| format!("failed to parse IPDB JSON header in '{}'", src.id))?;

    let tree_base = 4 + header_len;
    let tree_bytes = meta
        .node_count
        .checked_mul(8)
        .context("IPDB tree byte size overflow")?;
    if tree_base + tree_bytes > bytes.len() {
        bail!("IPDB truncated tree in '{}'", src.id);
    }

    let lang_offset = meta
        .languages
        .get("CN")
        .or_else(|| meta.languages.values().min())
        .copied()
        .unwrap_or(0);
    let field_count = meta.fields.len();
    if field_count == 0 {
        bail!("IPDB zero fields in '{}'", src.id);
    }

    let col_idx = |name: &str| meta.fields.iter().position(|f| f == name);
    let idx_country_name = col_idx("country_name");
    let idx_region_name = col_idx("region_name");
    let idx_city_name = col_idx("city_name");
    let idx_district_name = col_idx("district_name");
    let idx_owner = col_idx("owner_domain");
    let idx_isp = col_idx("isp_domain");
    let idx_country_code = col_idx("country_code");

    let is_ipv6_tree = (meta.ip_version & 0x02) != 0 || meta.ip_version == 3;
    let max_depth: u8 = if is_ipv6_tree { 128 } else { 32 };

    // Detect if `::ffff:0:0/96` aliases `::/96` so we don't traverse IPv4 twice.
    let v4_zero_root = if is_ipv6_tree {
        walk_ipdb_bits(bytes, tree_base, meta.node_count, 0, 96, false)
    } else {
        None
    };
    let v4_mapped_root = if is_ipv6_tree {
        if let Some(n80) = walk_ipdb_bits(bytes, tree_base, meta.node_count, 0, 80, false)
            && n80 < meta.node_count
        {
            walk_ipdb_bits(bytes, tree_base, meta.node_count, n80, 16, true)
        } else {
            None
        }
    } else {
        None
    };
    let skip_mapped = is_ipv6_tree && v4_zero_root.is_some() && v4_zero_root == v4_mapped_root;

    let mut out = ParsedSource::new(&src.id);
    let base_traits = src.base_traits();
    let mut ptr_cache: FxHashMap<usize, Option<u32>> = FxHashMap::default();

    let mut stack: Vec<(usize, u8, u128)> = Vec::with_capacity(256);
    if meta.node_count > 0 {
        stack.push((0, 0, 0));
    }

    while let Some((node_idx, depth, prefix)) = stack.pop() {
        if skip_mapped && depth == 96 && prefix == 0x0000_FFFF_0000_0000 {
            continue;
        }
        let node_off = tree_base + node_idx * 8;
        let left = u32::from_be_bytes(bytes[node_off..node_off + 4].try_into().unwrap()) as usize;
        let right =
            u32::from_be_bytes(bytes[node_off + 4..node_off + 8].try_into().unwrap()) as usize;

        for (bit, rec) in [(1u128, right), (0u128, left)] {
            let next_depth = depth + 1;
            let shift = (max_depth - next_depth) as u32;
            let child_prefix = prefix | (bit << shift);

            if rec < meta.node_count {
                if next_depth < max_depth {
                    stack.push((rec, next_depth, child_prefix));
                }
            } else if rec > meta.node_count {
                let payload_opt = if let Some(&cached) = ptr_cache.get(&rec) {
                    cached
                } else {
                    let data_off = tree_base + tree_bytes + (rec - meta.node_count);
                    let decoded = if data_off + 2 <= bytes.len() {
                        let d_len =
                            u16::from_be_bytes([bytes[data_off], bytes[data_off + 1]]) as usize;
                        if data_off + 2 + d_len <= bytes.len() {
                            std::str::from_utf8(&bytes[data_off + 2..data_off + 2 + d_len])
                                .ok()
                                .and_then(|s| {
                                    let cols: Vec<&str> = s.split('\t').collect();
                                    if cols.len() < lang_offset + field_count {
                                        return None;
                                    }
                                    let slice = &cols[lang_offset..lang_offset + field_count];
                                    build_ipdb_payload(
                                        slice,
                                        idx_country_name,
                                        idx_region_name,
                                        idx_city_name,
                                        idx_district_name,
                                        idx_owner,
                                        idx_isp,
                                        idx_country_code,
                                        base_traits,
                                        metadata,
                                        &mut out,
                                    )
                                })
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    ptr_cache.insert(rec, decoded);
                    decoded
                };

                if let Some(pid) = payload_opt {
                    let host_bits = max_depth - next_depth;
                    let mask = if host_bits == 128 {
                        u128::MAX
                    } else if host_bits == 0 {
                        0
                    } else {
                        (1u128 << host_bits) - 1
                    };
                    let start = child_prefix;
                    let end = child_prefix | mask;
                    if is_ipv6_tree {
                        out.push_v6(
                            start,
                            end,
                            pid,
                            next_depth.max(effective_prefix_v6(start, end)),
                        );
                    } else {
                        let s4 = start as u32;
                        let e4 = end as u32;
                        out.push_v4(
                            s4,
                            e4,
                            pid,
                            next_depth.min(32).max(effective_prefix_v4(s4, e4)),
                        );
                    }
                }
            }
        }
    }

    out.finalize();
    Ok(out)
}

fn walk_ipdb_bits(
    bytes: &[u8],
    tree_base: usize,
    node_count: usize,
    mut cur: usize,
    steps: usize,
    bit_one: bool,
) -> Option<usize> {
    for _ in 0..steps {
        if cur >= node_count {
            return Some(cur);
        }
        let off = tree_base + cur * 8;
        let l = u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
        let r = u32::from_be_bytes(bytes[off + 4..off + 8].try_into().unwrap()) as usize;
        cur = if bit_one { r } else { l };
    }
    Some(cur)
}

#[allow(clippy::too_many_arguments)]
fn build_ipdb_payload(
    cols: &[&str],
    idx_country_name: Option<usize>,
    idx_region_name: Option<usize>,
    idx_city_name: Option<usize>,
    idx_district_name: Option<usize>,
    idx_owner: Option<usize>,
    idx_isp: Option<usize>,
    idx_country_code: Option<usize>,
    base_traits: TraitFlags,
    metadata: &MetadataRegistry,
    out: &mut ParsedSource,
) -> Option<u32> {
    let get_col = |idx: Option<usize>| idx.and_then(|i| cols.get(i)).copied().unwrap_or("").trim();

    let c_name = get_col(idx_country_name);
    let r_name = get_col(idx_region_name);
    let city_name = get_col(idx_city_name);
    let dist_name = get_col(idx_district_name);
    let owner = get_col(idx_owner);
    let isp_raw = get_col(idx_isp);
    let cc_raw = get_col(idx_country_code);

    if matches!(
        c_name,
        "局域网" | "保留地址" | "本机地址" | "共享地址" | "链路本地" | "IANA"
    ) {
        return None;
    }

    let mut p = ObsPayload {
        traits: base_traits,
        ..ObsPayload::default()
    };

    if c_name.eq_ignore_ascii_case("ANYCAST")
        || r_name.eq_ignore_ascii_case("ANYCAST")
        || isp_raw.eq_ignore_ascii_case("ANYCAST")
    {
        p.traits.insert(TraitFlags::IS_ANYCAST);
    }

    // HK/MO/TW separation before resolving `CN`
    if r_name.contains("香港") || c_name.contains("香港") {
        p.country = Some(IsoCode::HK);
    } else if r_name.contains("澳门") || c_name.contains("澳门") {
        p.country = Some(IsoCode::MO);
    } else if r_name.contains("台湾") || c_name.contains("台湾") {
        p.country = Some(IsoCode::TW);
    } else {
        p.country = IsoCode::parse_raw(cc_raw)
            .and_then(|c| metadata.validate_iso(c))
            .or_else(|| {
                if c_name.eq_ignore_ascii_case("ANYCAST") {
                    None
                } else {
                    metadata.resolve_country(c_name)
                }
            });
    }

    if p.country == Some(IsoCode::CN) {
        let (prov, city) = metadata.resolve_cn_division(r_name, city_name);
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
        if !dist_name.is_empty() && dist_name != city_name {
            p.subdiv2_zh = out.intern_str(dist_name);
        }
    } else if p.country.is_some() {
        let skip_region_subdiv = matches!(p.country, Some(IsoCode::HK | IsoCode::MO | IsoCode::TW))
            && matches!(
                r_name.trim(),
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
        if !skip_region_subdiv
            && !r_name.is_empty()
            && !r_name.eq_ignore_ascii_case("ANYCAST")
            && r_name != c_name
        {
            p.subdiv1_zh = out.intern_str(r_name);
        }
        if !city_name.is_empty() && city_name != r_name {
            p.city_zh = out.intern_str(city_name);
        }
    }

    if let Some(isp) = normalize_isp_name(isp_raw) {
        p.isp = out.intern_str(&isp);
    }
    if !owner.is_empty() && owner != "*" && owner != "0" {
        p.organization = out.intern_str(owner);
    }

    out.intern_payload(p)
}
