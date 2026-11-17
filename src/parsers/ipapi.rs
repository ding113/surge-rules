use std::io::{Cursor, Read};
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};
use rustc_hash::FxHashMap;

use crate::config::{MetadataRegistry, SourceConfig};
use crate::model::{
    COORD_UNSET, IsoCode, ObsPayload, ParsedSource, effective_prefix_v4, effective_prefix_v6,
    quantize_coord,
};

/// Streaming parser for `ipapi-is/ipapi` `geolocationDatabaseIPv4.csv.zip` & `IPv6.csv.zip`
/// (`CC-BY-SA-4.0`). Streams CSV records directly out of `zip::ZipArchive` without materializing
/// the full 590 MB uncompressed CSV in memory, canonicalizes ISO-2 codes (`UK` -> `GB`, dropping
/// `XX`/`ZZ`/invalid), and enforces `min_plen` (`v4 >= 8`, `v6 >= 19`).
pub fn parse_ipapi_csv_zip(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    if bytes.len() >= 4 && &bytes[..4] == b"PK\x03\x04" {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
            .with_context(|| format!("invalid ZIP archive in '{}'", src.id))?;
        let mut best_idx: Option<(usize, bool, u64)> = None;
        for i in 0..archive.len() {
            let file = archive
                .by_index(i)
                .with_context(|| format!("corrupt ZIP entry {} in '{}'", i, src.id))?;
            if file.is_dir() {
                continue;
            }
            let name_lower = file.name().to_ascii_lowercase();
            if name_lower.contains("license") || name_lower.contains("readme") {
                continue;
            }
            let is_csv = name_lower.ends_with(".csv");
            let sz = file.size();
            let cand_key = (is_csv, sz);
            if best_idx.is_none_or(|(_, prev_csv, prev_sz)| cand_key > (prev_csv, prev_sz)) {
                best_idx = Some((i, is_csv, sz));
            }
        }
        let (idx, _, _) =
            best_idx.with_context(|| format!("no CSV data entry found in ZIP '{}'", src.id))?;
        let zf = archive
            .by_index(idx)
            .with_context(|| format!("failed opening ZIP entry {} in '{}'", idx, src.id))?;
        parse_ipapi_csv_reader(src, zf, metadata)
    } else {
        parse_ipapi_csv_reader(src, Cursor::new(bytes), metadata)
    }
}

fn parse_ipapi_csv_reader<R: Read>(
    src: &SourceConfig,
    reader: R,
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    let mut out = ParsedSource::new(&src.id);
    let base_traits = src.base_traits();
    let emit_city = src.city_weight > 0;
    let mut iso_cache: FxHashMap<IsoCode, u32> = FxHashMap::default();

    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(reader);

    // Default `ipapi-is/ipapi` layout:
    // 0:ip_version, 1:start_ip, 2:end_ip, 3:continent, 4:country_code, 5:country,
    // 6:state, 7:city, 8:zip, 9:timezone, 10:latitude, 11:longitude, 12:accuracy, 13:source
    let mut col_start = 1usize;
    let mut col_end = 2usize;
    let mut col_cc = 4usize;
    let mut col_state = 6usize;
    let mut col_city = 7usize;
    let mut col_zip = 8usize;
    let mut col_tz = 9usize;
    let mut col_lat = 10usize;
    let mut col_lon = 11usize;
    let mut col_acc = 12usize;

    if let Ok(headers) = rdr.headers() {
        for (i, h) in headers.iter().enumerate() {
            match h.trim().to_ascii_lowercase().as_str() {
                "start_ip" => col_start = i,
                "end_ip" => col_end = i,
                "country_code" => col_cc = i,
                "state" => col_state = i,
                "city" => col_city = i,
                "zip" => col_zip = i,
                "timezone" => col_tz = i,
                "latitude" => col_lat = i,
                "longitude" => col_lon = i,
                "accuracy" => col_acc = i,
                _ => {}
            }
        }
    }

    let mut rec = csv::StringRecord::new();
    while rdr.read_record(&mut rec).unwrap_or(false) {
        let Some(cc_raw) = rec.get(col_cc) else {
            continue;
        };
        let Some(iso) = IsoCode::parse_raw(cc_raw).and_then(|c| metadata.validate_iso(c)) else {
            continue;
        };
        let (Some(s_raw), Some(e_raw)) = (rec.get(col_start), rec.get(col_end)) else {
            continue;
        };
        let s_str = s_raw.trim();
        let e_str = e_raw.trim();

        let range_parsed = if !s_str.contains(':') {
            let (Ok(s4), Ok(e4)) = (s_str.parse::<Ipv4Addr>(), e_str.parse::<Ipv4Addr>()) else {
                continue;
            };
            let s = u32::from(s4);
            let e = u32::from(e4);
            if s > e {
                continue;
            }
            let plen = effective_prefix_v4(s, e);
            if plen < 8 {
                continue;
            }
            RangeKind::V4(s, e, plen)
        } else {
            let (Ok(s6), Ok(e6)) = (s_str.parse::<Ipv6Addr>(), e_str.parse::<Ipv6Addr>()) else {
                continue;
            };
            let s = u128::from(s6);
            let e = u128::from(e6);
            if s > e {
                continue;
            }
            let plen = effective_prefix_v6(s, e);
            if plen < 19 {
                continue;
            }
            RangeKind::V6(s, e, plen)
        };

        let pid = if !emit_city {
            if let Some(&cached) = iso_cache.get(&iso) {
                cached
            } else {
                let Some(id) = out.intern_payload(ObsPayload {
                    country: Some(iso),
                    traits: base_traits,
                    ..ObsPayload::default()
                }) else {
                    continue;
                };
                iso_cache.insert(iso, id);
                id
            }
        } else {
            let mut p = ObsPayload {
                country: Some(iso),
                traits: base_traits,
                ..ObsPayload::default()
            };
            let state_str = rec.get(col_state).unwrap_or("").trim();
            let city_str = rec.get(col_city).unwrap_or("").trim();
            if iso == IsoCode::CN {
                let (prov, cm) = metadata.resolve_cn_division(state_str, city_str);
                if let Some(pm) = prov {
                    p.subdiv1_iso = out.intern_str(&pm.iso_code);
                    p.subdiv1_en = out.intern_str(&pm.province_en);
                    p.subdiv1_zh = out.intern_str(&pm.province_zh);
                    p.subdiv1_geoname_id = pm.geoname_id;
                } else if !state_str.is_empty() {
                    p.subdiv1_en = out.intern_str(state_str);
                }
                if let Some(c_meta) = cm {
                    p.city_en = out.intern_str(&c_meta.city_en);
                    p.city_zh = out.intern_str(&c_meta.city_zh);
                    p.city_geoname_id = c_meta.geoname_id;
                } else if !city_str.is_empty() {
                    p.city_en = out.intern_str(city_str);
                }
            } else {
                if !state_str.is_empty() {
                    p.subdiv1_en = out.intern_str(state_str);
                }
                if !city_str.is_empty() {
                    p.city_en = out.intern_str(city_str);
                }
            }
            if let Some(z) = rec.get(col_zip).map(str::trim).filter(|s| !s.is_empty()) {
                p.postal_code = out.intern_str(z);
            }
            if let Some(tz) = rec.get(col_tz).map(str::trim).filter(|s| !s.is_empty()) {
                p.time_zone = out.intern_str(tz);
            }
            if let (Some(lat_s), Some(lon_s)) = (rec.get(col_lat), rec.get(col_lon))
                && let (Ok(lat), Ok(lon)) =
                    (lat_s.trim().parse::<f64>(), lon_s.trim().parse::<f64>())
            {
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
            if let Some(acc_s) = rec.get(col_acc)
                && let Ok(acc) = acc_s.trim().parse::<u16>()
            {
                p.accuracy_radius = acc;
            }
            let Some(id) = out.intern_payload(p) else {
                continue;
            };
            id
        };

        match range_parsed {
            RangeKind::V4(s, e, plen) => out.push_v4(s, e, pid, plen),
            RangeKind::V6(s, e, plen) => out.push_v6(s, e, pid, plen),
        }
    }

    out.finalize();
    Ok(out)
}

enum RangeKind {
    V4(u32, u32, u8),
    V6(u128, u128, u8),
}
