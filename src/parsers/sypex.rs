use anyhow::{Context, Result, bail};
use rustc_hash::FxHashMap;

use crate::config::{MetadataRegistry, SourceConfig};
use crate::model::{IsoCode, ObsPayload, ParsedSource, effective_prefix_v4};
use crate::parsers::{checked_slice, read_u16_be, read_u32_be};

/// Official Sypex Geo v2.2 ID-to-ISO3166-1 alpha-2 table (`SxGeo.php`).
const SYPEX_ID2ISO: [&str; 256] = [
    "", "AP", "EU", "AD", "AE", "AF", "AG", "AI", "AL", "AM", "CW", "AO", "AQ", "AR", "AS", "AT",
    "AU", "AW", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BM", "BN", "BO", "BR",
    "BS", "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM",
    "CN", "CO", "CR", "CU", "CV", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE",
    "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "SX", "GA", "GB", "GD", "GE",
    "GF", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM",
    "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IN", "IO", "IQ", "IR", "IS", "IT", "JM", "JO", "JP",
    "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK",
    "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "MG", "MH", "MK", "ML", "MM", "MN", "MO",
    "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG",
    "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM",
    "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RU", "RW", "SA", "SB", "SC", "SD", "SE",
    "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "ST", "SV", "SY", "SZ", "TC", "TD",
    "TF", "TG", "TH", "TJ", "TK", "TM", "TN", "TO", "TL", "TR", "TT", "TV", "TW", "TZ", "UA", "UG",
    "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI", "VN", "VU", "WF", "WS", "YE", "YT", "RS",
    "ZA", "ZM", "ME", "ZW", "A1", "XK", "O1", "AX", "GG", "IM", "JE", "BL", "MF", "BQ", "SS", "O1",
];

pub fn parse_sypex(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    if bytes.len() < 40 || &bytes[0..3] != b"SxG" {
        bail!("invalid Sypex Geo magic in '{}'", src.id);
    }
    let ver = bytes[3];
    if ver != 22 && ver != 21 {
        bail!("unsupported Sypex Geo version {} in '{}'", ver, src.id);
    }

    let b_idx_len = bytes[10] as usize;
    let m_idx_len = read_u16_be(bytes, 11).context("Sypex header EOF")? as usize;
    let db_items = read_u32_be(bytes, 15).context("Sypex header EOF")? as usize;
    let id_len = bytes[19] as usize;
    let region_size = read_u32_be(bytes, 24).context("Sypex header EOF")? as usize;
    let city_size = read_u32_be(bytes, 28).context("Sypex header EOF")? as usize;
    let country_size = read_u32_be(bytes, 34).context("Sypex header EOF")? as usize;
    let pack_size = read_u16_be(bytes, 38).context("Sypex header EOF")? as usize;

    let block_len = 3usize
        .checked_add(id_len)
        .context("Sypex block_len overflow")?;
    let b_idx_off = 40usize
        .checked_add(pack_size)
        .context("Sypex b_idx_off overflow")?;
    let m_idx_off = b_idx_len
        .checked_mul(4)
        .and_then(|sz| b_idx_off.checked_add(sz))
        .context("Sypex m_idx_off overflow")?;
    let db_off = m_idx_len
        .checked_mul(4)
        .and_then(|sz| m_idx_off.checked_add(sz))
        .context("Sypex db_off overflow")?;
    let db_bytes = db_items
        .checked_mul(block_len)
        .context("Sypex db_bytes overflow")?;
    let regions_off = db_off
        .checked_add(db_bytes)
        .context("Sypex regions_off overflow")?;
    let cities_off = regions_off
        .saturating_add(region_size)
        .saturating_add(country_size);

    if regions_off > bytes.len() || b_idx_len < 2 || !matches!(id_len, 1 | 3) {
        bail!(
            "invalid Sypex Geo layout in '{}': db_end={} total={}",
            src.id,
            regions_off,
            bytes.len()
        );
    }

    // Reconstruct flat `(start_ip, raw_id)` list across first-octet buckets `0 .. b_idx_len - 1`
    let mut b_idx = Vec::with_capacity(b_idx_len);
    for i in 0..b_idx_len {
        let off = b_idx_off + i * 4;
        let val = read_u32_be(bytes, off).context("Sypex b_idx truncated")? as usize;
        b_idx.push(val);
    }

    let mut entries: Vec<(u32, u32)> = Vec::with_capacity(db_items);
    for octet in 0..(b_idx_len - 1) {
        let start_item = b_idx[octet];
        let end_item = b_idx[octet + 1].min(db_items);
        if start_item >= end_item {
            continue;
        }
        for item in start_item..end_item {
            let off = db_off + item * block_len;
            let Some(rec) = checked_slice(bytes, off, block_len) else {
                continue;
            };
            let ip = u32::from_be_bytes([octet as u8, rec[0], rec[1], rec[2]]);
            let raw_id = if id_len == 1 {
                rec[3] as u32
            } else {
                ((rec[3] as u32) << 16) | ((rec[4] as u32) << 8) | (rec[5] as u32)
            };
            entries.push((ip, raw_id));
        }
    }

    let mut out = ParsedSource::new(&src.id);
    let base_traits = src.base_traits();
    let mut id_cache: FxHashMap<u32, Option<u32>> = FxHashMap::default();

    for i in 0..entries.len() {
        let (start_ip, raw_id) = entries[i];
        let end_ip = if i + 1 < entries.len() {
            entries[i + 1].0.saturating_sub(1)
        } else {
            0xDF_FF_FF_FFu32
        };
        if start_ip > end_ip || raw_id == 0 {
            continue;
        }

        let pid_opt = if let Some(&cached) = id_cache.get(&raw_id) {
            cached
        } else {
            let iso_opt = if id_len == 1 {
                let code_str = SYPEX_ID2ISO.get(raw_id as usize).copied().unwrap_or("");
                IsoCode::parse_raw(code_str).and_then(|c| metadata.validate_iso(c))
            } else {
                // For SxGeoCity (`id_len == 3`), if `raw_id < country_size` it's in `countries` block
                // where byte 0 is the `id2iso` country index; otherwise in `cities` block where byte 4 is `country_id`.
                let cid = if (raw_id as usize) < country_size {
                    let c_off = regions_off + region_size + (raw_id as usize);
                    bytes.get(c_off).copied().unwrap_or(0) as usize
                } else {
                    let c_off = cities_off.saturating_sub(country_size) + (raw_id as usize);
                    bytes.get(c_off + 4).copied().unwrap_or(0) as usize
                };
                let _ = city_size;
                let code_str = SYPEX_ID2ISO.get(cid).copied().unwrap_or("");
                IsoCode::parse_raw(code_str).and_then(|c| metadata.validate_iso(c))
            };
            let built = iso_opt.and_then(|iso| {
                out.intern_payload(ObsPayload {
                    country: Some(iso),
                    traits: base_traits,
                    ..ObsPayload::default()
                })
            });
            id_cache.insert(raw_id, built);
            built
        };

        if let Some(pid) = pid_opt {
            out.push_v4(start_ip, end_ip, pid, effective_prefix_v4(start_ip, end_ip));
        }
    }

    out.finalize();
    Ok(out)
}
