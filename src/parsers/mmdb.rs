use anyhow::{Context, Result, bail};
use rustc_hash::FxHashMap;

use crate::config::{MetadataRegistry, SourceConfig, normalize_isp_name};
use crate::model::{
    COORD_UNSET, IsoCode, ObsPayload, ParsedSource, StrId, TraitFlags, effective_prefix_v4,
    effective_prefix_v6, quantize_coord,
};

const METADATA_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";

#[derive(Clone, Debug)]
enum MmdbVal<'a> {
    Str(&'a str),
    Double(f64),
    Float(f32),
    Uint(u64),
    Int(i32),
    Bool(bool),
    Map(Vec<(&'a str, MmdbVal<'a>)>),
    Array(Vec<MmdbVal<'a>>),
    Ignored,
}

impl<'a> MmdbVal<'a> {
    fn as_str(&self) -> Option<&'a str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Uint(v) => Some(*v),
            Self::Int(v) if *v >= 0 => Some(*v as u64),
            _ => None,
        }
    }

    fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Double(v) => Some(*v),
            Self::Float(v) => Some(*v as f64),
            _ => None,
        }
    }

    fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    fn as_map(&self) -> Option<&[(&'a str, MmdbVal<'a>)]> {
        match self {
            Self::Map(m) => Some(m.as_slice()),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&[MmdbVal<'a>]> {
        match self {
            Self::Array(a) => Some(a.as_slice()),
            _ => None,
        }
    }

    fn get(&self, key: &str) -> Option<&MmdbVal<'a>> {
        let map = self.as_map()?;
        map.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }
}

pub fn parse_mmdb(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    let meta_pos = find_metadata_marker(bytes)
        .with_context(|| format!("MMDB metadata marker not found in '{}'", src.id))?;
    let meta_start = meta_pos + METADATA_MARKER.len();
    let (meta_val, _) = decode_value(bytes, meta_start, meta_start, 0)
        .with_context(|| format!("failed to decode MMDB metadata in '{}'", src.id))?;

    let ip_version = meta_val
        .get("ip_version")
        .and_then(MmdbVal::as_u64)
        .unwrap_or(6) as u8;
    let node_count = meta_val
        .get("node_count")
        .and_then(MmdbVal::as_u64)
        .context("MMDB metadata missing node_count")? as usize;
    let record_size = meta_val
        .get("record_size")
        .and_then(MmdbVal::as_u64)
        .context("MMDB metadata missing record_size")? as usize;

    if !matches!(record_size, 24 | 28 | 32) {
        bail!(
            "unsupported MMDB record_size {} in '{}'",
            record_size,
            src.id
        );
    }
    if !matches!(ip_version, 4 | 6) {
        bail!("unsupported MMDB ip_version {} in '{}'", ip_version, src.id);
    }

    let node_byte_size = (record_size * 2) / 8;
    let tree_byte_size = node_count
        .checked_mul(node_byte_size)
        .context("MMDB tree_byte_size overflow")?;
    let data_base = tree_byte_size + 16;
    if data_base > meta_pos {
        bail!(
            "corrupt MMDB '{}': data_base {} > metadata marker {}",
            src.id,
            data_base,
            meta_pos
        );
    }

    let mut out = ParsedSource::new(&src.id);
    let base_traits = src.base_traits();
    let mut ptr_cache: FxHashMap<usize, Option<u32>> = FxHashMap::default();

    // Detect if `::ffff:0:0/96` aliases the exact same node as `::/96` so we don't traverse IPv4 twice.
    let v4_zero_root = if ip_version == 6 {
        walk_fixed_bits(bytes, node_count, record_size, 0, 96, false)
    } else {
        None
    };
    let v4_mapped_root = if ip_version == 6 {
        if let Some(after_80) = walk_fixed_bits(bytes, node_count, record_size, 0, 80, false)
            && after_80 < node_count
        {
            walk_fixed_bits(bytes, node_count, record_size, after_80, 16, true)
        } else {
            None
        }
    } else {
        None
    };
    let skip_mapped_subtree =
        ip_version == 6 && v4_zero_root.is_some() && v4_zero_root == v4_mapped_root;

    let max_depth: u8 = if ip_version == 4 { 32 } else { 128 };
    // Iterative explicit stack DFS: `(node_idx, depth, prefix_u128)`
    let mut stack: Vec<(usize, u8, u128)> = Vec::with_capacity(256);
    if node_count > 0 {
        stack.push((0, 0, 0));
    }

    while let Some((node_idx, depth, prefix)) = stack.pop() {
        if skip_mapped_subtree && depth == 96 && prefix == 0x0000_FFFF_0000_0000 {
            continue;
        }
        let (left, right) = read_node(bytes, node_idx, record_size);
        // Push right first so left (lower IP) is popped first, producing ascending IP order!
        for (bit, rec) in [(1u128, right), (0u128, left)] {
            let next_depth = depth + 1;
            let shift = (max_depth - next_depth) as u32;
            let child_prefix = prefix | (bit << shift);

            if rec < node_count {
                if next_depth < max_depth {
                    stack.push((rec, next_depth, child_prefix));
                }
            } else if rec > node_count {
                let payload_opt = if let Some(&cached) = ptr_cache.get(&rec) {
                    cached
                } else {
                    let rel = rec.saturating_sub(node_count + 16);
                    let offset = data_base + rel;
                    let decoded = if offset < meta_pos {
                        decode_value(bytes, offset, data_base, 0)
                            .ok()
                            .and_then(|(val, _)| {
                                extract_mmdb_payload(&val, base_traits, metadata, &mut out)
                            })
                    } else {
                        None
                    };
                    ptr_cache.insert(rec, decoded);
                    decoded
                };

                if let Some(payload_id) = payload_opt {
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
                    if ip_version == 4 {
                        let s4 = start as u32;
                        let e4 = end as u32;
                        out.push_v4(
                            s4,
                            e4,
                            payload_id,
                            next_depth.min(32).max(effective_prefix_v4(s4, e4)),
                        );
                    } else {
                        out.push_v6(
                            start,
                            end,
                            payload_id,
                            next_depth.max(effective_prefix_v6(start, end)),
                        );
                    }
                }
            }
        }
    }

    out.finalize();
    Ok(out)
}

fn find_metadata_marker(bytes: &[u8]) -> Option<usize> {
    let search_start = bytes.len().saturating_sub(256 * 1024);
    let tail = &bytes[search_start..];
    tail.windows(METADATA_MARKER.len())
        .rposition(|w| w == METADATA_MARKER)
        .map(|pos| search_start + pos)
}

#[inline]
fn read_node(bytes: &[u8], node_idx: usize, record_size: usize) -> (usize, usize) {
    match record_size {
        24 => {
            let off = node_idx * 6;
            let left = ((bytes[off] as usize) << 16)
                | ((bytes[off + 1] as usize) << 8)
                | (bytes[off + 2] as usize);
            let right = ((bytes[off + 3] as usize) << 16)
                | ((bytes[off + 4] as usize) << 8)
                | (bytes[off + 5] as usize);
            (left, right)
        }
        28 => {
            let off = node_idx * 7;
            let mid = bytes[off + 3] as usize;
            let left = ((mid >> 4) << 24)
                | ((bytes[off] as usize) << 16)
                | ((bytes[off + 1] as usize) << 8)
                | (bytes[off + 2] as usize);
            let right = ((mid & 0x0f) << 24)
                | ((bytes[off + 4] as usize) << 16)
                | ((bytes[off + 5] as usize) << 8)
                | (bytes[off + 6] as usize);
            (left, right)
        }
        32 => {
            let off = node_idx * 8;
            let left =
                u32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
                    as usize;
            let right = u32::from_be_bytes([
                bytes[off + 4],
                bytes[off + 5],
                bytes[off + 6],
                bytes[off + 7],
            ]) as usize;
            (left, right)
        }
        _ => (0, 0),
    }
}

fn walk_fixed_bits(
    bytes: &[u8],
    node_count: usize,
    record_size: usize,
    mut cur: usize,
    steps: usize,
    bit_one: bool,
) -> Option<usize> {
    for _ in 0..steps {
        if cur >= node_count {
            return Some(cur);
        }
        let (l, r) = read_node(bytes, cur, record_size);
        cur = if bit_one { r } else { l };
    }
    Some(cur)
}

fn decode_value<'a>(
    bytes: &'a [u8],
    mut pos: usize,
    pointer_base: usize,
    depth: u8,
) -> Result<(MmdbVal<'a>, usize)> {
    if depth > 32 {
        bail!("MMDB pointer/container nesting exceeded limit");
    }
    if pos >= bytes.len() {
        bail!("MMDB unexpected EOF at {}", pos);
    }

    let ctrl = bytes[pos];
    pos += 1;
    let mut type_num = ctrl >> 5;
    if type_num == 0 {
        if pos >= bytes.len() {
            bail!("MMDB unexpected EOF reading extended type");
        }
        type_num = bytes[pos] + 7;
        pos += 1;
    }

    if type_num == 1 {
        // Pointer
        let ptr_size = (ctrl >> 3) & 0x03;
        let val_bits = (ctrl & 0x07) as usize;
        let rel_ptr = match ptr_size {
            0 => {
                if pos >= bytes.len() {
                    bail!("MMDB pointer EOF");
                }
                let p = (val_bits << 8) | (bytes[pos] as usize);
                pos += 1;
                p
            }
            1 => {
                if pos + 2 > bytes.len() {
                    bail!("MMDB pointer EOF");
                }
                let p =
                    ((val_bits << 16) | ((bytes[pos] as usize) << 8) | (bytes[pos + 1] as usize))
                        + 2048;
                pos += 2;
                p
            }
            2 => {
                if pos + 3 > bytes.len() {
                    bail!("MMDB pointer EOF");
                }
                let p = ((val_bits << 24)
                    | ((bytes[pos] as usize) << 16)
                    | ((bytes[pos + 1] as usize) << 8)
                    | (bytes[pos + 2] as usize))
                    + 526_336;
                pos += 3;
                p
            }
            _ => {
                if pos + 4 > bytes.len() {
                    bail!("MMDB pointer EOF");
                }
                let p = u32::from_be_bytes([
                    bytes[pos],
                    bytes[pos + 1],
                    bytes[pos + 2],
                    bytes[pos + 3],
                ]) as usize;
                pos += 4;
                p
            }
        };
        let target = pointer_base + rel_ptr;
        let (val, _) = decode_value(bytes, target, pointer_base, depth + 1)?;
        return Ok((val, pos));
    }

    let raw_sz = (ctrl & 0x1f) as usize;
    let sz = match raw_sz {
        0..=28 => raw_sz,
        29 => {
            if pos >= bytes.len() {
                bail!("MMDB size EOF");
            }
            let s = 29 + (bytes[pos] as usize);
            pos += 1;
            s
        }
        30 => {
            if pos + 2 > bytes.len() {
                bail!("MMDB size EOF");
            }
            let s = 285 + (u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize);
            pos += 2;
            s
        }
        _ => {
            if pos + 3 > bytes.len() {
                bail!("MMDB size EOF");
            }
            let s = 65_821
                + (((bytes[pos] as usize) << 16)
                    | ((bytes[pos + 1] as usize) << 8)
                    | (bytes[pos + 2] as usize));
            pos += 3;
            s
        }
    };

    match type_num {
        2 => {
            if pos + sz > bytes.len() {
                bail!("MMDB utf8 string EOF");
            }
            let s = std::str::from_utf8(&bytes[pos..pos + sz]).unwrap_or("");
            Ok((MmdbVal::Str(s), pos + sz))
        }
        3 => {
            if pos + 8 > bytes.len() {
                bail!("MMDB f64 EOF");
            }
            let v = f64::from_be_bytes(bytes[pos..pos + 8].try_into().unwrap());
            Ok((MmdbVal::Double(v), pos + 8))
        }
        4 => {
            if pos + sz > bytes.len() {
                bail!("MMDB bytes EOF");
            }
            Ok((MmdbVal::Ignored, pos + sz))
        }
        5 | 6 | 9 => {
            if pos + sz > bytes.len() || sz > 8 {
                bail!("MMDB uint EOF/overflow");
            }
            let mut acc = 0u64;
            for &b in &bytes[pos..pos + sz] {
                acc = (acc << 8) | (b as u64);
            }
            Ok((MmdbVal::Uint(acc), pos + sz))
        }
        7 => {
            let mut map = Vec::with_capacity(sz.min(64));
            let mut cur = pos;
            for _ in 0..sz {
                let (k_val, next) = decode_value(bytes, cur, pointer_base, depth + 1)?;
                let key = k_val.as_str().unwrap_or("");
                let (v_val, next2) = decode_value(bytes, next, pointer_base, depth + 1)?;
                map.push((key, v_val));
                cur = next2;
            }
            Ok((MmdbVal::Map(map), cur))
        }
        8 => {
            if pos + sz > bytes.len() || sz > 4 {
                bail!("MMDB i32 EOF");
            }
            let mut acc = 0u32;
            for &b in &bytes[pos..pos + sz] {
                acc = (acc << 8) | (b as u32);
            }
            Ok((MmdbVal::Int(acc as i32), pos + sz))
        }
        10 => {
            if pos + sz > bytes.len() || sz > 16 {
                bail!("MMDB u128 EOF");
            }
            Ok((MmdbVal::Ignored, pos + sz))
        }
        11 => {
            let mut arr = Vec::with_capacity(sz.min(64));
            let mut cur = pos;
            for _ in 0..sz {
                let (v_val, next) = decode_value(bytes, cur, pointer_base, depth + 1)?;
                arr.push(v_val);
                cur = next;
            }
            Ok((MmdbVal::Array(arr), cur))
        }
        12 | 13 => Ok((MmdbVal::Ignored, pos)),
        14 => Ok((MmdbVal::Bool(sz != 0), pos)),
        15 => {
            if pos + 4 > bytes.len() {
                bail!("MMDB f32 EOF");
            }
            let v = f32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap());
            Ok((MmdbVal::Float(v), pos + 4))
        }
        other => bail!("unknown MMDB data type {}", other),
    }
}

fn extract_mmdb_payload(
    root: &MmdbVal<'_>,
    base_traits: TraitFlags,
    metadata: &MetadataRegistry,
    out: &mut ParsedSource,
) -> Option<u32> {
    let mut p = ObsPayload {
        traits: base_traits,
        ..ObsPayload::default()
    };

    // 1. Country: nested `country.iso_code` or flat `country_code` / `country`
    let nested_country = root.get("country").and_then(|c| {
        c.get("iso_code")
            .and_then(MmdbVal::as_str)
            .or_else(|| c.as_str())
    });
    let flat_country = root.get("country_code").and_then(MmdbVal::as_str);
    if let Some(raw_cc) = nested_country.or(flat_country) {
        p.country = IsoCode::parse_raw(raw_cc)
            .and_then(|c| metadata.validate_iso(c))
            .or_else(|| metadata.resolve_country(raw_cc));
    }

    // 2. Registered & represented countries
    if let Some(rc) = root
        .get("registered_country")
        .and_then(|c| c.get("iso_code"))
        .and_then(MmdbVal::as_str)
    {
        p.registered_country = IsoCode::parse_raw(rc).and_then(|c| metadata.validate_iso(c));
    }
    if let Some(rep) = root
        .get("represented_country")
        .and_then(|c| c.get("iso_code"))
        .and_then(MmdbVal::as_str)
    {
        p.represented_country = IsoCode::parse_raw(rep).and_then(|c| metadata.validate_iso(c));
    }

    // 3. Subdivisions: MaxMind `subdivisions` array OR flat `region` / `region_code` / `state1`
    if let Some(subs) = root.get("subdivisions").and_then(MmdbVal::as_array) {
        if let Some(s1) = subs.first() {
            if let Some(iso) = s1.get("iso_code").and_then(MmdbVal::as_str) {
                p.subdiv1_iso = out.intern_str(iso);
            }
            if let Some(gid) = s1.get("geoname_id").and_then(MmdbVal::as_u64) {
                p.subdiv1_geoname_id = gid as u32;
            }
            if let Some(names) = s1.get("names") {
                if let Some(en) = names.get("en").and_then(MmdbVal::as_str) {
                    p.subdiv1_en = out.intern_str(en);
                }
                if let Some(zh) = names
                    .get("zh-CN")
                    .or_else(|| names.get("zh"))
                    .and_then(MmdbVal::as_str)
                {
                    p.subdiv1_zh = out.intern_str(zh);
                }
            }
        }
        if let Some(s2) = subs.get(1) {
            if let Some(iso) = s2.get("iso_code").and_then(MmdbVal::as_str) {
                p.subdiv2_iso = out.intern_str(iso);
            }
            if let Some(names) = s2.get("names") {
                if let Some(en) = names.get("en").and_then(MmdbVal::as_str) {
                    p.subdiv2_en = out.intern_str(en);
                }
                if let Some(zh) = names
                    .get("zh-CN")
                    .or_else(|| names.get("zh"))
                    .and_then(MmdbVal::as_str)
                {
                    p.subdiv2_zh = out.intern_str(zh);
                }
            }
        }
    } else {
        if let Some(rc) = root
            .get("region_code")
            .or_else(|| root.get("subdivision_1_iso_code"))
            .and_then(MmdbVal::as_str)
        {
            p.subdiv1_iso = out.intern_str(rc);
        }
        if let Some(rn) = root
            .get("region")
            .or_else(|| root.get("state1"))
            .or_else(|| root.get("region_name"))
            .and_then(MmdbVal::as_str)
        {
            p.subdiv1_en = out.intern_str(rn);
        }
    }

    // 4. City: nested map `city.names.{en,zh-CN}` or flat string `city`
    if let Some(city_val) = root.get("city") {
        if let Some(gid) = city_val.get("geoname_id").and_then(MmdbVal::as_u64) {
            p.city_geoname_id = gid as u32;
        }
        if let Some(names) = city_val.get("names") {
            if let Some(en) = names.get("en").and_then(MmdbVal::as_str) {
                p.city_en = out.intern_str(en);
            }
            if let Some(zh) = names
                .get("zh-CN")
                .or_else(|| names.get("zh"))
                .and_then(MmdbVal::as_str)
            {
                p.city_zh = out.intern_str(zh);
            }
        } else if let Some(flat_city) = city_val.as_str() {
            p.city_en = out.intern_str(flat_city);
        }
    }

    // 5. Postal
    if let Some(code) = root
        .get("postal")
        .and_then(|v| {
            v.get("code")
                .and_then(MmdbVal::as_str)
                .or_else(|| v.as_str())
        })
        .or_else(|| root.get("postal_code").and_then(MmdbVal::as_str))
        .or_else(|| root.get("postcode").and_then(MmdbVal::as_str))
    {
        p.postal_code = out.intern_str(code);
    }

    // 6. Location
    if let Some(loc) = root.get("location") {
        if let (Some(lat), Some(lon)) = (
            loc.get("latitude").and_then(MmdbVal::as_f64),
            loc.get("longitude").and_then(MmdbVal::as_f64),
        ) {
            p.latitude_e5 = quantize_coord(lat);
            p.longitude_e5 = quantize_coord(lon);
        }
        if let Some(tz) = loc.get("time_zone").and_then(MmdbVal::as_str)
            && tz.contains('/')
        {
            p.time_zone = out.intern_str(tz);
        }
        if let Some(rad) = loc.get("accuracy_radius").and_then(MmdbVal::as_u64) {
            p.accuracy_radius = rad.min(u16::MAX as u64) as u16;
        }
        if let Some(mc) = loc.get("metro_code").and_then(MmdbVal::as_u64) {
            p.metro_code = mc.min(u16::MAX as u64) as u16;
        }
    } else {
        if let (Some(lat), Some(lon)) = (
            root.get("latitude").and_then(MmdbVal::as_f64),
            root.get("longitude").and_then(MmdbVal::as_f64),
        ) {
            p.latitude_e5 = quantize_coord(lat);
            p.longitude_e5 = quantize_coord(lon);
        }
        if let Some(tz) = root
            .get("timezone")
            .or_else(|| root.get("time_zone"))
            .and_then(MmdbVal::as_str)
            && tz.contains('/')
        {
            p.time_zone = out.intern_str(tz);
        }
    }
    if p.latitude_e5 == 0 && p.longitude_e5 == 0 {
        p.latitude_e5 = COORD_UNSET;
        p.longitude_e5 = COORD_UNSET;
    }

    // 7. ASN (MaxMind `autonomous_system_number`, IPinfo `"asn": "AS13335"`, or nested `asn` map)
    if let Some(asn_u) = root
        .get("autonomous_system_number")
        .and_then(MmdbVal::as_u64)
    {
        p.asn = asn_u as u32;
    } else if let Some(asn_val) = root.get("asn") {
        if let Some(u) = asn_val.as_u64() {
            p.asn = u as u32;
        } else if let Some(s) = asn_val.as_str() {
            p.asn = parse_asn_str(s);
        } else if let Some(nested_u) = asn_val
            .get("asn")
            .or_else(|| asn_val.get("number"))
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().map(|s| parse_asn_str(s) as u64))
            })
        {
            p.asn = nested_u as u32;
            if let Some(name) = asn_val
                .get("name")
                .or_else(|| asn_val.get("org"))
                .or_else(|| asn_val.get("organization"))
                .and_then(MmdbVal::as_str)
            {
                p.as_org = out.intern_str(name);
            }
            if let Some(dom) = asn_val.get("domain").and_then(MmdbVal::as_str) {
                p.as_domain = out.intern_str(dom);
            }
        }
    }

    if p.as_org.is_empty()
        && let Some(org) = root
            .get("autonomous_system_organization")
            .or_else(|| root.get("as_name"))
            .or_else(|| root.get("as_org"))
            .and_then(MmdbVal::as_str)
    {
        p.as_org = out.intern_str(org);
    }
    if p.as_domain.is_empty()
        && let Some(dom) = root.get("as_domain").and_then(MmdbVal::as_str)
    {
        p.as_domain = out.intern_str(dom);
    }

    // 8. Traits (MaxMind nested `traits` + flat booleans/strings)
    if let Some(tr) = root.get("traits") {
        if let Some(isp_raw) = tr.get("isp").and_then(MmdbVal::as_str)
            && let Some(norm) = normalize_isp_name(isp_raw)
        {
            p.isp = out.intern_str(&norm);
        }
        if let Some(org_raw) = tr.get("organization").and_then(MmdbVal::as_str) {
            p.organization = out.intern_str(org_raw);
        }
        if p.as_domain.is_empty()
            && let Some(dom) = tr.get("domain").and_then(MmdbVal::as_str)
        {
            p.as_domain = out.intern_str(dom);
        }
        if p.asn == 0
            && let Some(u) = tr.get("autonomous_system_number").and_then(MmdbVal::as_u64)
        {
            p.asn = u as u32;
        }
        if p.as_org.is_empty()
            && let Some(o) = tr
                .get("autonomous_system_organization")
                .and_then(MmdbVal::as_str)
        {
            p.as_org = out.intern_str(o);
        }
        apply_bool_trait(tr, "is_anycast", TraitFlags::IS_ANYCAST, &mut p.traits);
        apply_bool_trait(
            tr,
            "is_anonymous_proxy",
            TraitFlags::IS_ANONYMOUS_PROXY,
            &mut p.traits,
        );
        apply_bool_trait(tr, "is_anonymous_vpn", TraitFlags::IS_VPN, &mut p.traits);
        apply_bool_trait(
            tr,
            "is_tor_exit_node",
            TraitFlags::IS_TOR_EXIT,
            &mut p.traits,
        );
        apply_bool_trait(
            tr,
            "is_hosting_provider",
            TraitFlags::IS_HOSTING,
            &mut p.traits,
        );
        apply_bool_trait(
            tr,
            "is_satellite_provider",
            TraitFlags::IS_SATELLITE,
            &mut p.traits,
        );
    }

    if p.isp.is_empty()
        && let Some(isp_raw) = root.get("isp").and_then(MmdbVal::as_str)
        && let Some(norm) = normalize_isp_name(isp_raw)
    {
        p.isp = out.intern_str(&norm);
    }
    if p.organization.is_empty()
        && let Some(org_raw) = root
            .get("organization")
            .or_else(|| root.get("org"))
            .and_then(MmdbVal::as_str)
    {
        p.organization = out.intern_str(org_raw);
    }

    apply_bool_trait(root, "is_anycast", TraitFlags::IS_ANYCAST, &mut p.traits);
    apply_bool_trait(root, "anycast", TraitFlags::IS_ANYCAST, &mut p.traits);
    apply_bool_trait(
        root,
        "is_anonymous_proxy",
        TraitFlags::IS_ANONYMOUS_PROXY,
        &mut p.traits,
    );
    apply_bool_trait(
        root,
        "is_proxy",
        TraitFlags::IS_ANONYMOUS_PROXY,
        &mut p.traits,
    );
    apply_bool_trait(root, "is_vpn", TraitFlags::IS_VPN, &mut p.traits);
    apply_bool_trait(root, "is_tor", TraitFlags::IS_TOR_EXIT, &mut p.traits);
    apply_bool_trait(root, "is_hosting", TraitFlags::IS_HOSTING, &mut p.traits);
    apply_bool_trait(
        root,
        "is_satellite",
        TraitFlags::IS_SATELLITE,
        &mut p.traits,
    );

    // Privacy nested object (IPLocate / IPinfo style)
    if let Some(priv_map) = root.get("privacy") {
        apply_bool_trait(priv_map, "vpn", TraitFlags::IS_VPN, &mut p.traits);
        apply_bool_trait(
            priv_map,
            "proxy",
            TraitFlags::IS_ANONYMOUS_PROXY,
            &mut p.traits,
        );
        apply_bool_trait(priv_map, "tor", TraitFlags::IS_TOR_EXIT, &mut p.traits);
        apply_bool_trait(priv_map, "hosting", TraitFlags::IS_HOSTING, &mut p.traits);
        apply_bool_trait(
            priv_map,
            "relay",
            TraitFlags::IS_ICLOUD_RELAY,
            &mut p.traits,
        );
    }

    // Ensure HK/MO/TW separation if subdiv1 indicates HK/MO/TW under CN
    if p.country == Some(IsoCode::CN) {
        let s1_iso = out.strings.get(p.subdiv1_iso);
        if matches!(s1_iso, "HK" | "CN-HK" | "91") {
            p.country = Some(IsoCode::HK);
            p.subdiv1_iso = StrId::EMPTY;
        } else if matches!(s1_iso, "MO" | "CN-MO" | "92") {
            p.country = Some(IsoCode::MO);
            p.subdiv1_iso = StrId::EMPTY;
        } else if matches!(s1_iso, "TW" | "CN-TW" | "71") {
            p.country = Some(IsoCode::TW);
            p.subdiv1_iso = StrId::EMPTY;
        }
    }

    out.intern_payload(p)
}

fn apply_bool_trait(map: &MmdbVal<'_>, key: &str, flag: u16, out: &mut TraitFlags) {
    if map.get(key).and_then(MmdbVal::as_bool) == Some(true) {
        out.insert(flag);
    }
}

pub fn parse_asn_str(s: &str) -> u32 {
    let trimmed = s.trim();
    let digits = trimmed
        .strip_prefix("AS")
        .or_else(|| trimmed.strip_prefix("as"))
        .unwrap_or(trimmed);
    digits.parse::<u32>().unwrap_or(0)
}
