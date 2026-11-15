use anyhow::{Result, bail};
use rustc_hash::FxHashMap;

use crate::config::{MetadataRegistry, SourceConfig};
use crate::model::{
    AsnMetaObs, IsoCode, ObsPayload, ParsedSource, TraitFlags, effective_prefix_v6,
};

const LIBLOC_MAGIC: &[u8] = b"LOCDBXX";
const LOC_NETWORK_FLAG_ANONYMOUS_PROXY: u16 = 1 << 0;
const LOC_NETWORK_FLAG_SATELLITE_PROVIDER: u16 = 1 << 1;
const LOC_NETWORK_FLAG_ANYCAST: u16 = 1 << 2;
const LOC_NETWORK_FLAG_DROP: u16 = 1 << 3;

pub fn parse_libloc(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    if bytes.len() < 72 || &bytes[0..7] != LIBLOC_MAGIC {
        bail!("invalid IPFire libloc magic in '{}'", src.id);
    }
    let version = bytes[7];
    if version != 1 {
        bail!(
            "unsupported IPFire libloc version {} in '{}'",
            version,
            src.id
        );
    }

    // `struct loc_database_header_v1` begins at offset 8 (all big-endian):
    //   created_at (u64: 8..16)
    //   vendor (u32: 16..20), description (u32: 20..24), license (u32: 24..28)
    //   as_offset (u32: 28..32), as_length (u32: 32..36)
    //   network_data_offset (u32: 36..40), network_data_length (u32: 40..44)
    //   network_tree_offset (u32: 44..48), network_tree_length (u32: 48..52)
    //   countries_offset (u32: 52..56), countries_length (u32: 56..60)
    //   pool_offset (u32: 60..64), pool_length (u32: 64..68)
    let as_offset = read_u32_be(bytes, 28) as usize;
    let as_length = read_u32_be(bytes, 32) as usize;
    let net_data_offset = read_u32_be(bytes, 36) as usize;
    let net_data_length = read_u32_be(bytes, 40) as usize;
    let net_tree_offset = read_u32_be(bytes, 44) as usize;
    let net_tree_length = read_u32_be(bytes, 48) as usize;
    let pool_offset = read_u32_be(bytes, 60) as usize;
    let pool_length = read_u32_be(bytes, 64) as usize;

    for (name, off, len) in [
        ("as", as_offset, as_length),
        ("network_data", net_data_offset, net_data_length),
        ("network_tree", net_tree_offset, net_tree_length),
        ("pool", pool_offset, pool_length),
    ] {
        if off.saturating_add(len) > bytes.len() {
            bail!(
                "IPFire libloc section '{}' out of bounds in '{}': off={} len={} total={}",
                name,
                src.id,
                off,
                len,
                bytes.len()
            );
        }
    }

    if as_length % 8 != 0 || net_data_length % 8 != 0 || net_tree_length % 12 != 0 {
        bail!(
            "IPFire libloc section alignment mismatch in '{}': as={} net_data={} net_tree={}",
            src.id,
            as_length,
            net_data_length,
            net_tree_length
        );
    }

    let pool_slice = &bytes[pool_offset..pool_offset + pool_length];
    let mut out = ParsedSource::new(&src.id);
    let base_traits = src.base_traits();

    // 1. Parse AS table (`struct loc_database_as_v1`: `number: u32 BE, name: u32 BE`)
    let mut asn_names: FxHashMap<u32, String> = FxHashMap::default();
    let as_count = as_length / 8;
    for i in 0..as_count {
        let off = as_offset + i * 8;
        let asn = read_u32_be(bytes, off);
        let name_off = read_u32_be(bytes, off + 4) as usize;
        if asn != 0
            && let Some(name) = read_pool_cstr(pool_slice, name_off)
            && !name.is_empty()
        {
            asn_names.insert(asn, name.to_string());
            out.asn_meta.push(AsnMetaObs {
                asn,
                organization: name.to_string(),
                domain: None,
                country: None,
                traits: TraitFlags::EMPTY,
                weight: src.asn_weight.max(80),
            });
        }
    }

    // 2. Lazily decode `network_data` entries (`country_code: [u8; 2], flags: u16 BE, asn: u32 BE`)
    let net_data_count = net_data_length / 8;
    let mut net_cache: FxHashMap<u32, Option<u32>> = FxHashMap::default();
    let decode_net = |net_idx: u32,
                      out: &mut ParsedSource,
                      cache: &mut FxHashMap<u32, Option<u32>>|
     -> Option<u32> {
        if let Some(&cached) = cache.get(&net_idx) {
            return cached;
        }
        if (net_idx as usize) >= net_data_count {
            cache.insert(net_idx, None);
            return None;
        }
        let off = net_data_offset + (net_idx as usize) * 8;
        let cc_bytes = &bytes[off..off + 2];
        let flags = u16::from_be_bytes([bytes[off + 2], bytes[off + 3]]);
        let asn = read_u32_be(bytes, off + 4);

        let mut p = ObsPayload {
            traits: base_traits,
            asn,
            ..ObsPayload::default()
        };

        if cc_bytes != [0, 0]
            && let Ok(cc_str) = std::str::from_utf8(cc_bytes)
        {
            match cc_str {
                "A1" => p.traits.insert(TraitFlags::IS_ANONYMOUS_PROXY),
                "A2" => p.traits.insert(TraitFlags::IS_SATELLITE),
                "A3" => p.traits.insert(TraitFlags::IS_ANYCAST),
                "XD" => p.traits.insert(TraitFlags::IS_MALWARE),
                _ => {
                    p.country = IsoCode::parse_raw(cc_str).and_then(|c| metadata.validate_iso(c));
                }
            }
        }

        if (flags & LOC_NETWORK_FLAG_ANONYMOUS_PROXY) != 0 {
            p.traits.insert(TraitFlags::IS_ANONYMOUS_PROXY);
        }
        if (flags & LOC_NETWORK_FLAG_SATELLITE_PROVIDER) != 0 {
            p.traits.insert(TraitFlags::IS_SATELLITE);
        }
        if (flags & LOC_NETWORK_FLAG_ANYCAST) != 0 {
            p.traits.insert(TraitFlags::IS_ANYCAST);
        }
        if (flags & LOC_NETWORK_FLAG_DROP) != 0 {
            p.traits.insert(TraitFlags::IS_MALWARE);
        }

        if asn != 0
            && let Some(org) = asn_names.get(&asn)
        {
            p.as_org = out.intern_str(org);
        }

        let pid = out.intern_payload(p);
        cache.insert(net_idx, pid);
        pid
    };

    // 3. Walk `network_tree` (`zero: u32 BE, one: u32 BE, network: u32 BE`)
    // Note: in `libloc`, IPv4 lives under `::ffff:0:0/96` (80 zero bits + 16 one bits),
    // and internal nodes can carry a `network` index (`!= 0xFFFFFFFF`) inherited by empty children!
    let node_count = net_tree_length / 12;
    if node_count == 0 {
        return Ok(out);
    }

    // Stack item: `(node_idx, depth, prefix_u128, Option<(inherited_payload_id, inherited_depth)>)`
    type LiblocWalkFrame = (usize, u8, u128, Option<(u32, u8)>);
    let mut stack: Vec<LiblocWalkFrame> = Vec::with_capacity(256);
    stack.push((0, 0, 0, None));

    while let Some((node_idx, depth, prefix, mut active)) = stack.pop() {
        if node_idx >= node_count {
            continue;
        }
        let off = net_tree_offset + node_idx * 12;
        let zero = read_u32_be(bytes, off) as usize;
        let one = read_u32_be(bytes, off + 4) as usize;
        let net_idx = read_u32_be(bytes, off + 8);

        if net_idx != 0xFFFF_FFFF
            && (net_idx as usize) < net_data_count
            && let Some(pid) = decode_net(net_idx, &mut out, &mut net_cache)
        {
            active = Some((pid, depth));
        }

        if depth == 128 {
            if let Some((pid, orig_depth)) = active {
                out.push_v6(prefix, prefix, pid, orig_depth.max(128));
            }
            continue;
        }

        // Push right (`1`) first so left (`0`) is visited first in ascending IP order
        for (bit, child_idx) in [(1u128, one), (0u128, zero)] {
            let next_depth = depth + 1;
            let shift = (128 - next_depth) as u32;
            let child_prefix = prefix | (bit << shift);

            if child_idx != 0 && child_idx < node_count {
                stack.push((child_idx, next_depth, child_prefix, active));
            } else if let Some((pid, orig_depth)) = active {
                let host_bits = 128 - next_depth;
                let mask = if host_bits == 128 {
                    u128::MAX
                } else if host_bits == 0 {
                    0
                } else {
                    (1u128 << host_bits) - 1
                };
                let start = child_prefix;
                let end = child_prefix | mask;
                out.push_v6(
                    start,
                    end,
                    pid,
                    orig_depth.max(effective_prefix_v6(start, end)),
                );
            }
        }
    }

    out.finalize();
    Ok(out)
}

#[inline]
fn read_u32_be(bytes: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

fn read_pool_cstr(pool: &[u8], off: usize) -> Option<&str> {
    if off >= pool.len() {
        return None;
    }
    let rel_end = pool[off..].iter().position(|&b| b == 0)?;
    std::str::from_utf8(&pool[off..off + rel_end]).ok()
}
