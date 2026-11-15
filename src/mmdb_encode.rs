use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use indexmap::IndexSet;
use rustc_hash::{FxBuildHasher, FxHashMap};

use crate::config::MetadataRegistry;
use crate::fusion::{OutputSpanV4, OutputSpanV6};
use crate::model::{
    COORD_UNSET, IsoCode, ResolvedAsnRecord, ResolvedGeoRecord, StrId, StringPool, TraitFlags,
    dequantize_coord, range_to_ipv4_cidrs, range_to_ipv6_cidrs,
};

const METADATA_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";

#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Debug)]
enum Edge {
    #[default]
    Empty,
    Record(u32),
    Node(u32),
}

#[derive(Clone, Copy, Default)]
struct BuilderNode {
    left: Edge,
    right: Edge,
}

struct DualStackTrieBuilder {
    nodes: Vec<BuilderNode>,
}

impl DualStackTrieBuilder {
    fn new() -> Self {
        Self {
            nodes: vec![BuilderNode::default()],
        }
    }

    fn alloc_node(&mut self, left: Edge, right: Edge) -> u32 {
        let idx = self.nodes.len() as u32;
        self.nodes.push(BuilderNode { left, right });
        idx
    }

    /// Inserts `prefix_len` MSB-aligned bits of `bits` (`(bits >> 127) & 1` first).
    fn insert_bits(&mut self, root: Edge, bits: u128, prefix_len: u8, rec: u32) -> Edge {
        if prefix_len == 0 {
            return Edge::Record(rec);
        }
        let node_idx = match root {
            Edge::Node(idx) => idx,
            Edge::Empty => self.alloc_node(Edge::Empty, Edge::Empty),
            Edge::Record(existing) => {
                if existing == rec {
                    return Edge::Record(rec);
                }
                self.alloc_node(Edge::Record(existing), Edge::Record(existing))
            }
        };

        let bit = (bits >> 127) & 1;
        let next_bits = bits << 1;

        if bit == 0 {
            let cur_left = self.nodes[node_idx as usize].left;
            let new_left = self.insert_bits(cur_left, next_bits, prefix_len - 1, rec);
            self.nodes[node_idx as usize].left = new_left;
        } else {
            let cur_right = self.nodes[node_idx as usize].right;
            let new_right = self.insert_bits(cur_right, next_bits, prefix_len - 1, rec);
            self.nodes[node_idx as usize].right = new_right;
        }

        Edge::Node(node_idx)
    }

    fn set_subtree_at_path(
        &mut self,
        root: Edge,
        path_bits: u128,
        depth: u8,
        target: Edge,
    ) -> Edge {
        if depth == 0 {
            return target;
        }
        let node_idx = match root {
            Edge::Node(idx) => idx,
            Edge::Empty => self.alloc_node(Edge::Empty, Edge::Empty),
            Edge::Record(r) => self.alloc_node(Edge::Record(r), Edge::Record(r)),
        };
        let bit = (path_bits >> (depth - 1)) & 1;
        if bit == 0 {
            let l = self.nodes[node_idx as usize].left;
            let nl = self.set_subtree_at_path(l, path_bits, depth - 1, target);
            self.nodes[node_idx as usize].left = nl;
        } else {
            let r = self.nodes[node_idx as usize].right;
            let nr = self.set_subtree_at_path(r, path_bits, depth - 1, target);
            self.nodes[node_idx as usize].right = nr;
        }
        Edge::Node(node_idx)
    }

    /// Collapses `(Empty, Empty) -> Empty` and `(Record(r), Record(r)) -> Record(r)` bottom-up.
    fn compress_edge(&mut self, edge: Edge, memo: &mut FxHashMap<u32, Edge>) -> Edge {
        let Edge::Node(idx) = edge else {
            return edge;
        };
        if let Some(&cached) = memo.get(&idx) {
            return cached;
        }
        let raw = self.nodes[idx as usize];
        let l = self.compress_edge(raw.left, memo);
        let r = self.compress_edge(raw.right, memo);
        self.nodes[idx as usize] = BuilderNode { left: l, right: r };

        let collapsed = match (l, r) {
            (Edge::Empty, Edge::Empty) => Edge::Empty,
            (Edge::Record(a), Edge::Record(b)) if a == b => Edge::Record(a),
            _ => Edge::Node(idx),
        };
        memo.insert(idx, collapsed);
        collapsed
    }

    /// Assigns sequential pre-order MMDB node indices starting with root at `0`,
    /// preserving shared subtree references (such as `::/96` and `::ffff:0:0/96`).
    fn linearize_preorder(&self, root: Edge) -> Vec<(Edge, Edge)> {
        let Edge::Node(root_idx) = root else {
            return vec![(root, root)];
        };
        let mut out: Vec<(Edge, Edge)> = Vec::with_capacity(self.nodes.len());
        let mut remap: FxHashMap<u32, u32> = FxHashMap::default();

        fn visit(
            builder: &DualStackTrieBuilder,
            old_idx: u32,
            out: &mut Vec<(Edge, Edge)>,
            remap: &mut FxHashMap<u32, u32>,
        ) -> u32 {
            if let Some(&new_idx) = remap.get(&old_idx) {
                return new_idx;
            }
            let new_idx = out.len() as u32;
            remap.insert(old_idx, new_idx);
            out.push((Edge::Empty, Edge::Empty));

            let n = builder.nodes[old_idx as usize];
            let new_left = match n.left {
                Edge::Node(c) => Edge::Node(visit(builder, c, out, remap)),
                other => other,
            };
            let new_right = match n.right {
                Edge::Node(c) => Edge::Node(visit(builder, c, out, remap)),
                other => other,
            };
            out[new_idx as usize] = (new_left, new_right);
            new_idx
        }

        visit(self, root_idx, &mut out, &mut remap);
        out
    }
}

fn build_dual_stack_tree(
    v4_spans: &[OutputSpanV4<u32>],
    v6_spans: &[OutputSpanV6<u32>],
) -> Vec<(Edge, Edge)> {
    let mut builder = DualStackTrieBuilder::new();

    // 1. Build 32-bit IPv4 trie
    let mut v4_root = Edge::Empty;
    for span in v4_spans {
        for cidr in range_to_ipv4_cidrs(span.start, span.end) {
            let bits = (u32::from(cidr.network()) as u128) << 96;
            v4_root = builder.insert_bits(v4_root, bits, cidr.prefix_len(), span.record_id);
        }
    }

    // 2. Build 128-bit IPv6 trie
    let mut v6_root = Edge::Empty;
    for span in v6_spans {
        for cidr in range_to_ipv6_cidrs(span.start, span.end) {
            let bits = u128::from(cidr.network());
            v6_root = builder.insert_bits(v6_root, bits, cidr.prefix_len(), span.record_id);
        }
    }

    // 3. Compress IPv4 subtree first, then mount at BOTH `::/96` (`0`) and `::ffff:0:0/96` (`0xffff`)
    let mut v4_memo = FxHashMap::default();
    let v4_compressed = builder.compress_edge(v4_root, &mut v4_memo);
    if v4_compressed != Edge::Empty {
        v6_root = builder.set_subtree_at_path(v6_root, 0, 96, v4_compressed);
        v6_root = builder.set_subtree_at_path(v6_root, 0xFFFF, 96, v4_compressed);
    }

    let mut v6_memo = FxHashMap::default();
    if let Edge::Node(v4_idx) = v4_compressed {
        v6_memo.insert(v4_idx, v4_compressed);
    }
    let v6_compressed = builder.compress_edge(v6_root, &mut v6_memo);
    builder.linearize_preorder(v6_compressed)
}

// ============================================================================
// Deep Structural Hash-Consed MMDB v2.0 Data Section Pool
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct ValId(u32);

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum DataNode {
    Str(String),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    Double(u64), // IEEE-754 f64 bits
    Bool(bool),
    Array(Vec<ValId>),
    Map(Vec<(ValId, ValId)>), // `(key_str_val_id, value_val_id)` sorted by key for canonical dedup
}

struct DataEncoder {
    nodes: IndexSet<DataNode, FxBuildHasher>,
    written_offsets: FxHashMap<ValId, u32>,
    buf: Vec<u8>,
}

impl DataEncoder {
    fn new() -> Self {
        Self {
            nodes: IndexSet::with_hasher(FxBuildHasher),
            written_offsets: FxHashMap::default(),
            buf: Vec::with_capacity(16 * 1024 * 1024),
        }
    }

    fn intern(&mut self, node: DataNode) -> ValId {
        let (idx, _) = self.nodes.insert_full(node);
        ValId(idx as u32)
    }

    fn str_val(&mut self, s: &str) -> ValId {
        self.intern(DataNode::Str(s.to_string()))
    }

    fn u16_val(&mut self, v: u16) -> ValId {
        self.intern(DataNode::Uint16(v))
    }

    fn u32_val(&mut self, v: u32) -> ValId {
        self.intern(DataNode::Uint32(v))
    }

    fn f64_val(&mut self, v: f64) -> ValId {
        let canonical = if v == 0.0 {
            0.0f64.to_bits()
        } else {
            v.to_bits()
        };
        self.intern(DataNode::Double(canonical))
    }

    fn bool_val(&mut self, v: bool) -> ValId {
        self.intern(DataNode::Bool(v))
    }

    fn array_val(&mut self, items: Vec<ValId>) -> ValId {
        self.intern(DataNode::Array(items))
    }

    fn map_val(&mut self, mut entries: Vec<(&str, ValId)>) -> ValId {
        entries.sort_unstable_by_key(|(a, _)| *a);
        let pairs: Vec<(ValId, ValId)> = entries
            .into_iter()
            .map(|(k, v)| (self.str_val(k), v))
            .collect();
        self.intern(DataNode::Map(pairs))
    }

    /// Pre-emits schema keys at the start of the data section (< 2048 bytes for 2-byte pointers),
    /// then emits high-frequency shared subtrees (`refs >= 2`) descending by frequency so pointer
    /// targets cluster at low byte offsets.
    fn pre_emit_hot_nodes(&mut self, root_ids: &[ValId], priority_keys: &[&str]) {
        for &key in priority_keys {
            if key.len() >= 3 {
                let id = self.str_val(key);
                if !self.written_offsets.contains_key(&id) {
                    self.emit_value(id, false, true);
                }
            }
        }

        let n = self.nodes.len();
        let mut reachable = vec![false; n];
        let mut refs = vec![0u32; n];
        for &r in root_ids {
            reachable[r.0 as usize] = true;
        }

        for idx in (0..n).rev() {
            if !reachable[idx] {
                continue;
            }
            match &self.nodes[idx] {
                DataNode::Array(items) => {
                    for &child in items {
                        let ci = child.0 as usize;
                        reachable[ci] = true;
                        refs[ci] = refs[ci].saturating_add(1);
                    }
                }
                DataNode::Map(pairs) => {
                    for &(k, v) in pairs {
                        let ki = k.0 as usize;
                        let vi = v.0 as usize;
                        reachable[ki] = true;
                        reachable[vi] = true;
                        refs[ki] = refs[ki].saturating_add(1);
                        refs[vi] = refs[vi].saturating_add(1);
                    }
                }
                _ => {}
            }
        }

        let mut shared: Vec<(u32, u32)> = Vec::new();
        for (idx, &count) in refs.iter().enumerate() {
            if count < 2 {
                continue;
            }
            let worth_pointing = match &self.nodes[idx] {
                DataNode::Str(s) => s.len() >= 3,
                DataNode::Array(a) => !a.is_empty(),
                DataNode::Map(m) => !m.is_empty(),
                _ => false,
            };
            if worth_pointing && !self.written_offsets.contains_key(&ValId(idx as u32)) {
                shared.push((count, idx as u32));
            }
        }
        shared.sort_unstable_by_key(|&(count, idx)| (std::cmp::Reverse(count), idx));

        for (_, idx) in shared {
            let id = ValId(idx);
            if !self.written_offsets.contains_key(&id) {
                self.emit_value(id, false, true);
            }
        }
    }

    /// Emits a top-level record map directly (never as a top-level pointer) and returns its
    /// relative byte offset in `self.buf`. Nested maps, arrays, and strings (>= 3 bytes)
    /// use MMDB v2.0 pointers whenever previously serialized.
    fn emit_top_level_record(&mut self, id: ValId) -> u32 {
        if let Some(&existing_off) = self.written_offsets.get(&id) {
            return existing_off;
        }
        self.emit_value(id, false, true)
    }

    fn emit_value(&mut self, id: ValId, allow_pointer: bool, children_use_pointers: bool) -> u32 {
        let node = self.nodes[id.0 as usize].clone();
        let worth_pointing = match &node {
            DataNode::Str(s) => s.len() >= 3,
            DataNode::Array(a) => !a.is_empty(),
            DataNode::Map(m) => !m.is_empty(),
            _ => false,
        };

        if allow_pointer
            && worth_pointing
            && let Some(&existing_off) = self.written_offsets.get(&id)
        {
            let ptr_pos = self.buf.len() as u32;
            encode_pointer(existing_off, &mut self.buf);
            return ptr_pos;
        }

        let start_off = self.buf.len() as u32;
        match node {
            DataNode::Str(s) => {
                encode_ctrl_and_size(2, s.len(), &mut self.buf);
                self.buf.extend_from_slice(s.as_bytes());
                if worth_pointing && children_use_pointers {
                    self.written_offsets.entry(id).or_insert(start_off);
                }
            }
            DataNode::Double(bits) => {
                encode_ctrl_and_size(3, 8, &mut self.buf);
                self.buf.extend_from_slice(&bits.to_be_bytes());
            }
            DataNode::Uint16(v) => {
                encode_uint(5, v as u64, &mut self.buf);
            }
            DataNode::Uint32(v) => {
                encode_uint(6, v as u64, &mut self.buf);
            }
            DataNode::Uint64(v) => {
                encode_uint(9, v, &mut self.buf);
            }
            DataNode::Bool(b) => {
                encode_ctrl_and_size(14, usize::from(b), &mut self.buf);
            }
            DataNode::Array(items) => {
                encode_ctrl_and_size(11, items.len(), &mut self.buf);
                for child in items {
                    self.emit_value(child, children_use_pointers, children_use_pointers);
                }
                if worth_pointing && children_use_pointers {
                    self.written_offsets.entry(id).or_insert(start_off);
                }
            }
            DataNode::Map(pairs) => {
                encode_ctrl_and_size(7, pairs.len(), &mut self.buf);
                for (k_id, v_id) in pairs {
                    self.emit_value(k_id, children_use_pointers, children_use_pointers);
                    self.emit_value(v_id, children_use_pointers, children_use_pointers);
                }
                if worth_pointing && children_use_pointers {
                    self.written_offsets.entry(id).or_insert(start_off);
                }
            }
        }
        start_off
    }
}

fn encode_ctrl_and_size(type_num: u8, size: usize, buf: &mut Vec<u8>) {
    let size_field: u8 = if size < 29 {
        size as u8
    } else if size < 285 {
        29
    } else if size < 65_821 {
        30
    } else {
        31
    };

    if type_num <= 7 {
        buf.push((type_num << 5) | size_field);
    } else {
        buf.push(size_field); // extended type (`0 << 5 | size_field`)
        buf.push(type_num - 7);
    }

    if (29..285).contains(&size) {
        buf.push((size - 29) as u8);
    } else if (285..65_821).contains(&size) {
        let adj = (size - 285) as u16;
        buf.extend_from_slice(&adj.to_be_bytes());
    } else if size >= 65_821 {
        let adj = (size - 65_821) as u32;
        buf.push(((adj >> 16) & 0xFF) as u8);
        buf.push(((adj >> 8) & 0xFF) as u8);
        buf.push((adj & 0xFF) as u8);
    }
}

fn encode_uint(type_num: u8, val: u64, buf: &mut Vec<u8>) {
    if val == 0 {
        encode_ctrl_and_size(type_num, 0, buf);
        return;
    }
    let bytes = val.to_be_bytes();
    let first_non_zero = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    let slice = &bytes[first_non_zero..];
    encode_ctrl_and_size(type_num, slice.len(), buf);
    buf.extend_from_slice(slice);
}

fn encode_pointer(offset: u32, buf: &mut Vec<u8>) {
    if offset < 2048 {
        buf.push(0x20 | (((offset >> 8) as u8) & 0x07));
        buf.push((offset & 0xFF) as u8);
    } else if offset < 526_336 {
        let adj = offset - 2048;
        buf.push(0x28 | (((adj >> 16) as u8) & 0x07));
        buf.push(((adj >> 8) & 0xFF) as u8);
        buf.push((adj & 0xFF) as u8);
    } else if offset < 134_744_064 {
        let adj = offset - 526_336;
        buf.push(0x30 | (((adj >> 24) as u8) & 0x07));
        buf.push(((adj >> 16) & 0xFF) as u8);
        buf.push(((adj >> 8) & 0xFF) as u8);
        buf.push((adj & 0xFF) as u8);
    } else {
        buf.push(0x38);
        buf.extend_from_slice(&offset.to_be_bytes());
    }
}

// ============================================================================
// High-Level MMDB Artifact Writers
// ============================================================================

#[derive(Clone, Debug)]
pub struct MmdbWriteStats {
    pub path: std::path::PathBuf,
    pub size_bytes: u64,
    pub node_count: u32,
    pub record_size: u16,
    pub unique_records: usize,
}

#[allow(clippy::too_many_arguments)]
pub fn write_geo_mmdb(
    path: &Path,
    database_type: &str,
    description_en: &str,
    description_zh: &str,
    build_epoch: u64,
    records: &IndexSet<ResolvedGeoRecord, FxBuildHasher>,
    v4_spans: &[OutputSpanV4<u32>],
    v6_spans: &[OutputSpanV6<u32>],
    strings: &StringPool,
    metadata: &MetadataRegistry,
) -> Result<MmdbWriteStats> {
    // Only encode records actually referenced by `v4_spans` or `v6_spans`!
    let mut used_map: FxHashMap<u32, u32> = FxHashMap::default();
    let mut compact_records: Vec<&ResolvedGeoRecord> = Vec::new();

    let remap_v4: Vec<OutputSpanV4<u32>> = v4_spans
        .iter()
        .map(|s| {
            let new_id = *used_map.entry(s.record_id).or_insert_with(|| {
                let id = compact_records.len() as u32;
                compact_records.push(&records[s.record_id as usize]);
                id
            });
            OutputSpanV4 {
                start: s.start,
                end: s.end,
                record_id: new_id,
            }
        })
        .collect();

    let remap_v6: Vec<OutputSpanV6<u32>> = v6_spans
        .iter()
        .map(|s| {
            let new_id = *used_map.entry(s.record_id).or_insert_with(|| {
                let id = compact_records.len() as u32;
                compact_records.push(&records[s.record_id as usize]);
                id
            });
            OutputSpanV6 {
                start: s.start,
                end: s.end,
                record_id: new_id,
            }
        })
        .collect();

    let tree_nodes = build_dual_stack_tree(&remap_v4, &remap_v6);
    let mut enc = DataEncoder::new();

    // Pre-build `continent` and `country` maps per ISO so all records share pointers
    let mut iso_country_vals: FxHashMap<IsoCode, (ValId, ValId)> = FxHashMap::default();
    for (&iso, cm) in &metadata.countries {
        let cont_name_entries = vec![
            ("en", enc.str_val(&cm.continent_en)),
            ("zh-CN", enc.str_val(&cm.continent_zh)),
        ];
        let cont_names = enc.map_val(cont_name_entries);
        let cont_entries = vec![
            ("code", enc.str_val(&cm.continent_code)),
            ("geoname_id", enc.u32_val(cm.continent_geoname_id)),
            ("names", cont_names),
        ];
        let cont_map = enc.map_val(cont_entries);

        let c_name_entries = vec![
            ("en", enc.str_val(&cm.name_en)),
            ("zh-CN", enc.str_val(&cm.name_zh)),
        ];
        let c_names = enc.map_val(c_name_entries);
        let mut c_entries = vec![
            ("geoname_id", enc.u32_val(cm.geoname_id)),
            ("iso_code", enc.str_val(iso.as_str())),
            ("names", c_names),
        ];
        if cm.is_eu {
            c_entries.push(("is_in_european_union", enc.bool_val(true)));
        }
        let country_map = enc.map_val(c_entries);
        iso_country_vals.insert(iso, (cont_map, country_map));
    }

    let mut root_ids = Vec::with_capacity(compact_records.len());
    for rec in &compact_records {
        root_ids.push(build_geo_record_val(
            &mut enc,
            rec,
            strings,
            &iso_country_vals,
        ));
    }

    enc.pre_emit_hot_nodes(
        &root_ids,
        &[
            "names",
            "zh-CN",
            "continent",
            "country",
            "registered_country",
            "represented_country",
            "subdivisions",
            "city",
            "postal",
            "location",
            "traits",
            "asn",
            "geoname_id",
            "iso_code",
            "code",
            "is_in_european_union",
            "latitude",
            "longitude",
            "time_zone",
            "accuracy_radius",
            "metro_code",
            "autonomous_system_number",
            "autonomous_system_organization",
            "number",
            "organization",
            "domain",
            "isp",
            "connection_type",
            "user_type",
            "network_type",
            "virtual_network",
            "is_anycast",
            "is_anonymous_proxy",
            "is_anonymous_vpn",
            "is_vpn",
            "is_tor_exit_node",
            "is_hosting_provider",
            "is_cdn",
            "is_satellite_provider",
            "is_icloud_relay",
            "is_crawler",
            "is_bogon",
            "is_private",
            "is_virtual_mesh",
            "is_malware",
        ],
    );

    let mut rec_offsets = Vec::with_capacity(root_ids.len());
    for val_id in root_ids {
        rec_offsets.push(enc.emit_top_level_record(val_id));
    }

    finalize_mmdb_file(
        path,
        database_type,
        description_en,
        Some(description_zh),
        &["en", "zh-CN"],
        build_epoch,
        &tree_nodes,
        &rec_offsets,
        &enc.buf,
        compact_records.len(),
    )
}

pub fn write_asn_mmdb(
    path: &Path,
    build_epoch: u64,
    records: &IndexSet<ResolvedAsnRecord, FxBuildHasher>,
    v4_spans: &[OutputSpanV4<u32>],
    v6_spans: &[OutputSpanV6<u32>],
    strings: &StringPool,
) -> Result<MmdbWriteStats> {
    let mut used_map: FxHashMap<u32, u32> = FxHashMap::default();
    let mut compact_records: Vec<ResolvedAsnRecord> = Vec::new();

    let remap_v4: Vec<OutputSpanV4<u32>> = v4_spans
        .iter()
        .map(|s| {
            let new_id = *used_map.entry(s.record_id).or_insert_with(|| {
                let id = compact_records.len() as u32;
                compact_records.push(records[s.record_id as usize]);
                id
            });
            OutputSpanV4 {
                start: s.start,
                end: s.end,
                record_id: new_id,
            }
        })
        .collect();

    let remap_v6: Vec<OutputSpanV6<u32>> = v6_spans
        .iter()
        .map(|s| {
            let new_id = *used_map.entry(s.record_id).or_insert_with(|| {
                let id = compact_records.len() as u32;
                compact_records.push(records[s.record_id as usize]);
                id
            });
            OutputSpanV6 {
                start: s.start,
                end: s.end,
                record_id: new_id,
            }
        })
        .collect();

    let tree_nodes = build_dual_stack_tree(&remap_v4, &remap_v6);
    let mut enc = DataEncoder::new();
    let mut root_ids = Vec::with_capacity(compact_records.len());

    for rec in &compact_records {
        let mut entries = vec![("autonomous_system_number", enc.u32_val(rec.asn))];
        let org_s = strings.get(rec.as_org);
        if !org_s.is_empty() {
            entries.push(("autonomous_system_organization", enc.str_val(org_s)));
        }
        let dom_s = strings.get(rec.as_domain);
        if !dom_s.is_empty() {
            entries.push(("as_domain", enc.str_val(dom_s)));
        }
        root_ids.push(enc.map_val(entries));
    }

    enc.pre_emit_hot_nodes(
        &root_ids,
        &[
            "autonomous_system_number",
            "autonomous_system_organization",
            "as_domain",
        ],
    );

    let mut rec_offsets = Vec::with_capacity(root_ids.len());
    for map_id in root_ids {
        rec_offsets.push(enc.emit_top_level_record(map_id));
    }

    finalize_mmdb_file(
        path,
        "GeoLite2-ASN",
        "Surge Multi-Source BGP & RIR Autonomous System Database",
        None,
        &["en"],
        build_epoch,
        &tree_nodes,
        &rec_offsets,
        &enc.buf,
        compact_records.len(),
    )
}

fn build_geo_record_val(
    enc: &mut DataEncoder,
    rec: &ResolvedGeoRecord,
    strings: &StringPool,
    iso_country_vals: &FxHashMap<IsoCode, (ValId, ValId)>,
) -> ValId {
    let mut root: Vec<(&str, ValId)> = Vec::with_capacity(12);

    if let Some(c_iso) = rec.country
        && let Some(&(cont_val, country_val)) = iso_country_vals.get(&c_iso)
    {
        root.push(("continent", cont_val));
        root.push(("country", country_val));
    }
    if let Some(rc_iso) = rec.registered_country
        && let Some(&(_, rc_val)) = iso_country_vals.get(&rc_iso)
    {
        root.push(("registered_country", rc_val));
    }
    if let Some(rep_iso) = rec.represented_country
        && let Some(&(_, rep_val)) = iso_country_vals.get(&rep_iso)
    {
        root.push(("represented_country", rep_val));
    }

    // Subdivisions
    let mut subs: Vec<ValId> = Vec::new();
    if let Some(s1) = build_subdivision_val(
        enc,
        strings,
        rec.subdiv1_iso,
        rec.subdiv1_en,
        rec.subdiv1_zh,
        rec.subdiv1_geoname_id,
    ) {
        subs.push(s1);
    }
    if let Some(s2) = build_subdivision_val(
        enc,
        strings,
        rec.subdiv2_iso,
        rec.subdiv2_en,
        rec.subdiv2_zh,
        0,
    ) {
        subs.push(s2);
    }
    if !subs.is_empty() {
        root.push(("subdivisions", enc.array_val(subs)));
    }

    // City
    let city_en = strings.get(rec.city_en);
    let city_zh = strings.get(rec.city_zh);
    if !city_en.is_empty() || !city_zh.is_empty() {
        let mut names = Vec::with_capacity(2);
        if !city_en.is_empty() {
            names.push(("en", enc.str_val(city_en)));
        }
        if !city_zh.is_empty() {
            names.push(("zh-CN", enc.str_val(city_zh)));
        }
        let mut c_map = vec![("names", enc.map_val(names))];
        if rec.city_geoname_id != 0 {
            c_map.push(("geoname_id", enc.u32_val(rec.city_geoname_id)));
        }
        root.push(("city", enc.map_val(c_map)));
    }

    // Postal
    let postal_s = strings.get(rec.postal_code);
    if !postal_s.is_empty() {
        let p_val = enc.str_val(postal_s);
        root.push(("postal", enc.map_val(vec![("code", p_val)])));
    }

    // Location
    let tz_s = strings.get(rec.time_zone);
    let has_coords = rec.latitude_e5 != COORD_UNSET && rec.longitude_e5 != COORD_UNSET;
    if has_coords || !tz_s.is_empty() || rec.accuracy_radius != 0 || rec.metro_code != 0 {
        let mut loc = Vec::with_capacity(5);
        if has_coords
            && let (Some(lat), Some(lon)) = (
                dequantize_coord(rec.latitude_e5),
                dequantize_coord(rec.longitude_e5),
            )
        {
            loc.push(("latitude", enc.f64_val(lat)));
            loc.push(("longitude", enc.f64_val(lon)));
        }
        if !tz_s.is_empty() {
            loc.push(("time_zone", enc.str_val(tz_s)));
        }
        if rec.accuracy_radius != 0 {
            loc.push(("accuracy_radius", enc.u16_val(rec.accuracy_radius)));
        }
        if rec.metro_code != 0 {
            loc.push(("metro_code", enc.u16_val(rec.metro_code)));
        }
        if !loc.is_empty() {
            root.push(("location", enc.map_val(loc)));
        }
    }

    // ASN (both top-level GeoLite2-ASN keys + structured `asn` object)
    let as_org_s = strings.get(rec.as_org);
    let as_dom_s = strings.get(rec.as_domain);
    if rec.asn != 0 {
        let asn_u = enc.u32_val(rec.asn);
        root.push(("autonomous_system_number", asn_u));
        let mut asn_obj = vec![("number", asn_u)];
        if !as_org_s.is_empty() {
            let o_val = enc.str_val(as_org_s);
            root.push(("autonomous_system_organization", o_val));
            asn_obj.push(("organization", o_val));
        }
        if !as_dom_s.is_empty() {
            asn_obj.push(("domain", enc.str_val(as_dom_s)));
        }
        root.push(("asn", enc.map_val(asn_obj)));
    }

    // Rich Traits
    let mut tr: Vec<(&str, ValId)> = Vec::new();
    let isp_s = strings.get(rec.isp);
    let org_s = strings.get(rec.organization);
    let sp_net_s = strings.get(rec.special_network_type);
    let vnet_s = strings.get(rec.virtual_network);

    if !isp_s.is_empty() {
        tr.push(("isp", enc.str_val(isp_s)));
    }
    if !org_s.is_empty() {
        tr.push(("organization", enc.str_val(org_s)));
    }
    if !as_dom_s.is_empty() {
        tr.push(("domain", enc.str_val(as_dom_s)));
    }
    if !sp_net_s.is_empty() {
        tr.push(("network_type", enc.str_val(sp_net_s)));
    }
    if !vnet_s.is_empty() {
        tr.push(("virtual_network", enc.str_val(vnet_s)));
    }
    if rec.asn != 0 {
        tr.push(("autonomous_system_number", enc.u32_val(rec.asn)));
        if !as_org_s.is_empty() {
            tr.push(("autonomous_system_organization", enc.str_val(as_org_s)));
        }
    }

    // Derived `connection_type` & `user_type`
    if rec.traits.contains(TraitFlags::IS_VIRTUAL_MESH) {
        tr.push(("connection_type", enc.str_val("Virtual Mesh")));
    } else if rec.traits.contains(TraitFlags::IS_SATELLITE) {
        tr.push(("connection_type", enc.str_val("Satellite")));
        tr.push(("user_type", enc.str_val("satellite")));
    } else if rec.traits.contains(TraitFlags::IS_CDN) {
        tr.push(("user_type", enc.str_val("content_delivery_network")));
    } else if rec.traits.contains(TraitFlags::IS_HOSTING) {
        tr.push(("user_type", enc.str_val("hosting")));
    } else if rec.traits.contains(TraitFlags::IS_TOR_EXIT)
        || rec.traits.contains(TraitFlags::IS_VPN)
        || rec.traits.contains(TraitFlags::IS_ANONYMOUS_PROXY)
        || rec.traits.contains(TraitFlags::IS_ICLOUD_RELAY)
    {
        tr.push(("user_type", enc.str_val("anonymizer")));
    } else if matches!(isp_s, "CERNET" | "CSTNET") {
        tr.push(("user_type", enc.str_val("college")));
    }

    let t_true = enc.bool_val(true);
    for (bit, key) in [
        (TraitFlags::IS_ANYCAST, "is_anycast"),
        (TraitFlags::IS_ANONYMOUS_PROXY, "is_anonymous_proxy"),
        (TraitFlags::IS_VPN, "is_anonymous_vpn"),
        (TraitFlags::IS_VPN, "is_vpn"),
        (TraitFlags::IS_TOR_EXIT, "is_tor_exit_node"),
        (TraitFlags::IS_HOSTING, "is_hosting_provider"),
        (TraitFlags::IS_CDN, "is_cdn"),
        (TraitFlags::IS_SATELLITE, "is_satellite_provider"),
        (TraitFlags::IS_ICLOUD_RELAY, "is_icloud_relay"),
        (TraitFlags::IS_CRAWLER, "is_crawler"),
        (TraitFlags::IS_BOGON, "is_bogon"),
        (TraitFlags::IS_PRIVATE, "is_private"),
        (TraitFlags::IS_VIRTUAL_MESH, "is_virtual_mesh"),
        (TraitFlags::IS_MALWARE, "is_malware"),
    ] {
        if rec.traits.contains(bit) {
            tr.push((key, t_true));
        }
    }

    if !tr.is_empty() {
        root.push(("traits", enc.map_val(tr)));
    }

    enc.map_val(root)
}

fn build_subdivision_val(
    enc: &mut DataEncoder,
    strings: &StringPool,
    iso_id: StrId,
    en_id: StrId,
    zh_id: StrId,
    geoname_id: u32,
) -> Option<ValId> {
    let iso_s = strings.get(iso_id);
    let en_s = strings.get(en_id);
    let zh_s = strings.get(zh_id);
    if iso_s.is_empty() && en_s.is_empty() && zh_s.is_empty() {
        return None;
    }
    let mut sub = Vec::with_capacity(3);
    if !iso_s.is_empty() {
        sub.push(("iso_code", enc.str_val(iso_s)));
    }
    if geoname_id != 0 {
        sub.push(("geoname_id", enc.u32_val(geoname_id)));
    }
    if !en_s.is_empty() || !zh_s.is_empty() {
        let mut names = Vec::with_capacity(2);
        if !en_s.is_empty() {
            names.push(("en", enc.str_val(en_s)));
        }
        if !zh_s.is_empty() {
            names.push(("zh-CN", enc.str_val(zh_s)));
        }
        sub.push(("names", enc.map_val(names)));
    }
    Some(enc.map_val(sub))
}

#[allow(clippy::too_many_arguments)]
fn finalize_mmdb_file(
    path: &Path,
    database_type: &str,
    description_en: &str,
    description_zh: Option<&str>,
    languages: &[&str],
    build_epoch: u64,
    tree_nodes: &[(Edge, Edge)],
    rec_offsets: &[u32],
    data_buf: &[u8],
    unique_records: usize,
) -> Result<MmdbWriteStats> {
    let node_count = tree_nodes.len() as u64;
    if node_count == 0 || node_count > u32::MAX as u64 {
        bail!("invalid MMDB node_count {}", node_count);
    }

    let max_ptr = node_count + 16 + (data_buf.len() as u64);
    let record_size: u16 = if max_ptr < (1 << 24) {
        24
    } else if max_ptr < (1 << 28) {
        28
    } else if max_ptr < (1 << 32) {
        32
    } else {
        bail!("MMDB search tree + data section exceeds 32-bit pointer capacity");
    };

    let node_bytes = (record_size as usize * 2) / 8;
    let tree_byte_len = (node_count as usize) * node_bytes;

    // Encode metadata section (self-contained without pointers)
    let mut meta_enc = DataEncoder::new();
    let mut desc_entries = vec![("en", meta_enc.str_val(description_en))];
    if let Some(zh) = description_zh {
        desc_entries.push(("zh-CN", meta_enc.str_val(zh)));
    }
    let desc_val = meta_enc.map_val(desc_entries);
    let lang_vals: Vec<ValId> = languages.iter().map(|s| meta_enc.str_val(s)).collect();
    let lang_arr = meta_enc.array_val(lang_vals);
    let epoch_val = meta_enc.intern(DataNode::Uint64(build_epoch));

    let meta_entries = vec![
        ("binary_format_major_version", meta_enc.u16_val(2)),
        ("binary_format_minor_version", meta_enc.u16_val(0)),
        ("build_epoch", epoch_val),
        ("database_type", meta_enc.str_val(database_type)),
        ("description", desc_val),
        ("ip_version", meta_enc.u16_val(6)),
        ("languages", lang_arr),
        ("node_count", meta_enc.u32_val(node_count as u32)),
        ("record_size", meta_enc.u16_val(record_size)),
    ];
    let meta_root = meta_enc.map_val(meta_entries);
    // Serialize metadata map completely pointer-free
    let _ = meta_enc.emit_value(meta_root, false, false);

    let total_size =
        tree_byte_len + 16 + data_buf.len() + METADATA_MARKER.len() + meta_enc.buf.len();
    let mut out = Vec::with_capacity(total_size);

    let resolve_edge = |edge: Edge| -> u32 {
        match edge {
            Edge::Empty => node_count as u32,
            Edge::Node(idx) => idx,
            Edge::Record(rid) => (node_count as u32) + 16 + rec_offsets[rid as usize],
        }
    };

    for &(l_edge, r_edge) in tree_nodes {
        let l = resolve_edge(l_edge);
        let r = resolve_edge(r_edge);
        match record_size {
            24 => {
                out.push(((l >> 16) & 0xFF) as u8);
                out.push(((l >> 8) & 0xFF) as u8);
                out.push((l & 0xFF) as u8);
                out.push(((r >> 16) & 0xFF) as u8);
                out.push(((r >> 8) & 0xFF) as u8);
                out.push((r & 0xFF) as u8);
            }
            28 => {
                out.push(((l >> 16) & 0xFF) as u8);
                out.push(((l >> 8) & 0xFF) as u8);
                out.push((l & 0xFF) as u8);
                out.push(((((l >> 24) & 0x0F) << 4) | ((r >> 24) & 0x0F)) as u8);
                out.push(((r >> 16) & 0xFF) as u8);
                out.push(((r >> 8) & 0xFF) as u8);
                out.push((r & 0xFF) as u8);
            }
            32 => {
                out.extend_from_slice(&l.to_be_bytes());
                out.extend_from_slice(&r.to_be_bytes());
            }
            _ => unreachable!(),
        }
    }

    // 16-byte NUL separator
    out.extend_from_slice(&[0u8; 16]);
    // Data section
    out.extend_from_slice(data_buf);
    // Metadata marker + Metadata map
    out.extend_from_slice(METADATA_MARKER);
    out.extend_from_slice(&meta_enc.buf);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating parent dir {}", parent.display()))?;
    }
    let tmp = path.with_extension("mmdb.tmp");
    fs::write(&tmp, &out).with_context(|| format!("failed writing {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("failed renaming {} -> {}", tmp.display(), path.display()))?;

    Ok(MmdbWriteStats {
        path: path.to_path_buf(),
        size_bytes: out.len() as u64,
        node_count: node_count as u32,
        record_size,
        unique_records,
    })
}
