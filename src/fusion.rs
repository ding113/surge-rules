use std::cmp::Reverse;
use std::collections::BinaryHeap;

use ipnet::{Ipv4Net, Ipv6Net};
use rayon::prelude::*;
use rustc_hash::FxHashMap;

use crate::config::{MetadataRegistry, SourceConfig, SourceTier};
use crate::model::{
    AsnDictionaryEntry, COORD_UNSET, GlobalArena, IntervalV4, IntervalV6, IsoCode,
    ResolvedAsnRecord, ResolvedGeoRecord, StrId, TraitFlags, range_to_ipv4_cidrs,
    range_to_ipv6_cidrs,
};
use crate::overrides::CompiledOverrides;

#[derive(Clone, Debug)]
pub struct SourceMetaRuntime {
    pub id: String,
    pub tier: SourceTier,
    pub lineage_id: u16,
    pub country_weight: u16,
    pub cn_weight: u16,
    pub city_weight: u16,
    pub isp_weight: u16,
    pub asn_weight: u16,
    pub registered_country_weight: u16,
}

pub struct PreparedSourceIntervals {
    pub meta: SourceMetaRuntime,
    pub v4: Vec<IntervalV4>,
    pub v6: Vec<IntervalV6>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OutputSpanV4<Id> {
    pub start: u32,
    pub end: u32,
    pub record_id: Id,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OutputSpanV6<Id> {
    pub start: u128,
    pub end: u128,
    pub record_id: Id,
}

pub struct FusionResult {
    pub country_records: indexmap::IndexSet<ResolvedGeoRecord, rustc_hash::FxBuildHasher>,
    pub country_v4: Vec<OutputSpanV4<u32>>,
    pub country_v6: Vec<OutputSpanV6<u32>>,

    pub cn_v4: Vec<OutputSpanV4<u32>>,
    pub cn_v6: Vec<OutputSpanV6<u32>>,

    pub asn_records: indexmap::IndexSet<ResolvedAsnRecord, rustc_hash::FxBuildHasher>,
    pub asn_v4: Vec<OutputSpanV4<u32>>,
    pub asn_v6: Vec<OutputSpanV6<u32>>,
}

impl FusionResult {
    pub fn country_v4_cidr_count(&self) -> usize {
        self.country_v4
            .iter()
            .map(|s| range_to_ipv4_cidrs(s.start, s.end).len())
            .sum()
    }

    pub fn country_v6_cidr_count(&self) -> usize {
        self.country_v6
            .iter()
            .map(|s| range_to_ipv6_cidrs(s.start, s.end).len())
            .sum()
    }

    pub fn cn_v4_cidr_count(&self) -> usize {
        self.cn_v4
            .iter()
            .map(|s| range_to_ipv4_cidrs(s.start, s.end).len())
            .sum()
    }

    pub fn cn_v6_cidr_count(&self) -> usize {
        self.cn_v6
            .iter()
            .map(|s| range_to_ipv6_cidrs(s.start, s.end).len())
            .sum()
    }
}

/// Flattens overlapping/nested IPv4 intervals into strictly disjoint ascending intervals,
/// selecting the highest `prefix_len` (ties broken by later index) in O(N log D).
pub fn flatten_disjoint_v4(mut input: Vec<IntervalV4>) -> Vec<IntervalV4> {
    if input.len() <= 1 {
        return input;
    }
    input.sort_unstable_by_key(|iv| (iv.start, Reverse(iv.prefix_len()), iv.end));

    // Fast path if already disjoint
    if input.windows(2).all(|w| w[0].end < w[1].start) {
        return coalesce_v4(input);
    }

    let mut out: Vec<IntervalV4> = Vec::with_capacity(input.len());
    // Max-heap by `(prefix_len, seq_idx)`: `(prefix_len, seq_idx, end, packed)`
    let mut heap: BinaryHeap<(u8, usize, u32, u32)> = BinaryHeap::with_capacity(64);
    let mut idx = 0usize;
    let mut cur: u64 = input[0].start as u64;

    while cur <= u32::MAX as u64 {
        while let Some(&(_, _, end, _)) = heap.peek() {
            if (end as u64) < cur {
                heap.pop();
            } else {
                break;
            }
        }
        while idx < input.len() && (input[idx].start as u64) <= cur {
            let iv = input[idx];
            if (iv.end as u64) >= cur {
                heap.push((iv.prefix_len(), idx, iv.end, iv.packed));
            }
            idx += 1;
        }
        while let Some(&(_, _, end, _)) = heap.peek() {
            if (end as u64) < cur {
                heap.pop();
            } else {
                break;
            }
        }

        let Some(&(_, _, top_end, top_packed)) = heap.peek() else {
            if idx >= input.len() {
                break;
            }
            cur = input[idx].start as u64;
            continue;
        };

        let mut step_end = top_end as u64;
        if idx < input.len() {
            let next_start = input[idx].start as u64;
            if next_start > cur {
                step_end = step_end.min(next_start - 1);
            }
        }

        let s4 = cur as u32;
        let e4 = step_end as u32;
        if let Some(last) = out.last_mut()
            && last.packed == top_packed
            && last.end.saturating_add(1) == s4
        {
            last.end = e4;
        } else {
            out.push(IntervalV4 {
                start: s4,
                end: e4,
                packed: top_packed,
            });
        }

        cur = step_end + 1;
    }

    out
}

/// Flattens overlapping/nested IPv6 intervals into strictly disjoint ascending intervals.
pub fn flatten_disjoint_v6(mut input: Vec<IntervalV6>) -> Vec<IntervalV6> {
    if input.len() <= 1 {
        return input;
    }
    input.sort_unstable_by_key(|iv| (iv.start, Reverse(iv.prefix_len()), iv.end));

    if input.windows(2).all(|w| w[0].end < w[1].start) {
        return coalesce_v6(input);
    }

    let mut out: Vec<IntervalV6> = Vec::with_capacity(input.len());
    let mut heap: BinaryHeap<(u8, usize, u128, u32)> = BinaryHeap::with_capacity(64);
    let mut idx = 0usize;
    let mut cur: Option<u128> = Some(input[0].start);

    while let Some(c) = cur {
        while let Some(&(_, _, end, _)) = heap.peek() {
            if end < c {
                heap.pop();
            } else {
                break;
            }
        }
        while idx < input.len() && input[idx].start <= c {
            let iv = input[idx];
            if iv.end >= c {
                heap.push((iv.prefix_len(), idx, iv.end, iv.packed));
            }
            idx += 1;
        }
        while let Some(&(_, _, end, _)) = heap.peek() {
            if end < c {
                heap.pop();
            } else {
                break;
            }
        }

        let Some(&(_, _, top_end, top_packed)) = heap.peek() else {
            if idx >= input.len() {
                break;
            }
            cur = Some(input[idx].start);
            continue;
        };

        let mut step_end = top_end;
        if idx < input.len() {
            let next_start = input[idx].start;
            if next_start > c {
                step_end = step_end.min(next_start - 1);
            }
        }

        if let Some(last) = out.last_mut()
            && last.packed == top_packed
            && last.end.checked_add(1) == Some(c)
        {
            last.end = step_end;
        } else {
            out.push(IntervalV6 {
                start: c,
                end: step_end,
                packed: top_packed,
            });
        }

        cur = step_end.checked_add(1);
    }

    out
}

fn coalesce_v4(input: Vec<IntervalV4>) -> Vec<IntervalV4> {
    let mut out: Vec<IntervalV4> = Vec::with_capacity(input.len());
    for iv in input {
        if let Some(last) = out.last_mut()
            && last.packed == iv.packed
            && last.end.saturating_add(1) >= iv.start
        {
            last.end = last.end.max(iv.end);
        } else {
            out.push(iv);
        }
    }
    out
}

fn coalesce_v6(input: Vec<IntervalV6>) -> Vec<IntervalV6> {
    let mut out: Vec<IntervalV6> = Vec::with_capacity(input.len());
    for iv in input {
        if let Some(last) = out.last_mut()
            && last.packed == iv.packed
            && last.end.saturating_add(1) >= iv.start
        {
            last.end = last.end.max(iv.end);
        } else {
            out.push(iv);
        }
    }
    out
}

/// Prepares human ASN overrides into `arena.asn_dict` at highest authority (`u16::MAX`).
pub fn apply_asn_overrides_to_arena(
    arena: &mut GlobalArena,
    overrides: &CompiledOverrides,
    metadata: &MetadataRegistry,
) {
    for (&asn, ov) in &overrides.asn_overrides {
        let org_id = arena.strings.intern(&ov.organization);
        let isp_id = ov
            .isp
            .as_deref()
            .map_or(StrId::EMPTY, |s| arena.strings.intern(s));
        let dom_id = ov
            .domain
            .as_deref()
            .map_or(StrId::EMPTY, |s| arena.strings.intern(s));
        let prov_id = ov
            .province_hint_zh_cn
            .as_deref()
            .map_or(StrId::EMPTY, |s| arena.strings.intern(s));
        let country_hint = ov
            .country_hint
            .as_deref()
            .and_then(IsoCode::parse_raw)
            .and_then(|c| metadata.validate_iso(c));

        let mut traits = TraitFlags::EMPTY;
        let mut clear_traits = TraitFlags::EMPTY;
        match ov.is_hosting {
            Some(true) => traits.insert(TraitFlags::IS_HOSTING),
            Some(false) => clear_traits.insert(TraitFlags::IS_HOSTING),
            None => {}
        }
        match ov.is_cdn {
            Some(true) => traits.insert(TraitFlags::IS_CDN),
            Some(false) => clear_traits.insert(TraitFlags::IS_CDN),
            None => {}
        }
        match ov.is_anycast {
            Some(true) => traits.insert(TraitFlags::IS_ANYCAST),
            Some(false) => clear_traits.insert(TraitFlags::IS_ANYCAST),
            None => {}
        }

        let entry = arena.asn_dict.entry(asn).or_default();
        entry.organization = org_id;
        entry.org_weight = u16::MAX;
        if !isp_id.is_empty() {
            entry.isp = isp_id;
        }
        if !dom_id.is_empty() {
            entry.domain = dom_id;
            entry.domain_weight = u16::MAX;
        }
        if country_hint.is_some() {
            entry.country_hint = country_hint;
        }
        if !prov_id.is_empty() {
            entry.province_hint_zh = prov_id;
        }
        entry.traits = entry.traits.union(traits).without(clear_traits);
        entry.clear_traits = entry.clear_traits.union(clear_traits);
    }
}

/// Pre-interned override structures so the hot sweep-line loop performs zero string interning!
struct InternedSpecialRule {
    network_type: StrId,
    virtual_network: StrId,
    organization: StrId,
    traits: TraitFlags,
}

struct InternedCountryOverride {
    iso_code: IsoCode,
    registered_iso_code: Option<IsoCode>,
    subdiv1_iso: StrId,
    subdiv1_en: StrId,
    subdiv1_zh: StrId,
    subdiv1_geoname_id: u32,
    city_en: StrId,
    city_zh: StrId,
    city_geoname_id: u32,
    lat_e5: i32,
    lon_e5: i32,
    isp: StrId,
    organization: StrId,
    traits: TraitFlags,
    clear_city: bool,
}

struct InternedCnExclusion {
    fallback_iso_code: Option<IsoCode>,
}

struct PrecomputedCountryDefault {
    default_tz: StrId,
}

/// Runs the full dual-stack multi-source fusion sweep.
pub fn run_fusion(
    arena: &mut GlobalArena,
    metadata: &MetadataRegistry,
    overrides: &CompiledOverrides,
    sources_in: Vec<(SourceConfig, Vec<IntervalV4>, Vec<IntervalV6>)>,
) -> FusionResult {
    apply_asn_overrides_to_arena(arena, overrides, metadata);

    // Pre-intern country default timezones & CN divisions that might be referenced via ASN province hints
    let mut country_defaults: FxHashMap<IsoCode, PrecomputedCountryDefault> = FxHashMap::default();
    for (&iso, cm) in &metadata.countries {
        country_defaults.insert(
            iso,
            PrecomputedCountryDefault {
                default_tz: arena.strings.intern(&cm.default_tz),
            },
        );
    }

    let mut cn_prov_interned: FxHashMap<StrId, (StrId, StrId, StrId, u32, i32, i32)> =
        FxHashMap::default();
    for entry in arena.asn_dict.values() {
        if !entry.province_hint_zh.is_empty() {
            let p_str = arena.strings.get(entry.province_hint_zh).to_string();
            if let Some(pm) = metadata.resolve_cn_province(&p_str) {
                let iso_id = arena.strings.intern(&pm.iso_code);
                let en_id = arena.strings.intern(&pm.province_en);
                let zh_id = arena.strings.intern(&pm.province_zh);
                cn_prov_interned.insert(
                    entry.province_hint_zh,
                    (iso_id, en_id, zh_id, pm.geoname_id, pm.lat_e5, pm.lon_e5),
                );
            }
        }
    }

    // Build flattened disjoint layers for SpecialNetworks, CountryOverrides, and CnExclusions
    let (special_rules, special_v4, special_v6) =
        compile_special_layers(arena, &overrides.special_v4, &overrides.special_v6);
    let (country_ov_rules, country_ov_v4, country_ov_v6) = compile_country_override_layers(
        arena,
        metadata,
        &overrides.country_v4,
        &overrides.country_v6,
    );
    let (cn_excl_rules, cn_excl_v4, cn_excl_v6) =
        compile_cn_excl_layers(&overrides.cn_excl_v4, &overrides.cn_excl_v6);

    // Assign numeric `lineage_id`s
    let mut lineage_map: FxHashMap<String, u16> = FxHashMap::default();
    let mut next_lineage_id = 1u16;
    let mut meta_list = Vec::with_capacity(sources_in.len());
    let mut raw_vecs = Vec::with_capacity(sources_in.len());

    for (cfg, v4, v6) in sources_in {
        let lid = *lineage_map.entry(cfg.lineage.clone()).or_insert_with(|| {
            let id = next_lineage_id;
            next_lineage_id += 1;
            id
        });
        meta_list.push(SourceMetaRuntime {
            id: cfg.id,
            tier: cfg.tier,
            lineage_id: lid,
            country_weight: cfg.country_weight,
            cn_weight: cfg.cn_weight,
            city_weight: cfg.city_weight,
            isp_weight: cfg.isp_weight,
            asn_weight: cfg.asn_weight,
            registered_country_weight: cfg.registered_country_weight,
        });
        raw_vecs.push((v4, v6));
    }

    // Flatten each source's IPv4 and IPv6 intervals in parallel via Rayon
    let flattened: Vec<(Vec<IntervalV4>, Vec<IntervalV6>)> = raw_vecs
        .into_par_iter()
        .map(|(v4, v6)| (flatten_disjoint_v4(v4), flatten_disjoint_v6(v6)))
        .collect();

    let prepared: Vec<PreparedSourceIntervals> = meta_list
        .into_iter()
        .zip(flattened)
        .map(|(meta, (v4, v6))| PreparedSourceIntervals { meta, v4, v6 })
        .collect();

    let ctx = SweepContext {
        arena,
        country_defaults: &country_defaults,
        cn_prov_interned: &cn_prov_interned,
        special_rules: &special_rules,
        country_ov_rules: &country_ov_rules,
        cn_excl_rules: &cn_excl_rules,
        sources: &prepared,
        num_lineages: next_lineage_id as usize,
    };

    // Sweep IPv4 and IPv6 in parallel!
    let (v4_out, v6_out) = rayon::join(
        || sweep_v4(&ctx, &special_v4, &country_ov_v4, &cn_excl_v4),
        || sweep_v6(&ctx, &special_v6, &country_ov_v6, &cn_excl_v6),
    );

    // Unify record interning tables across IPv4 and IPv6
    let mut country_records = indexmap::IndexSet::with_capacity_and_hasher(
        v4_out.geo_set.len() + v6_out.geo_set.len(),
        rustc_hash::FxBuildHasher,
    );
    let mut asn_records = indexmap::IndexSet::with_capacity_and_hasher(
        v4_out.asn_set.len() + v6_out.asn_set.len(),
        rustc_hash::FxBuildHasher,
    );

    let v4_geo_map: Vec<u32> = v4_out
        .geo_set
        .into_iter()
        .map(|r| country_records.insert_full(r).0 as u32)
        .collect();
    let v6_geo_map: Vec<u32> = v6_out
        .geo_set
        .into_iter()
        .map(|r| country_records.insert_full(r).0 as u32)
        .collect();

    let v4_asn_map: Vec<u32> = v4_out
        .asn_set
        .into_iter()
        .map(|r| asn_records.insert_full(r).0 as u32)
        .collect();
    let v6_asn_map: Vec<u32> = v6_out
        .asn_set
        .into_iter()
        .map(|r| asn_records.insert_full(r).0 as u32)
        .collect();

    let remap_v4 = |spans: Vec<OutputSpanV4<u32>>, map: &[u32]| -> Vec<OutputSpanV4<u32>> {
        spans
            .into_iter()
            .map(|s| OutputSpanV4 {
                start: s.start,
                end: s.end,
                record_id: map[s.record_id as usize],
            })
            .collect()
    };
    let remap_v6 = |spans: Vec<OutputSpanV6<u32>>, map: &[u32]| -> Vec<OutputSpanV6<u32>> {
        spans
            .into_iter()
            .map(|s| OutputSpanV6 {
                start: s.start,
                end: s.end,
                record_id: map[s.record_id as usize],
            })
            .collect()
    };

    FusionResult {
        country_v4: remap_v4(v4_out.country_spans, &v4_geo_map),
        country_v6: remap_v6(v6_out.country_spans, &v6_geo_map),
        cn_v4: remap_v4(v4_out.cn_spans, &v4_geo_map),
        cn_v6: remap_v6(v6_out.cn_spans, &v6_geo_map),
        asn_v4: remap_v4(v4_out.asn_spans, &v4_asn_map),
        asn_v6: remap_v6(v6_out.asn_spans, &v6_asn_map),
        country_records,
        asn_records,
    }
}

fn compile_special_layers(
    arena: &mut GlobalArena,
    v4_in: &[(Ipv4Net, crate::overrides::SpecialNetworkRule)],
    v6_in: &[(Ipv6Net, crate::overrides::SpecialNetworkRule)],
) -> (Vec<InternedSpecialRule>, Vec<IntervalV4>, Vec<IntervalV6>) {
    let mut rules = Vec::with_capacity(v4_in.len() + v6_in.len());
    let mut v4 = Vec::with_capacity(v4_in.len());
    let mut v6 = Vec::with_capacity(v6_in.len());

    for (net, r) in v4_in {
        let rid = rules.len() as u32;
        rules.push(InternedSpecialRule {
            network_type: arena.strings.intern(&r.network_type),
            virtual_network: r
                .virtual_network
                .as_deref()
                .map_or(StrId::EMPTY, |s| arena.strings.intern(s)),
            organization: arena.strings.intern(&r.organization),
            traits: r.traits,
        });
        v4.push(IntervalV4::new(
            u32::from(net.network()),
            u32::from(net.broadcast()),
            rid,
            r.prefix_len,
        ));
    }
    for (net, r) in v6_in {
        let rid = rules.len() as u32;
        rules.push(InternedSpecialRule {
            network_type: arena.strings.intern(&r.network_type),
            virtual_network: r
                .virtual_network
                .as_deref()
                .map_or(StrId::EMPTY, |s| arena.strings.intern(s)),
            organization: arena.strings.intern(&r.organization),
            traits: r.traits,
        });
        v6.push(IntervalV6::new(
            u128::from(net.network()),
            u128::from(net.broadcast()),
            rid,
            r.prefix_len,
        ));
    }

    (rules, flatten_disjoint_v4(v4), flatten_disjoint_v6(v6))
}

fn compile_country_override_layers(
    arena: &mut GlobalArena,
    metadata: &MetadataRegistry,
    v4_in: &[(Ipv4Net, crate::overrides::CountryOverrideRule)],
    v6_in: &[(Ipv6Net, crate::overrides::CountryOverrideRule)],
) -> (
    Vec<InternedCountryOverride>,
    Vec<IntervalV4>,
    Vec<IntervalV6>,
) {
    let mut rules = Vec::with_capacity(v4_in.len() + v6_in.len());
    let mut v4 = Vec::with_capacity(v4_in.len());
    let mut v6 = Vec::with_capacity(v6_in.len());

    let mut intern_one = |r: &crate::overrides::CountryOverrideRule| -> u32 {
        let rid = rules.len() as u32;
        let mut subdiv1_iso = r
            .subdivision_iso_code
            .as_deref()
            .map_or(StrId::EMPTY, |s| arena.strings.intern(s));
        let mut subdiv1_en = StrId::EMPTY;
        let mut subdiv1_zh = StrId::EMPTY;
        let mut subdiv1_geoname_id = 0;
        let mut city_en = r
            .city_en
            .as_deref()
            .map_or(StrId::EMPTY, |s| arena.strings.intern(s));
        let mut city_zh = r
            .city_zh_cn
            .as_deref()
            .map_or(StrId::EMPTY, |s| arena.strings.intern(s));
        let mut city_geoname_id = 0;
        let mut lat_e5 = COORD_UNSET;
        let mut lon_e5 = COORD_UNSET;

        if r.iso_code == IsoCode::CN {
            let (prov, cm) = metadata.resolve_cn_division(
                r.subdivision_iso_code.as_deref().unwrap_or(""),
                r.city_zh_cn
                    .as_deref()
                    .or(r.city_en.as_deref())
                    .unwrap_or(""),
            );
            if let Some(pm) = prov {
                subdiv1_iso = arena.strings.intern(&pm.iso_code);
                subdiv1_en = arena.strings.intern(&pm.province_en);
                subdiv1_zh = arena.strings.intern(&pm.province_zh);
                subdiv1_geoname_id = pm.geoname_id;
                lat_e5 = pm.lat_e5;
                lon_e5 = pm.lon_e5;
            }
            if let Some(c_meta) = cm {
                city_en = arena.strings.intern(&c_meta.city_en);
                city_zh = arena.strings.intern(&c_meta.city_zh);
                city_geoname_id = c_meta.geoname_id;
                lat_e5 = c_meta.lat_e5;
                lon_e5 = c_meta.lon_e5;
            }
        }

        let mut traits = TraitFlags::EMPTY;
        if r.is_anycast {
            traits.insert(TraitFlags::IS_ANYCAST);
        }

        rules.push(InternedCountryOverride {
            iso_code: r.iso_code,
            registered_iso_code: r.registered_iso_code,
            subdiv1_iso,
            subdiv1_en,
            subdiv1_zh,
            subdiv1_geoname_id,
            city_en,
            city_zh,
            city_geoname_id,
            lat_e5,
            lon_e5,
            isp: r
                .isp
                .as_deref()
                .map_or(StrId::EMPTY, |s| arena.strings.intern(s)),
            organization: r
                .organization
                .as_deref()
                .map_or(StrId::EMPTY, |s| arena.strings.intern(s)),
            traits,
            clear_city: r.clear_city,
        });
        rid
    };

    for (net, r) in v4_in {
        let rid = intern_one(r);
        v4.push(IntervalV4::new(
            u32::from(net.network()),
            u32::from(net.broadcast()),
            rid,
            r.prefix_len,
        ));
    }
    for (net, r) in v6_in {
        let rid = intern_one(r);
        v6.push(IntervalV6::new(
            u128::from(net.network()),
            u128::from(net.broadcast()),
            rid,
            r.prefix_len,
        ));
    }

    (rules, flatten_disjoint_v4(v4), flatten_disjoint_v6(v6))
}

fn compile_cn_excl_layers(
    v4_in: &[(Ipv4Net, crate::overrides::CnExclusionRule)],
    v6_in: &[(Ipv6Net, crate::overrides::CnExclusionRule)],
) -> (Vec<InternedCnExclusion>, Vec<IntervalV4>, Vec<IntervalV6>) {
    let mut rules = Vec::with_capacity(v4_in.len() + v6_in.len());
    let mut v4 = Vec::with_capacity(v4_in.len());
    let mut v6 = Vec::with_capacity(v6_in.len());

    for (net, r) in v4_in {
        let rid = rules.len() as u32;
        rules.push(InternedCnExclusion {
            fallback_iso_code: r.fallback_iso_code,
        });
        v4.push(IntervalV4::new(
            u32::from(net.network()),
            u32::from(net.broadcast()),
            rid,
            r.prefix_len,
        ));
    }
    for (net, r) in v6_in {
        let rid = rules.len() as u32;
        rules.push(InternedCnExclusion {
            fallback_iso_code: r.fallback_iso_code,
        });
        v6.push(IntervalV6::new(
            u128::from(net.network()),
            u128::from(net.broadcast()),
            rid,
            r.prefix_len,
        ));
    }

    (rules, flatten_disjoint_v4(v4), flatten_disjoint_v6(v6))
}

struct SweepContext<'a> {
    arena: &'a GlobalArena,
    country_defaults: &'a FxHashMap<IsoCode, PrecomputedCountryDefault>,
    cn_prov_interned: &'a FxHashMap<StrId, (StrId, StrId, StrId, u32, i32, i32)>,
    special_rules: &'a [InternedSpecialRule],
    country_ov_rules: &'a [InternedCountryOverride],
    cn_excl_rules: &'a [InternedCnExclusion],
    sources: &'a [PreparedSourceIntervals],
    num_lineages: usize,
}

struct FamilySweepOutput<SpanGeo, SpanAsn> {
    geo_set: indexmap::IndexSet<ResolvedGeoRecord, rustc_hash::FxBuildHasher>,
    asn_set: indexmap::IndexSet<ResolvedAsnRecord, rustc_hash::FxBuildHasher>,
    country_spans: Vec<SpanGeo>,
    cn_spans: Vec<SpanGeo>,
    asn_spans: Vec<SpanAsn>,
}

/// Reusable scratch buffers to keep the inner sweep loop 100% allocation-free!
struct ResolverScratch {
    active_obs: Vec<(usize, u32, u8)>, // (source_idx, payload_id, prefix_len)
    lineage_country_best: Vec<Option<(IsoCode, SourceTier, u16, u8)>>,
    lineage_asn_best: Vec<Option<(u32, u16, u8)>>,
    country_scores: Vec<(IsoCode, u32, u8)>, // (iso, weighted_score, distinct_lineages)
    tier1_scores: Vec<(IsoCode, u32)>,
    asn_scores: Vec<(u32, u32, u8)>, // (asn, total_weight, max_prefix_len)
}

impl ResolverScratch {
    fn new(num_sources: usize, num_lineages: usize) -> Self {
        Self {
            active_obs: Vec::with_capacity(num_sources),
            lineage_country_best: vec![None; num_lineages + 1],
            lineage_asn_best: vec![None; num_lineages + 1],
            country_scores: Vec::with_capacity(16),
            tier1_scores: Vec::with_capacity(8),
            asn_scores: Vec::with_capacity(8),
        }
    }
}

fn sweep_v4(
    ctx: &SweepContext<'_>,
    special_v4: &[IntervalV4],
    country_ov_v4: &[IntervalV4],
    cn_excl_v4: &[IntervalV4],
) -> FamilySweepOutput<OutputSpanV4<u32>, OutputSpanV4<u32>> {
    let k = ctx.sources.len();
    let mut cursors = vec![0usize; k];
    let mut sp_cur = 0usize;
    let mut cov_cur = 0usize;
    let mut cne_cur = 0usize;

    let mut scratch = ResolverScratch::new(k, ctx.num_lineages);
    let mut geo_set =
        indexmap::IndexSet::with_capacity_and_hasher(65536, rustc_hash::FxBuildHasher);
    let mut asn_set =
        indexmap::IndexSet::with_capacity_and_hasher(65536, rustc_hash::FxBuildHasher);
    let mut country_spans: Vec<OutputSpanV4<u32>> = Vec::with_capacity(524_288);
    let mut cn_spans: Vec<OutputSpanV4<u32>> = Vec::with_capacity(32_768);
    let mut asn_spans: Vec<OutputSpanV4<u32>> = Vec::with_capacity(524_288);

    let mut cur: u64 = 0;
    while cur <= u32::MAX as u64 {
        let cur32 = cur as u32;
        let mut step_end: u64 = u32::MAX as u64;
        let mut any_covering = false;

        // 1. Check Priority-0 Special Networks
        while sp_cur < special_v4.len() && special_v4[sp_cur].end < cur32 {
            sp_cur += 1;
        }
        let active_special = if sp_cur < special_v4.len() {
            let iv = special_v4[sp_cur];
            if iv.start <= cur32 {
                any_covering = true;
                step_end = step_end.min(iv.end as u64);
                Some(iv.payload_id() as usize)
            } else {
                step_end = step_end.min((iv.start as u64) - 1);
                None
            }
        } else {
            None
        };

        // If Priority-0 special network is active, we don't even need to inspect upstream sources!
        // We can emit the entire special span `[cur32, iv.end]` at once!
        if let Some(sp_idx) = active_special {
            let e32 = step_end as u32;
            let rec = build_special_record(&ctx.special_rules[sp_idx]);
            let (gid, _) = geo_set.insert_full(rec);
            push_coalesced_v4(&mut country_spans, cur32, e32, gid as u32);
            cur = step_end + 1;
            continue;
        }

        // 2. Check Country Overrides & CN Exclusions
        while cov_cur < country_ov_v4.len() && country_ov_v4[cov_cur].end < cur32 {
            cov_cur += 1;
        }
        let active_cov = if cov_cur < country_ov_v4.len() {
            let iv = country_ov_v4[cov_cur];
            if iv.start <= cur32 {
                any_covering = true;
                step_end = step_end.min(iv.end as u64);
                Some(iv.payload_id() as usize)
            } else {
                step_end = step_end.min((iv.start as u64) - 1);
                None
            }
        } else {
            None
        };

        while cne_cur < cn_excl_v4.len() && cn_excl_v4[cne_cur].end < cur32 {
            cne_cur += 1;
        }
        let active_cne = if cne_cur < cn_excl_v4.len() {
            let iv = cn_excl_v4[cne_cur];
            if iv.start <= cur32 {
                step_end = step_end.min(iv.end as u64);
                Some(iv.payload_id() as usize)
            } else {
                step_end = step_end.min((iv.start as u64) - 1);
                None
            }
        } else {
            None
        };

        // 3. Scan K source slices
        scratch.active_obs.clear();
        for (s_idx, src) in ctx.sources.iter().enumerate() {
            let slice = &src.v4;
            let mut c = cursors[s_idx];
            while c < slice.len() && slice[c].end < cur32 {
                c += 1;
            }
            cursors[s_idx] = c;
            if c < slice.len() {
                let iv = slice[c];
                if iv.start <= cur32 {
                    any_covering = true;
                    step_end = step_end.min(iv.end as u64);
                    scratch
                        .active_obs
                        .push((s_idx, iv.payload_id(), iv.prefix_len()));
                } else {
                    step_end = step_end.min((iv.start as u64) - 1);
                }
            }
        }

        if !any_covering {
            cur = step_end + 1;
            continue;
        }

        let e32 = step_end as u32;
        if let Some((geo_rec, asn_rec_opt)) =
            resolve_atomic_interval(ctx, active_cov, active_cne, &mut scratch)
        {
            let is_cn = geo_rec.country == Some(IsoCode::CN);
            let (gid, _) = geo_set.insert_full(geo_rec);
            push_coalesced_v4(&mut country_spans, cur32, e32, gid as u32);
            if is_cn {
                push_coalesced_v4(&mut cn_spans, cur32, e32, gid as u32);
            }
            if let Some(asn_rec) = asn_rec_opt {
                let (aid, _) = asn_set.insert_full(asn_rec);
                push_coalesced_v4(&mut asn_spans, cur32, e32, aid as u32);
            }
        }

        cur = step_end + 1;
    }

    FamilySweepOutput {
        geo_set,
        asn_set,
        country_spans,
        cn_spans,
        asn_spans,
    }
}

fn sweep_v6(
    ctx: &SweepContext<'_>,
    special_v6: &[IntervalV6],
    country_ov_v6: &[IntervalV6],
    cn_excl_v6: &[IntervalV6],
) -> FamilySweepOutput<OutputSpanV6<u32>, OutputSpanV6<u32>> {
    let k = ctx.sources.len();
    let mut cursors = vec![0usize; k];
    let mut sp_cur = 0usize;
    let mut cov_cur = 0usize;
    let mut cne_cur = 0usize;

    let mut scratch = ResolverScratch::new(k, ctx.num_lineages);
    let mut geo_set =
        indexmap::IndexSet::with_capacity_and_hasher(65536, rustc_hash::FxBuildHasher);
    let mut asn_set =
        indexmap::IndexSet::with_capacity_and_hasher(65536, rustc_hash::FxBuildHasher);
    let mut country_spans: Vec<OutputSpanV6<u32>> = Vec::with_capacity(524_288);
    let mut cn_spans: Vec<OutputSpanV6<u32>> = Vec::with_capacity(32_768);
    let mut asn_spans: Vec<OutputSpanV6<u32>> = Vec::with_capacity(524_288);

    // Start IPv6 sweep right after `::ffff:ffff:ffff` (`0x0001_0000_0000_0000`) because
    // `::/96` and `::ffff:0:0/96` are reserved for mounting the IPv4 tree!
    let mut cur_opt: Option<u128> = Some(0x0001_0000_0000_0000);

    while let Some(cur) = cur_opt {
        let mut step_end: u128 = u128::MAX;
        let mut any_covering = false;

        // 1. Check Priority-0 Special Networks
        while sp_cur < special_v6.len() && special_v6[sp_cur].end < cur {
            sp_cur += 1;
        }
        let active_special = if sp_cur < special_v6.len() {
            let iv = special_v6[sp_cur];
            if iv.start <= cur {
                any_covering = true;
                step_end = step_end.min(iv.end);
                Some(iv.payload_id() as usize)
            } else {
                step_end = step_end.min(iv.start - 1);
                None
            }
        } else {
            None
        };

        if let Some(sp_idx) = active_special {
            let rec = build_special_record(&ctx.special_rules[sp_idx]);
            let (gid, _) = geo_set.insert_full(rec);
            push_coalesced_v6(&mut country_spans, cur, step_end, gid as u32);
            cur_opt = step_end.checked_add(1);
            continue;
        }

        // 2. Check Country Overrides & CN Exclusions
        while cov_cur < country_ov_v6.len() && country_ov_v6[cov_cur].end < cur {
            cov_cur += 1;
        }
        let active_cov = if cov_cur < country_ov_v6.len() {
            let iv = country_ov_v6[cov_cur];
            if iv.start <= cur {
                any_covering = true;
                step_end = step_end.min(iv.end);
                Some(iv.payload_id() as usize)
            } else {
                step_end = step_end.min(iv.start - 1);
                None
            }
        } else {
            None
        };

        while cne_cur < cn_excl_v6.len() && cn_excl_v6[cne_cur].end < cur {
            cne_cur += 1;
        }
        let active_cne = if cne_cur < cn_excl_v6.len() {
            let iv = cn_excl_v6[cne_cur];
            if iv.start <= cur {
                step_end = step_end.min(iv.end);
                Some(iv.payload_id() as usize)
            } else {
                step_end = step_end.min(iv.start - 1);
                None
            }
        } else {
            None
        };

        // 3. Scan K source slices
        scratch.active_obs.clear();
        for (s_idx, src) in ctx.sources.iter().enumerate() {
            let slice = &src.v6;
            let mut c = cursors[s_idx];
            while c < slice.len() && slice[c].end < cur {
                c += 1;
            }
            cursors[s_idx] = c;
            if c < slice.len() {
                let iv = slice[c];
                if iv.start <= cur {
                    any_covering = true;
                    step_end = step_end.min(iv.end);
                    scratch
                        .active_obs
                        .push((s_idx, iv.payload_id(), iv.prefix_len()));
                } else {
                    step_end = step_end.min(iv.start - 1);
                }
            }
        }

        if !any_covering {
            cur_opt = step_end.checked_add(1);
            continue;
        }

        if let Some((geo_rec, asn_rec_opt)) =
            resolve_atomic_interval(ctx, active_cov, active_cne, &mut scratch)
        {
            let is_cn = geo_rec.country == Some(IsoCode::CN);
            let (gid, _) = geo_set.insert_full(geo_rec);
            push_coalesced_v6(&mut country_spans, cur, step_end, gid as u32);
            if is_cn {
                push_coalesced_v6(&mut cn_spans, cur, step_end, gid as u32);
            }
            if let Some(asn_rec) = asn_rec_opt {
                let (aid, _) = asn_set.insert_full(asn_rec);
                push_coalesced_v6(&mut asn_spans, cur, step_end, aid as u32);
            }
        }

        cur_opt = step_end.checked_add(1);
    }

    FamilySweepOutput {
        geo_set,
        asn_set,
        country_spans,
        cn_spans,
        asn_spans,
    }
}

#[inline]
fn build_special_record(rule: &InternedSpecialRule) -> ResolvedGeoRecord {
    ResolvedGeoRecord {
        is_special_non_routable: true,
        special_network_type: rule.network_type,
        virtual_network: rule.virtual_network,
        organization: rule.organization,
        traits: rule.traits,
        latitude_e5: COORD_UNSET,
        longitude_e5: COORD_UNSET,
        ..ResolvedGeoRecord::default()
    }
}

#[inline]
fn push_coalesced_v4(spans: &mut Vec<OutputSpanV4<u32>>, start: u32, end: u32, record_id: u32) {
    if let Some(last) = spans.last_mut()
        && last.record_id == record_id
        && last.end.saturating_add(1) == start
    {
        last.end = end;
    } else {
        spans.push(OutputSpanV4 {
            start,
            end,
            record_id,
        });
    }
}

#[inline]
fn push_coalesced_v6(spans: &mut Vec<OutputSpanV6<u32>>, start: u128, end: u128, record_id: u32) {
    if let Some(last) = spans.last_mut()
        && last.record_id == record_id
        && last.end.checked_add(1) == Some(start)
    {
        last.end = end;
    } else {
        spans.push(OutputSpanV6 {
            start,
            end,
            record_id,
        });
    }
}

#[inline]
const fn tier_rank(t: SourceTier) -> u8 {
    match t {
        SourceTier::Tier1Geofeed => 5,
        SourceTier::Tier2aCn => 4,
        SourceTier::Tier2bGlobal => 4,
        SourceTier::Tier3BgpRir => 2,
        SourceTier::TraitOverlay => 1,
    }
}

fn resolve_atomic_interval(
    ctx: &SweepContext<'_>,
    active_cov: Option<usize>,
    active_cne: Option<usize>,
    scratch: &mut ResolverScratch,
) -> Option<(ResolvedGeoRecord, Option<ResolvedAsnRecord>)> {
    let mut rec = ResolvedGeoRecord::empty();
    let cn_excluded = active_cne.is_some();

    // -------------------------------------------------------------------------
    // Step 1: Resolve ASN first (lineage-deduplicated BGP specificity + weight)
    // -------------------------------------------------------------------------
    scratch.asn_scores.clear();
    for &(s_idx, pid, plen) in &scratch.active_obs {
        let p = &ctx.arena.payloads[pid as usize];
        if p.asn == 0 {
            continue;
        }
        let sm = &ctx.sources[s_idx].meta;
        let lid = sm.lineage_id as usize;
        let w = sm.asn_weight.max(50);
        match scratch.lineage_asn_best[lid] {
            None => scratch.lineage_asn_best[lid] = Some((p.asn, w, plen)),
            Some((_, prev_w, prev_p)) if (plen, w) > (prev_p, prev_w) => {
                scratch.lineage_asn_best[lid] = Some((p.asn, w, plen));
            }
            _ => {}
        }
    }

    for &(s_idx, _, _) in &scratch.active_obs {
        let lid = ctx.sources[s_idx].meta.lineage_id as usize;
        if let Some((asn, w, plen)) = scratch.lineage_asn_best[lid].take() {
            if let Some(entry) = scratch.asn_scores.iter_mut().find(|(a, _, _)| *a == asn) {
                entry.1 += w as u32;
                entry.2 = entry.2.max(plen);
            } else {
                scratch.asn_scores.push((asn, w as u32, plen));
            }
        }
    }

    let mut winning_asn = 0u32;
    let mut best_asn_score = 0u32;
    for &(asn, sum_w, max_plen) in &scratch.asn_scores {
        let score = sum_w + (max_plen as u32) * 3;
        if score > best_asn_score {
            best_asn_score = score;
            winning_asn = asn;
        }
    }

    let asn_dict_entry: Option<&AsnDictionaryEntry> = if winning_asn != 0 {
        ctx.arena.asn_dict.get(&winning_asn)
    } else {
        None
    };

    // -------------------------------------------------------------------------
    // Step 2: Resolve Country & Registered Country (lineage-deduplicated)
    // -------------------------------------------------------------------------
    let mut best_reg_country: Option<(IsoCode, u16)> = None;
    for &(s_idx, pid, plen) in &scratch.active_obs {
        let p = &ctx.arena.payloads[pid as usize];
        let sm = &ctx.sources[s_idx].meta;

        if let Some(rc) = p.registered_country {
            let rw = sm.registered_country_weight.max(sm.country_weight);
            if best_reg_country.is_none_or(|(_, prev_w)| rw > prev_w) {
                best_reg_country = Some((rc, rw));
            }
        }

        let Some(iso) = p.country else {
            continue;
        };
        if cn_excluded && iso == IsoCode::CN {
            continue;
        }

        let eff_w = if iso == IsoCode::CN {
            sm.country_weight.max(sm.cn_weight)
        } else {
            sm.country_weight
        };
        if eff_w == 0 {
            continue;
        }

        let lid = sm.lineage_id as usize;
        let cand_key = (tier_rank(sm.tier), eff_w, plen);
        match scratch.lineage_country_best[lid] {
            None => scratch.lineage_country_best[lid] = Some((iso, sm.tier, eff_w, plen)),
            Some((_, pt, pw, pp)) if cand_key > (tier_rank(pt), pw, pp) => {
                scratch.lineage_country_best[lid] = Some((iso, sm.tier, eff_w, plen));
            }
            _ => {}
        }
    }

    scratch.country_scores.clear();
    scratch.tier1_scores.clear();

    for &(s_idx, _, _) in &scratch.active_obs {
        let lid = ctx.sources[s_idx].meta.lineage_id as usize;
        if let Some((iso, tier, eff_w, plen)) = scratch.lineage_country_best[lid].take() {
            if tier == SourceTier::Tier1Geofeed {
                let t1_score = (eff_w as u32) * 10 + (plen.min(64) as u32);
                if let Some(entry) = scratch.tier1_scores.iter_mut().find(|(c, _)| *c == iso) {
                    entry.1 += t1_score;
                } else {
                    scratch.tier1_scores.push((iso, t1_score));
                }
            }
            let total_w = (eff_w as u32) + (plen.min(48) as u32) / 4;
            if let Some(entry) = scratch
                .country_scores
                .iter_mut()
                .find(|(c, _, _)| *c == iso)
            {
                entry.1 += total_w;
                entry.2 = entry.2.saturating_add(1);
            } else {
                scratch.country_scores.push((iso, total_w, 1));
            }
        }
    }

    // Apply ASN country_hint bonus (+30) to break ties or guard HK/MO/TW/foreign blocks
    if let Some(asn_meta) = asn_dict_entry
        && let Some(hint_iso) = asn_meta.country_hint
        && !(cn_excluded && hint_iso == IsoCode::CN)
        && let Some(entry) = scratch
            .country_scores
            .iter_mut()
            .find(|(c, _, _)| *c == hint_iso)
    {
        entry.1 += 30;
    }

    let winning_country = if let Some(cov_idx) = active_cov {
        Some(ctx.country_ov_rules[cov_idx].iso_code)
    } else if !scratch.tier1_scores.is_empty() {
        scratch
            .tier1_scores
            .iter()
            .max_by_key(|(_, sc)| *sc)
            .map(|(c, _)| *c)
    } else if !scratch.country_scores.is_empty() {
        // High-recall CN + HK/MO/TW separation + global consensus
        let cn_entry = scratch
            .country_scores
            .iter()
            .find(|(c, _, _)| *c == IsoCode::CN)
            .copied();
        let best_non_cn = scratch
            .country_scores
            .iter()
            .filter(|(c, _, _)| *c != IsoCode::CN)
            .max_by_key(|(_, sc, _)| *sc)
            .copied();

        match (cn_entry, best_non_cn) {
            (Some((_, cn_score, cn_cnt)), Some((other_iso, other_score, other_cnt))) => {
                if other_iso.is_hk_mo_tw() {
                    // HK/MO/TW separation: do not conflate with CN when HK/MO/TW outweighs CN
                    // or has >=2 lineages + matching ASN/RIR registration
                    if other_score >= cn_score
                        || (other_cnt >= 2
                            && best_reg_country.is_some_and(|(rc, _)| rc == other_iso))
                    {
                        Some(other_iso)
                    } else {
                        Some(IsoCode::CN)
                    }
                } else if cn_score >= other_score {
                    Some(IsoCode::CN)
                } else if cn_cnt >= 2
                    && best_reg_country.is_some_and(|(rc, _)| rc == IsoCode::CN)
                    && cn_score * 3 >= other_score * 2
                {
                    // High-recall CN: >=2 independent CN lineages backed by APNIC CN registration
                    Some(IsoCode::CN)
                } else if cn_cnt == 1 && other_cnt >= 3 && other_score > cn_score * 2 {
                    // 3+ global lineages decisively refute a lone noisy CN claim
                    Some(other_iso)
                } else if other_score > cn_score + 45 {
                    Some(other_iso)
                } else {
                    Some(IsoCode::CN)
                }
            }
            (Some(_), None) => Some(IsoCode::CN),
            (None, Some((other_iso, _, _))) => Some(other_iso),
            (None, None) => None,
        }
    } else if let Some(cne_idx) = active_cne {
        ctx.cn_excl_rules[cne_idx].fallback_iso_code
    } else {
        None
    };

    rec.country = winning_country;
    rec.registered_country = active_cov
        .and_then(|idx| ctx.country_ov_rules[idx].registered_iso_code)
        .or_else(|| best_reg_country.map(|(rc, _)| rc))
        .or(winning_country);

    // -------------------------------------------------------------------------
    // Step 3: Resolve City, Subdivisions, Coordinates, Postal, ISP & Traits
    //         (strictly filtered to country-consistent observations!)
    // -------------------------------------------------------------------------
    let mut best_city_score: u32 = 0;
    let mut best_isp_weight: u16 = 0;
    let mut best_org_weight: u16 = 0;
    let mut best_as_org_weight: u16 = 0;
    let mut best_as_dom_weight: u16 = 0;

    for &(s_idx, pid, plen) in &scratch.active_obs {
        let p = &ctx.arena.payloads[pid as usize];
        let sm = &ctx.sources[s_idx].meta;

        // Always union network traits across all active overlays and databases
        rec.traits = rec.traits.union(p.traits);

        if rec.represented_country.is_none() && p.represented_country.is_some() {
            rec.represented_country = p.represented_country;
        }

        // ISP & Organization
        if !p.isp.is_empty() {
            let iw = sm.isp_weight.max(60);
            if iw > best_isp_weight {
                best_isp_weight = iw;
                rec.isp = p.isp;
            }
        }
        if !p.organization.is_empty() {
            let ow = sm.city_weight.max(sm.isp_weight).max(50);
            if ow > best_org_weight {
                best_org_weight = ow;
                rec.organization = p.organization;
            }
        }
        if winning_asn != 0 && p.asn == winning_asn {
            let aw = sm.asn_weight.max(50);
            if !p.as_org.is_empty() && aw >= best_as_org_weight {
                best_as_org_weight = aw;
                rec.as_org = p.as_org;
            }
            if !p.as_domain.is_empty() && aw >= best_as_dom_weight {
                best_as_dom_weight = aw;
                rec.as_domain = p.as_domain;
            }
        }

        // City / Subdivision / Location must match `winning_country`!
        let country_matches = match (winning_country, p.country) {
            (Some(win_c), Some(obs_c)) => win_c == obs_c,
            _ => false,
        };
        if !country_matches {
            continue;
        }

        let has_sub_or_city = !p.subdiv1_iso.is_empty()
            || !p.subdiv1_en.is_empty()
            || !p.subdiv1_zh.is_empty()
            || !p.city_en.is_empty()
            || !p.city_zh.is_empty();

        if has_sub_or_city {
            let completeness_bonus: u32 = (!p.city_en.is_empty() as u32) * 3
                + (!p.city_zh.is_empty() as u32) * 3
                + (!p.subdiv1_iso.is_empty() as u32) * 2;
            let city_score =
                (sm.city_weight as u32) * 4 + (plen.min(48) as u32) + completeness_bonus;

            let same_subdiv = !rec.subdiv1_iso.is_empty() && rec.subdiv1_iso == p.subdiv1_iso;
            let same_city = (p.city_geoname_id != 0 && rec.city_geoname_id == p.city_geoname_id)
                || (!rec.city_en.is_empty() && rec.city_en == p.city_en)
                || (!rec.city_zh.is_empty() && rec.city_zh == p.city_zh);

            if city_score > best_city_score {
                best_city_score = city_score;
                rec.subdiv1_iso = p.subdiv1_iso;
                if !p.subdiv1_en.is_empty() || !same_subdiv {
                    rec.subdiv1_en = p.subdiv1_en;
                }
                if !p.subdiv1_zh.is_empty() || !same_subdiv {
                    rec.subdiv1_zh = p.subdiv1_zh;
                }
                if p.subdiv1_geoname_id != 0 || !same_subdiv {
                    rec.subdiv1_geoname_id = p.subdiv1_geoname_id;
                }
                rec.subdiv2_iso = p.subdiv2_iso;
                rec.subdiv2_en = p.subdiv2_en;
                rec.subdiv2_zh = p.subdiv2_zh;
                if !p.city_en.is_empty() || !same_city {
                    rec.city_en = p.city_en;
                }
                if !p.city_zh.is_empty() || !same_city {
                    rec.city_zh = p.city_zh;
                }
                if p.city_geoname_id != 0 || !same_city {
                    rec.city_geoname_id = p.city_geoname_id;
                }
                if !p.postal_code.is_empty() || !same_city {
                    rec.postal_code = p.postal_code;
                }
                if p.latitude_e5 != COORD_UNSET && p.longitude_e5 != COORD_UNSET {
                    rec.latitude_e5 = p.latitude_e5;
                    rec.longitude_e5 = p.longitude_e5;
                } else if !same_city {
                    rec.latitude_e5 = COORD_UNSET;
                    rec.longitude_e5 = COORD_UNSET;
                }
                if !p.time_zone.is_empty() || !same_city {
                    rec.time_zone = p.time_zone;
                }
            } else {
                // Fill complementary missing localized names if referring to the same division or city
                if same_subdiv {
                    if rec.subdiv1_en.is_empty() && !p.subdiv1_en.is_empty() {
                        rec.subdiv1_en = p.subdiv1_en;
                    }
                    if rec.subdiv1_zh.is_empty() && !p.subdiv1_zh.is_empty() {
                        rec.subdiv1_zh = p.subdiv1_zh;
                    }
                    if rec.subdiv1_geoname_id == 0 && p.subdiv1_geoname_id != 0 {
                        rec.subdiv1_geoname_id = p.subdiv1_geoname_id;
                    }
                }
                if same_city {
                    if rec.city_en.is_empty() && !p.city_en.is_empty() {
                        rec.city_en = p.city_en;
                    }
                    if rec.city_zh.is_empty() && !p.city_zh.is_empty() {
                        rec.city_zh = p.city_zh;
                    }
                    if rec.city_geoname_id == 0 && p.city_geoname_id != 0 {
                        rec.city_geoname_id = p.city_geoname_id;
                    }
                }
            }
        }

        let same_city_after = (p.city_geoname_id != 0 && rec.city_geoname_id == p.city_geoname_id)
            || (!rec.city_en.is_empty() && rec.city_en == p.city_en)
            || (!rec.city_zh.is_empty() && rec.city_zh == p.city_zh);
        if rec.postal_code.is_empty()
            && !p.postal_code.is_empty()
            && (same_city_after
                || (rec.city_en.is_empty() && rec.city_zh.is_empty() && sm.city_weight >= 88))
        {
            rec.postal_code = p.postal_code;
        }
        if rec.time_zone.is_empty() && !p.time_zone.is_empty() {
            rec.time_zone = p.time_zone;
        }
        if rec.latitude_e5 == COORD_UNSET
            && p.latitude_e5 != COORD_UNSET
            && p.longitude_e5 != COORD_UNSET
        {
            rec.latitude_e5 = p.latitude_e5;
            rec.longitude_e5 = p.longitude_e5;
        }
        if rec.accuracy_radius == 0 && p.accuracy_radius != 0 {
            rec.accuracy_radius = p.accuracy_radius;
        }
        if rec.metro_code == 0 && p.metro_code != 0 {
            rec.metro_code = p.metro_code;
        }
    }

    // -------------------------------------------------------------------------
    // Step 4: Enrich with ASN dictionary & Human Overrides
    // -------------------------------------------------------------------------
    if winning_asn != 0 {
        rec.asn = winning_asn;
        if let Some(meta) = asn_dict_entry {
            if !meta.organization.is_empty()
                && (rec.as_org.is_empty() || meta.org_weight >= best_as_org_weight)
            {
                rec.as_org = meta.organization;
            }
            if !meta.domain.is_empty()
                && (rec.as_domain.is_empty() || meta.domain_weight >= best_as_dom_weight)
            {
                rec.as_domain = meta.domain;
            }
            if !meta.isp.is_empty() {
                rec.isp = meta.isp;
            }
            rec.traits = rec.traits.union(meta.traits).without(meta.clear_traits);

            // If CN record lacks provincial subdivision, apply provincial ASN hint (e.g. AS4812 -> Shanghai)
            if rec.country == Some(IsoCode::CN)
                && rec.subdiv1_iso.is_empty()
                && !meta.province_hint_zh.is_empty()
                && let Some(&(iso_id, en_id, zh_id, gid, lat, lon)) =
                    ctx.cn_prov_interned.get(&meta.province_hint_zh)
            {
                rec.subdiv1_iso = iso_id;
                rec.subdiv1_en = en_id;
                rec.subdiv1_zh = zh_id;
                rec.subdiv1_geoname_id = gid;
                if rec.latitude_e5 == COORD_UNSET {
                    rec.latitude_e5 = lat;
                    rec.longitude_e5 = lon;
                }
            }
        }
    }

    if let Some(cov_idx) = active_cov {
        let cov = &ctx.country_ov_rules[cov_idx];
        rec.traits = rec.traits.union(cov.traits);
        if !cov.isp.is_empty() {
            rec.isp = cov.isp;
        }
        if !cov.organization.is_empty() {
            rec.organization = cov.organization;
        }
        if cov.clear_city {
            rec.subdiv1_iso = StrId::EMPTY;
            rec.subdiv1_en = StrId::EMPTY;
            rec.subdiv1_zh = StrId::EMPTY;
            rec.subdiv1_geoname_id = 0;
            rec.subdiv2_iso = StrId::EMPTY;
            rec.subdiv2_en = StrId::EMPTY;
            rec.subdiv2_zh = StrId::EMPTY;
            rec.city_en = StrId::EMPTY;
            rec.city_zh = StrId::EMPTY;
            rec.city_geoname_id = 0;
            rec.postal_code = StrId::EMPTY;
            rec.latitude_e5 = COORD_UNSET;
            rec.longitude_e5 = COORD_UNSET;
        } else {
            if !cov.subdiv1_iso.is_empty() {
                rec.subdiv1_iso = cov.subdiv1_iso;
            }
            if !cov.subdiv1_en.is_empty() {
                rec.subdiv1_en = cov.subdiv1_en;
            }
            if !cov.subdiv1_zh.is_empty() {
                rec.subdiv1_zh = cov.subdiv1_zh;
            }
            if cov.subdiv1_geoname_id != 0 {
                rec.subdiv1_geoname_id = cov.subdiv1_geoname_id;
            }
            if !cov.city_en.is_empty() {
                rec.city_en = cov.city_en;
            }
            if !cov.city_zh.is_empty() {
                rec.city_zh = cov.city_zh;
            }
            if cov.city_geoname_id != 0 {
                rec.city_geoname_id = cov.city_geoname_id;
            }
            if cov.lat_e5 != COORD_UNSET {
                rec.latitude_e5 = cov.lat_e5;
                rec.longitude_e5 = cov.lon_e5;
            }
        }
    }

    if rec.organization.is_empty() && !rec.as_org.is_empty() {
        rec.organization = rec.as_org;
    }

    // Default country timezone fallback
    if rec.time_zone.is_empty()
        && let Some(c) = rec.country
        && let Some(def) = ctx.country_defaults.get(&c)
    {
        rec.time_zone = def.default_tz;
    }

    if rec.is_empty() {
        return None;
    }

    let asn_out = if rec.asn != 0 {
        Some(ResolvedAsnRecord {
            asn: rec.asn,
            as_org: rec.as_org,
            as_domain: rec.as_domain,
        })
    } else {
        None
    };

    Some((rec, asn_out))
}
