use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use indexmap::IndexSet;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rustc_hash::{FxBuildHasher, FxHashMap};

/// Canonical two-letter uppercase ASCII ISO 3166-1 alpha-2 code (plus `XK`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IsoCode(pub [u8; 2]);

impl IsoCode {
    pub const CN: Self = Self(*b"CN");
    pub const HK: Self = Self(*b"HK");
    pub const MO: Self = Self(*b"MO");
    pub const TW: Self = Self(*b"TW");
    pub const GB: Self = Self(*b"GB");

    #[inline]
    pub fn parse_raw(raw: &str) -> Option<Self> {
        let s = raw.trim();
        if s.len() != 2 {
            return None;
        }
        let b = s.as_bytes();
        if !b[0].is_ascii_alphabetic() || !b[1].is_ascii_alphabetic() {
            return None;
        }
        let code = [b[0].to_ascii_uppercase(), b[1].to_ascii_uppercase()];
        match &code {
            b"UK" => Some(Self::GB),
            // Reject non-country pseudo-codes emitted by legacy GeoIP/RIR feeds
            b"ZZ" | b"XX" | b"AA" | b"OO" | b"AP" | b"EU" | b"AN" => {
                // Note: AN was Netherlands Antilles (dissolved), AQ is Antarctica.
                None
            }
            _ => Some(Self(code)),
        }
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or("ZZ")
    }

    #[inline]
    pub fn is_hk_mo_tw(self) -> bool {
        matches!(self, Self::HK | Self::MO | Self::TW)
    }
}

impl fmt::Debug for IsoCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for IsoCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Bitflags representing network traits and risk attributes.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TraitFlags(pub u16);

impl TraitFlags {
    pub const EMPTY: Self = Self(0);
    pub const IS_ANYCAST: u16 = 1 << 0;
    pub const IS_ANONYMOUS_PROXY: u16 = 1 << 1;
    pub const IS_VPN: u16 = 1 << 2;
    pub const IS_TOR_EXIT: u16 = 1 << 3;
    pub const IS_HOSTING: u16 = 1 << 4;
    pub const IS_CDN: u16 = 1 << 5;
    pub const IS_SATELLITE: u16 = 1 << 6;
    pub const IS_ICLOUD_RELAY: u16 = 1 << 7;
    pub const IS_CRAWLER: u16 = 1 << 8;
    pub const IS_BOGON: u16 = 1 << 9;
    pub const IS_PRIVATE: u16 = 1 << 10;
    pub const IS_VIRTUAL_MESH: u16 = 1 << 11;
    pub const IS_MALWARE: u16 = 1 << 12;

    #[inline]
    pub fn insert(&mut self, bits: u16) {
        self.0 |= bits;
    }

    #[inline]
    pub fn contains(self, bits: u16) -> bool {
        (self.0 & bits) == bits
    }

    #[inline]
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[inline]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Interned string handle (`StrId::EMPTY` == `0` == `""`).
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct StrId(pub u32);

impl StrId {
    pub const EMPTY: Self = Self(0);

    #[inline]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Append-only deduplicated string pool.
#[derive(Clone, Debug)]
pub struct StringPool {
    set: IndexSet<Box<str>, FxBuildHasher>,
}

impl Default for StringPool {
    fn default() -> Self {
        Self::new()
    }
}

impl StringPool {
    pub fn new() -> Self {
        let mut set = IndexSet::with_hasher(FxBuildHasher);
        set.insert(Box::from(""));
        Self { set }
    }

    #[inline]
    pub fn intern(&mut self, s: &str) -> StrId {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return StrId::EMPTY;
        }
        if let Some(idx) = self.set.get_index_of(trimmed) {
            return StrId(idx as u32);
        }
        let (idx, _) = self.set.insert_full(Box::from(trimmed));
        StrId(idx as u32)
    }

    #[inline]
    pub fn get(&self, id: StrId) -> &str {
        self.set.get_index(id.0 as usize).map_or("", |b| b.as_ref())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.set.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.set.len() <= 1
    }
}

pub const COORD_UNSET: i32 = i32::MIN;

#[inline]
pub fn quantize_coord(val: f64) -> i32 {
    if !val.is_finite() {
        return COORD_UNSET;
    }
    (val * 100.0).round() as i32
}

#[inline]
pub fn dequantize_coord(val: i32) -> Option<f64> {
    if val == COORD_UNSET {
        None
    } else {
        Some((val as f64) / 100.0)
    }
}

/// Normalized observation payload interned per source and then globally.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct ObsPayload {
    pub country: Option<IsoCode>,
    pub registered_country: Option<IsoCode>,
    pub represented_country: Option<IsoCode>,
    pub subdiv1_iso: StrId,
    pub subdiv1_en: StrId,
    pub subdiv1_zh: StrId,
    pub subdiv1_geoname_id: u32,
    pub subdiv2_iso: StrId,
    pub subdiv2_en: StrId,
    pub subdiv2_zh: StrId,
    pub city_en: StrId,
    pub city_zh: StrId,
    pub city_geoname_id: u32,
    pub postal_code: StrId,
    pub time_zone: StrId,
    pub latitude_e5: i32,
    pub longitude_e5: i32,
    pub accuracy_radius: u16,
    pub metro_code: u16,
    pub asn: u32,
    pub as_org: StrId,
    pub as_domain: StrId,
    pub isp: StrId,
    pub organization: StrId,
    pub traits: TraitFlags,
}

impl Default for ObsPayload {
    fn default() -> Self {
        Self {
            country: None,
            registered_country: None,
            represented_country: None,
            subdiv1_iso: StrId::EMPTY,
            subdiv1_en: StrId::EMPTY,
            subdiv1_zh: StrId::EMPTY,
            subdiv1_geoname_id: 0,
            subdiv2_iso: StrId::EMPTY,
            subdiv2_en: StrId::EMPTY,
            subdiv2_zh: StrId::EMPTY,
            city_en: StrId::EMPTY,
            city_zh: StrId::EMPTY,
            city_geoname_id: 0,
            postal_code: StrId::EMPTY,
            time_zone: StrId::EMPTY,
            latitude_e5: COORD_UNSET,
            longitude_e5: COORD_UNSET,
            accuracy_radius: 0,
            metro_code: 0,
            asn: 0,
            as_org: StrId::EMPTY,
            as_domain: StrId::EMPTY,
            isp: StrId::EMPTY,
            organization: StrId::EMPTY,
            traits: TraitFlags::EMPTY,
        }
    }
}

impl ObsPayload {
    #[inline]
    pub fn is_meaningful(&self) -> bool {
        self.country.is_some()
            || self.registered_country.is_some()
            || self.represented_country.is_some()
            || !self.subdiv1_iso.is_empty()
            || !self.subdiv1_en.is_empty()
            || !self.subdiv1_zh.is_empty()
            || !self.city_en.is_empty()
            || !self.city_zh.is_empty()
            || self.asn != 0
            || !self.isp.is_empty()
            || !self.organization.is_empty()
            || !self.traits.is_empty()
    }
}

/// Packs a 24-bit payload index (`0..16_777_216`) and an 8-bit effective prefix length (`0..=128`).
#[inline]
pub const fn pack_payload_prefix(payload_id: u32, prefix_len: u8) -> u32 {
    debug_assert!(payload_id <= 0x00FF_FFFF);
    (payload_id & 0x00FF_FFFF) | ((prefix_len as u32) << 24)
}

#[inline]
pub const fn unpack_payload_id(packed: u32) -> u32 {
    packed & 0x00FF_FFFF
}

#[inline]
pub const fn unpack_prefix_len(packed: u32) -> u8 {
    (packed >> 24) as u8
}

/// Effective prefix specificity for an arbitrary inclusive IPv4 range `[start, end]`.
#[inline]
pub fn effective_prefix_v4(start: u32, end: u32) -> u8 {
    let span = (end as u64).saturating_sub(start as u64) + 1;
    let bits = 63u32.saturating_sub(span.leading_zeros());
    32u8.saturating_sub(bits as u8)
}

/// Effective prefix specificity for an arbitrary inclusive IPv6 range `[start, end]`.
#[inline]
pub fn effective_prefix_v6(start: u128, end: u128) -> u8 {
    if start == 0 && end == u128::MAX {
        return 0;
    }
    let diff = end.saturating_sub(start);
    if diff == 0 {
        return 128;
    }
    let span_minus_one_bits = 128u32.saturating_sub(diff.leading_zeros());
    128u8.saturating_sub(span_minus_one_bits as u8)
}

/// Compact 12-byte inclusive IPv4 interval `[start, end]`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IntervalV4 {
    pub start: u32,
    pub end: u32,
    pub packed: u32,
}

impl IntervalV4 {
    #[inline]
    pub fn new(start: u32, end: u32, payload_id: u32, prefix_len: u8) -> Self {
        Self {
            start,
            end,
            packed: pack_payload_prefix(payload_id, prefix_len),
        }
    }

    #[inline]
    pub fn payload_id(self) -> u32 {
        unpack_payload_id(self.packed)
    }

    #[inline]
    pub fn prefix_len(self) -> u8 {
        unpack_prefix_len(self.packed)
    }
}

/// Compact 36-byte inclusive IPv6 interval `[start, end]`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IntervalV6 {
    pub start: u128,
    pub end: u128,
    pub packed: u32,
}

impl IntervalV6 {
    #[inline]
    pub fn new(start: u128, end: u128, payload_id: u32, prefix_len: u8) -> Self {
        Self {
            start,
            end,
            packed: pack_payload_prefix(payload_id, prefix_len),
        }
    }

    #[inline]
    pub fn payload_id(self) -> u32 {
        unpack_payload_id(self.packed)
    }

    #[inline]
    pub fn prefix_len(self) -> u8 {
        unpack_prefix_len(self.packed)
    }
}

/// Standalone ASN dictionary metadata observation (from `bgptools_asns`, `ipverse`, `sat_asns`, etc.).
#[derive(Clone, Debug)]
pub struct AsnMetaObs {
    pub asn: u32,
    pub organization: String,
    pub domain: Option<String>,
    pub country: Option<IsoCode>,
    pub traits: TraitFlags,
    pub weight: u16,
}

/// Self-contained parsed output of a single upstream source, constructed lock-free in parallel.
#[derive(Clone, Debug)]
pub struct ParsedSource {
    pub source_id: String,
    pub strings: StringPool,
    pub payloads: IndexSet<ObsPayload, FxBuildHasher>,
    pub v4: Vec<IntervalV4>,
    pub v6: Vec<IntervalV6>,
    pub asn_meta: Vec<AsnMetaObs>,
}

impl ParsedSource {
    pub fn new(source_id: impl Into<String>) -> Self {
        Self {
            source_id: source_id.into(),
            strings: StringPool::new(),
            payloads: IndexSet::with_hasher(FxBuildHasher),
            v4: Vec::new(),
            v6: Vec::new(),
            asn_meta: Vec::new(),
        }
    }

    #[inline]
    pub fn intern_str(&mut self, s: &str) -> StrId {
        self.strings.intern(s)
    }

    #[inline]
    pub fn intern_payload(&mut self, payload: ObsPayload) -> Option<u32> {
        if !payload.is_meaningful() {
            return None;
        }
        if let Some(idx) = self.payloads.get_index_of(&payload) {
            return Some(idx as u32);
        }
        let (idx, _) = self.payloads.insert_full(payload);
        Some(idx as u32)
    }

    #[inline]
    pub fn push_v4(&mut self, start: u32, end: u32, payload_id: u32, prefix_len: u8) {
        if start > end {
            return;
        }
        let packed = pack_payload_prefix(payload_id, prefix_len);
        if let Some(last) = self.v4.last_mut()
            && last.packed == packed
            && last.end.saturating_add(1) >= start
            && last.start <= start
        {
            last.end = last.end.max(end);
            return;
        }
        self.v4.push(IntervalV4 { start, end, packed });
    }

    #[inline]
    pub fn push_v6(&mut self, start: u128, end: u128, payload_id: u32, prefix_len: u8) {
        if start > end {
            return;
        }
        // If an upstream dual-stack source emits IPv4-mapped `::ffff:0:0/96` or IPv4-compatible `::/96`
        // entries inside its IPv6 space, route them cleanly to `v4` instead of polluting IPv6 `::/96`.
        const V4_COMPAT_END: u128 = 0x0000_0000_FFFF_FFFF;
        const V4_MAPPED_START: u128 = 0x0000_FFFF_0000_0000;
        const V4_MAPPED_END: u128 = 0x0000_FFFF_FFFF_FFFF;

        if end <= V4_COMPAT_END {
            if !(start == 0 && end == V4_COMPAT_END && prefix_len == 0) {
                self.push_v4(
                    start as u32,
                    end as u32,
                    payload_id,
                    prefix_len
                        .saturating_sub(96)
                        .max(effective_prefix_v4(start as u32, end as u32)),
                );
            }
            return;
        }
        if start >= V4_MAPPED_START && end <= V4_MAPPED_END {
            let s4 = (start - V4_MAPPED_START) as u32;
            let e4 = (end - V4_MAPPED_START) as u32;
            let p4 = if prefix_len >= 96 {
                prefix_len - 96
            } else {
                effective_prefix_v4(s4, e4)
            };
            self.push_v4(s4, e4, payload_id, p4);
            return;
        }
        // Clip intervals starting inside `::/95` (which overlaps IPv4 mount space `0..=0x1_ffff_ffff`)
        let clipped_start = start.max(V4_MAPPED_END + 1);
        if clipped_start > end {
            return;
        }

        let packed = pack_payload_prefix(payload_id, prefix_len);
        if let Some(last) = self.v6.last_mut()
            && last.packed == packed
            && last.end.saturating_add(1) >= clipped_start
            && last.start <= clipped_start
        {
            last.end = last.end.max(end);
            return;
        }
        self.v6.push(IntervalV6 {
            start: clipped_start,
            end,
            packed,
        });
    }

    #[inline]
    pub fn push_ipnet(&mut self, net: IpNet, payload_id: u32) {
        let net = net.trunc();
        match net {
            IpNet::V4(v4) => {
                let start = u32::from(v4.network());
                let end = u32::from(v4.broadcast());
                self.push_v4(start, end, payload_id, v4.prefix_len());
            }
            IpNet::V6(v6) => {
                let start = u128::from(v6.network());
                let end = u128::from(v6.broadcast());
                self.push_v6(start, end, payload_id, v6.prefix_len());
            }
        }
    }

    #[inline]
    pub fn push_ip_addr(&mut self, addr: IpAddr, payload_id: u32) {
        match addr {
            IpAddr::V4(v4) => {
                let ip = u32::from(v4);
                self.push_v4(ip, ip, payload_id, 32);
            }
            IpAddr::V6(v6) => {
                let ip = u128::from(v6);
                self.push_v6(ip, ip, payload_id, 128);
            }
        }
    }

    pub fn finalize(&mut self) {
        self.v4.sort_unstable_by_key(|iv| (iv.start, iv.end));
        self.v6.sort_unstable_by_key(|iv| (iv.start, iv.end));
    }
}

/// Decomposes an arbitrary inclusive IPv4 range `[start, end]` into minimal exact CIDRs.
pub fn range_to_ipv4_cidrs(mut start: u32, end: u32) -> Vec<Ipv4Net> {
    let mut out = Vec::new();
    if start > end {
        return out;
    }
    loop {
        let tz = if start == 0 {
            32
        } else {
            start.trailing_zeros()
        };
        let remaining = (end as u64) - (start as u64) + 1;
        let max_span_log2 = 63 - remaining.leading_zeros();
        let host_bits = tz.min(max_span_log2);
        let prefix_len = (32 - host_bits) as u8;
        if let Ok(net) = Ipv4Net::new(Ipv4Addr::from(start), prefix_len) {
            out.push(net);
        }
        let step = 1u64 << host_bits;
        let next = (start as u64) + step;
        if next > (end as u64) {
            break;
        }
        start = next as u32;
    }
    out
}

/// Decomposes an arbitrary inclusive IPv6 range `[start, end]` into minimal exact CIDRs.
pub fn range_to_ipv6_cidrs(mut start: u128, end: u128) -> Vec<Ipv6Net> {
    let mut out = Vec::new();
    if start > end {
        return out;
    }
    loop {
        let tz = if start == 0 {
            128
        } else {
            start.trailing_zeros()
        };
        let diff = end - start;
        let max_span_log2 = if diff == u128::MAX {
            128
        } else {
            let rem = diff + 1;
            127 - rem.leading_zeros()
        };
        let host_bits = tz.min(max_span_log2);
        let prefix_len = (128 - host_bits) as u8;
        if let Ok(net) = Ipv6Net::new(Ipv6Addr::from(start), prefix_len) {
            out.push(net);
        }
        if host_bits == 128 {
            break;
        }
        let step = 1u128 << host_bits;
        match start.checked_add(step) {
            Some(next) if next <= end => start = next,
            _ => break,
        }
    }
    out
}

/// Enriched global ASN entry merged across BGP dictionaries and human overrides.
#[derive(Clone, Default, Debug)]
pub struct AsnDictionaryEntry {
    pub organization: StrId,
    pub org_weight: u16,
    pub isp: StrId,
    pub domain: StrId,
    pub domain_weight: u16,
    pub country_hint: Option<IsoCode>,
    pub province_hint_zh: StrId,
    pub traits: TraitFlags,
}

/// Global interned arena holding all sources' remapped intervals and strings.
pub struct GlobalArena {
    pub strings: StringPool,
    pub payloads: IndexSet<ObsPayload, FxBuildHasher>,
    pub asn_dict: FxHashMap<u32, AsnDictionaryEntry>,
}

impl Default for GlobalArena {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalArena {
    pub fn new() -> Self {
        Self {
            strings: StringPool::new(),
            payloads: IndexSet::with_hasher(FxBuildHasher),
            asn_dict: FxHashMap::default(),
        }
    }

    pub fn remap_str(&mut self, local_pool: &StringPool, id: StrId) -> StrId {
        if id.is_empty() {
            StrId::EMPTY
        } else {
            self.strings.intern(local_pool.get(id))
        }
    }

    pub fn ingest_parsed_source(
        &mut self,
        parsed: ParsedSource,
        source_weight_asn: u16,
    ) -> (Vec<IntervalV4>, Vec<IntervalV6>) {
        let mut id_map = Vec::with_capacity(parsed.payloads.len());
        for p in &parsed.payloads {
            let gp = ObsPayload {
                country: p.country,
                registered_country: p.registered_country,
                represented_country: p.represented_country,
                subdiv1_iso: self.remap_str(&parsed.strings, p.subdiv1_iso),
                subdiv1_en: self.remap_str(&parsed.strings, p.subdiv1_en),
                subdiv1_zh: self.remap_str(&parsed.strings, p.subdiv1_zh),
                subdiv1_geoname_id: p.subdiv1_geoname_id,
                subdiv2_iso: self.remap_str(&parsed.strings, p.subdiv2_iso),
                subdiv2_en: self.remap_str(&parsed.strings, p.subdiv2_en),
                subdiv2_zh: self.remap_str(&parsed.strings, p.subdiv2_zh),
                city_en: self.remap_str(&parsed.strings, p.city_en),
                city_zh: self.remap_str(&parsed.strings, p.city_zh),
                city_geoname_id: p.city_geoname_id,
                postal_code: self.remap_str(&parsed.strings, p.postal_code),
                time_zone: self.remap_str(&parsed.strings, p.time_zone),
                latitude_e5: p.latitude_e5,
                longitude_e5: p.longitude_e5,
                accuracy_radius: p.accuracy_radius,
                metro_code: p.metro_code,
                asn: p.asn,
                as_org: self.remap_str(&parsed.strings, p.as_org),
                as_domain: self.remap_str(&parsed.strings, p.as_domain),
                isp: self.remap_str(&parsed.strings, p.isp),
                organization: self.remap_str(&parsed.strings, p.organization),
                traits: p.traits,
            };

            // Opportunistically harvest ASN org/domain from payload into ASN dictionary
            if gp.asn != 0 && (!gp.as_org.is_empty() || !gp.as_domain.is_empty()) {
                let entry = self.asn_dict.entry(gp.asn).or_default();
                if !gp.as_org.is_empty() && source_weight_asn >= entry.org_weight {
                    entry.organization = gp.as_org;
                    entry.org_weight = source_weight_asn;
                }
                if !gp.as_domain.is_empty() && source_weight_asn >= entry.domain_weight {
                    entry.domain = gp.as_domain;
                    entry.domain_weight = source_weight_asn;
                }
            }

            let (g_idx, _) = self.payloads.insert_full(gp);
            id_map.push(g_idx as u32);
        }

        for meta in parsed.asn_meta {
            if meta.asn == 0 {
                continue;
            }
            let org_id = self.strings.intern(&meta.organization);
            let dom_id = meta
                .domain
                .as_deref()
                .map_or(StrId::EMPTY, |d| self.strings.intern(d));
            let entry = self.asn_dict.entry(meta.asn).or_default();
            if !org_id.is_empty() && meta.weight >= entry.org_weight {
                entry.organization = org_id;
                entry.org_weight = meta.weight;
            }
            if !dom_id.is_empty() && meta.weight >= entry.domain_weight {
                entry.domain = dom_id;
                entry.domain_weight = meta.weight;
            }
            if entry.country_hint.is_none() {
                entry.country_hint = meta.country;
            }
            entry.traits = entry.traits.union(meta.traits);
        }

        let v4 = parsed
            .v4
            .into_iter()
            .map(|iv| {
                let g_id = id_map[iv.payload_id() as usize];
                IntervalV4::new(iv.start, iv.end, g_id, iv.prefix_len())
            })
            .collect();

        let v6 = parsed
            .v6
            .into_iter()
            .map(|iv| {
                let g_id = id_map[iv.payload_id() as usize];
                IntervalV6::new(iv.start, iv.end, g_id, iv.prefix_len())
            })
            .collect();

        (v4, v6)
    }
}

/// Final resolved full-field record emitted by the fusion engine (`Country.mmdb` & `Country-cn.mmdb`).
#[derive(Clone, PartialEq, Eq, Hash, Default, Debug)]
pub struct ResolvedGeoRecord {
    pub is_special_non_routable: bool,
    pub special_network_type: StrId,
    pub virtual_network: StrId,
    pub country: Option<IsoCode>,
    pub registered_country: Option<IsoCode>,
    pub represented_country: Option<IsoCode>,
    pub subdiv1_iso: StrId,
    pub subdiv1_en: StrId,
    pub subdiv1_zh: StrId,
    pub subdiv1_geoname_id: u32,
    pub subdiv2_iso: StrId,
    pub subdiv2_en: StrId,
    pub subdiv2_zh: StrId,
    pub city_en: StrId,
    pub city_zh: StrId,
    pub city_geoname_id: u32,
    pub postal_code: StrId,
    pub time_zone: StrId,
    pub latitude_e5: i32,
    pub longitude_e5: i32,
    pub accuracy_radius: u16,
    pub metro_code: u16,
    pub asn: u32,
    pub as_org: StrId,
    pub as_domain: StrId,
    pub isp: StrId,
    pub organization: StrId,
    pub traits: TraitFlags,
}

impl ResolvedGeoRecord {
    pub fn empty() -> Self {
        Self {
            latitude_e5: COORD_UNSET,
            longitude_e5: COORD_UNSET,
            ..Self::default()
        }
    }

    pub fn is_empty(&self) -> bool {
        !self.is_special_non_routable
            && self.country.is_none()
            && self.registered_country.is_none()
            && self.represented_country.is_none()
            && self.asn == 0
            && self.isp.is_empty()
            && self.organization.is_empty()
            && self.traits.is_empty()
    }
}

/// Final resolved pure ASN record (`ASN.mmdb`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
pub struct ResolvedAsnRecord {
    pub asn: u32,
    pub as_org: StrId,
    pub as_domain: StrId,
}
