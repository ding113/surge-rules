use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use rustc_hash::FxHashMap;
use serde::Deserialize;

use crate::model::{COORD_UNSET, IsoCode, TraitFlags, quantize_coord};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceTier {
    Tier1Geofeed,
    Tier2aCn,
    Tier2bGlobal,
    Tier3BgpRir,
    TraitOverlay,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceFormat {
    GeofeedParquet,
    Rfc8805Csv,
    AwsIpRangesJson,
    GcpCloudJson,
    OracleCloudJson,
    Xdb,
    QqwryDat,
    Ipdb,
    CidrCountry,
    CidrIsp,
    CidrTrait,
    Mmdb,
    Ip2locationBin,
    Ip2locationCsv,
    Libloc,
    IpscopeCsv,
    SypexDat,
    BgptoolsTable,
    BgptoolsAsnsCsv,
    BgptoolsTagCsv,
    IpverseAsCsv,
    IptoasnTsv,
    RirDelegated,
    FastlyJson,
    GcoreJson,
    GithubMetaJson,
    OnionooJson,
    OpenproxydbCsv,
    SatGeoipJsonl,
    SatAsnsCsv,
    SpamhausDrop,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum EndpointConfig {
    Direct {
        url: String,
    },
    GithubRelease {
        repo: String,
        asset_pattern: String,
    },
    NpmTarball {
        package: String,
        member_path: String,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceConfig {
    pub id: String,
    pub tier: SourceTier,
    pub format: SourceFormat,
    pub lineage: String,
    #[serde(default)]
    pub country_weight: u16,
    #[serde(default)]
    pub cn_weight: u16,
    #[serde(default)]
    pub city_weight: u16,
    #[serde(default)]
    pub isp_weight: u16,
    #[serde(default)]
    pub asn_weight: u16,
    #[serde(default)]
    pub registered_country_weight: u16,
    #[serde(default)]
    pub fixed_country: Option<String>,
    #[serde(default)]
    pub fixed_isp: Option<String>,
    #[serde(default)]
    pub is_hosting: bool,
    #[serde(default)]
    pub is_cdn: bool,
    #[serde(default)]
    pub is_vpn: bool,
    #[serde(default)]
    pub is_anycast: bool,
    #[serde(default)]
    pub is_anonymous_proxy: bool,
    #[serde(default)]
    pub is_tor_exit: bool,
    #[serde(default)]
    pub is_icloud_relay: bool,
    #[serde(default)]
    pub is_satellite: bool,
    #[serde(default)]
    pub is_crawler: bool,
    #[serde(default)]
    pub is_malware: bool,
    #[serde(default)]
    pub core: bool,
    pub endpoints: Vec<EndpointConfig>,
}

impl SourceConfig {
    pub fn base_traits(&self) -> TraitFlags {
        let mut f = TraitFlags::EMPTY;
        if self.is_anycast {
            f.insert(TraitFlags::IS_ANYCAST);
        }
        if self.is_anonymous_proxy {
            f.insert(TraitFlags::IS_ANONYMOUS_PROXY);
        }
        if self.is_vpn {
            f.insert(TraitFlags::IS_VPN);
        }
        if self.is_tor_exit {
            f.insert(TraitFlags::IS_TOR_EXIT);
        }
        if self.is_hosting {
            f.insert(TraitFlags::IS_HOSTING);
        }
        if self.is_cdn {
            f.insert(TraitFlags::IS_CDN);
        }
        if self.is_satellite {
            f.insert(TraitFlags::IS_SATELLITE);
        }
        if self.is_icloud_relay {
            f.insert(TraitFlags::IS_ICLOUD_RELAY);
        }
        if self.is_crawler {
            f.insert(TraitFlags::IS_CRAWLER);
        }
        if self.is_malware {
            f.insert(TraitFlags::IS_MALWARE);
        }
        f
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceCatalog {
    pub schema_version: u32,
    pub sources: Vec<SourceConfig>,
}

impl SourceCatalog {
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read source catalog {}", path.display()))?;
        let catalog: Self = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse source catalog {}", path.display()))?;
        if catalog.schema_version != 1 {
            bail!(
                "unsupported source catalog schemaVersion {} in {}",
                catalog.schema_version,
                path.display()
            );
        }
        if catalog.sources.is_empty() {
            bail!("source catalog {} contains zero sources", path.display());
        }
        let mut seen = rustc_hash::FxHashSet::default();
        for src in &catalog.sources {
            if !seen.insert(src.id.as_str()) {
                bail!("duplicate source id '{}' in {}", src.id, path.display());
            }
            if src.endpoints.is_empty() {
                bail!("source '{}' has zero endpoints", src.id);
            }
        }
        Ok(catalog)
    }
}

#[derive(Clone, Debug)]
pub struct CountryMeta {
    pub iso_code: IsoCode,
    pub continent_code: String,
    pub continent_geoname_id: u32,
    pub continent_en: String,
    pub continent_zh: String,
    pub geoname_id: u32,
    pub is_eu: bool,
    pub name_en: String,
    pub name_zh: String,
    pub default_tz: String,
}

#[derive(Clone, Debug)]
pub struct CnDivisionMeta {
    pub province_zh: String,
    pub city_zh: String,
    pub iso_code: String,
    pub province_en: String,
    pub city_en: String,
    pub geoname_id: u32,
    pub lat_e5: i32,
    pub lon_e5: i32,
}

#[derive(Clone, Debug)]
pub struct CloudRegionMeta {
    pub provider: String,
    pub region: String,
    pub iso_code: IsoCode,
    pub subdivision_iso: String,
    pub subdivision_en: String,
    pub city_en: String,
    pub tz: String,
    pub lat_e5: i32,
    pub lon_e5: i32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MetadataBundleJson {
    schema_version: u32,
    countries: Vec<CountryJson>,
    cn_divisions: Vec<CnDivisionJson>,
    cloud_regions: Vec<CloudRegionJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CountryJson {
    iso_code: String,
    continent_code: String,
    continent_geoname_id: u32,
    continent_en: String,
    continent_zh: String,
    geoname_id: u32,
    is_eu: bool,
    name_en: String,
    name_zh: String,
    default_tz: String,
    aliases: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CnDivisionJson {
    #[allow(dead_code)]
    adcode: String,
    level: u8,
    iso_code: String,
    province_zh: String,
    province_en: String,
    city_zh: String,
    city_en: String,
    district_zh: String,
    district_en: String,
    geoname_id: u32,
    lat: f64,
    lon: f64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CloudRegionJson {
    provider: String,
    region: String,
    iso_code: String,
    subdivision_iso: String,
    subdivision_en: String,
    city_en: String,
    tz: String,
    lat: f64,
    lon: f64,
}

#[derive(Clone, Debug)]
pub struct MetadataRegistry {
    pub countries: FxHashMap<IsoCode, CountryMeta>,
    country_aliases: FxHashMap<String, IsoCode>,
    cn_provinces_by_iso: FxHashMap<String, CnDivisionMeta>,
    cn_provinces_by_key: FxHashMap<String, CnDivisionMeta>,
    cn_cities_by_prov_and_key: FxHashMap<(String, String), CnDivisionMeta>,
    cn_cities_by_key: FxHashMap<String, CnDivisionMeta>,
    prov_prefixes: Vec<String>,
    cloud_regions: FxHashMap<(String, String), CloudRegionMeta>,
}

impl MetadataRegistry {
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let raw = fs::read(path)
            .with_context(|| format!("failed to read metadata JSON {}", path.display()))?;
        let bundle: MetadataBundleJson = serde_json::from_slice(&raw)
            .with_context(|| format!("failed to parse metadata JSON {}", path.display()))?;
        if bundle.schema_version != 1 {
            bail!(
                "unsupported metadata schemaVersion {} in {}",
                bundle.schema_version,
                path.display()
            );
        }

        let mut countries = FxHashMap::default();
        let mut country_aliases = FxHashMap::default();
        for c in bundle.countries {
            let iso = IsoCode::parse_raw(&c.iso_code).with_context(|| {
                format!(
                    "{}: invalid country isoCode '{}'",
                    path.display(),
                    c.iso_code
                )
            })?;
            let meta = CountryMeta {
                iso_code: iso,
                continent_code: c.continent_code,
                continent_geoname_id: c.continent_geoname_id,
                continent_en: c.continent_en,
                continent_zh: c.continent_zh,
                geoname_id: c.geoname_id,
                is_eu: c.is_eu,
                name_en: c.name_en,
                name_zh: c.name_zh,
                default_tz: c.default_tz,
            };
            country_aliases.insert(iso.as_str().to_ascii_lowercase(), iso);
            country_aliases.insert(meta.name_en.to_ascii_lowercase(), iso);
            country_aliases.insert(meta.name_zh.to_lowercase(), iso);
            for alias in c.aliases {
                let norm = alias.trim().to_lowercase();
                if !norm.is_empty() {
                    country_aliases.insert(norm, iso);
                }
            }
            countries.insert(iso, meta);
        }

        let mut cn_provinces_by_iso = FxHashMap::default();
        let mut cn_provinces_by_key = FxHashMap::default();
        let mut cn_cities_by_prov_and_key = FxHashMap::default();
        let mut cn_cities_by_key = FxHashMap::default();
        let mut prov_prefixes: Vec<String> = Vec::new();
        let mut level3_rows: Vec<&CnDivisionJson> = Vec::new();

        let quantize_opt = |v: f64| -> i32 {
            if v == 0.0 || !v.is_finite() {
                COORD_UNSET
            } else {
                quantize_coord(v)
            }
        };

        for d in &bundle.cn_divisions {
            let prov_iso = d.iso_code.trim().to_ascii_uppercase();
            if d.level == 1 {
                let is_municipality = matches!(prov_iso.as_str(), "BJ" | "TJ" | "SH" | "CQ");
                let div = CnDivisionMeta {
                    province_zh: d.province_zh.clone(),
                    city_zh: if is_municipality {
                        d.province_zh.clone()
                    } else {
                        String::new()
                    },
                    iso_code: prov_iso.clone(),
                    province_en: d.province_en.clone(),
                    city_en: if is_municipality {
                        d.province_en.clone()
                    } else {
                        String::new()
                    },
                    geoname_id: d.geoname_id,
                    lat_e5: quantize_opt(d.lat),
                    lon_e5: quantize_opt(d.lon),
                };
                let prov_stem = strip_cn_admin_suffix(&div.province_zh);
                cn_provinces_by_iso.insert(prov_iso.clone(), div.clone());
                cn_provinces_by_key.insert(div.province_zh.to_lowercase(), div.clone());
                cn_provinces_by_key.insert(prov_stem.to_lowercase(), div.clone());
                cn_provinces_by_key.insert(div.province_en.to_ascii_lowercase(), div.clone());
                cn_provinces_by_key.insert(prov_iso.to_ascii_lowercase(), div.clone());

                if !div.province_zh.is_empty() {
                    prov_prefixes.push(div.province_zh.clone());
                }
                if !prov_stem.is_empty() && prov_stem != div.province_zh {
                    prov_prefixes.push(prov_stem.to_string());
                }
            } else if d.level == 2 {
                let div = CnDivisionMeta {
                    province_zh: d.province_zh.clone(),
                    city_zh: d.city_zh.clone(),
                    iso_code: prov_iso.clone(),
                    province_en: d.province_en.clone(),
                    city_en: d.city_en.clone(),
                    geoname_id: d.geoname_id,
                    lat_e5: quantize_opt(d.lat),
                    lon_e5: quantize_opt(d.lon),
                };
                let city_stem = strip_cn_admin_suffix(&div.city_zh);
                for ck in [
                    div.city_zh.to_lowercase(),
                    city_stem.to_lowercase(),
                    div.city_en.to_ascii_lowercase(),
                ] {
                    if !ck.is_empty() {
                        cn_cities_by_prov_and_key
                            .insert((prov_iso.clone(), ck.clone()), div.clone());
                        cn_cities_by_key.entry(ck).or_insert_with(|| div.clone());
                    }
                }
            } else if d.level == 3 {
                level3_rows.push(d);
            }
        }

        // Index level-3 divisions after level-2 prefecture cities so prefecture cities keep priority on shared short stems.
        for d in level3_rows {
            if d.district_zh.is_empty() {
                continue;
            }
            let prov_iso = d.iso_code.trim().to_ascii_uppercase();
            let is_independent_city = d.city_zh.is_empty() || d.district_zh.ends_with('市');
            let div = CnDivisionMeta {
                province_zh: d.province_zh.clone(),
                city_zh: if is_independent_city {
                    d.district_zh.clone()
                } else {
                    d.city_zh.clone()
                },
                iso_code: prov_iso.clone(),
                province_en: d.province_en.clone(),
                city_en: if is_independent_city {
                    d.district_en.clone()
                } else {
                    d.city_en.clone()
                },
                geoname_id: d.geoname_id,
                lat_e5: quantize_opt(d.lat),
                lon_e5: quantize_opt(d.lon),
            };
            let dist_stem = strip_cn_district_suffix(&d.district_zh);
            for ck in [
                d.district_zh.to_lowercase(),
                dist_stem.to_lowercase(),
                d.district_en.to_ascii_lowercase(),
            ] {
                if !ck.is_empty() {
                    cn_cities_by_prov_and_key
                        .entry((prov_iso.clone(), ck.clone()))
                        .or_insert_with(|| div.clone());
                    cn_cities_by_key.entry(ck).or_insert_with(|| div.clone());
                }
            }
        }

        prov_prefixes.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        prov_prefixes.dedup();

        let mut cloud_regions = FxHashMap::default();
        for r in bundle.cloud_regions {
            let Some(iso) = IsoCode::parse_raw(&r.iso_code) else {
                continue;
            };
            let meta = CloudRegionMeta {
                provider: r.provider.trim().to_ascii_lowercase(),
                region: r.region.trim().to_ascii_lowercase(),
                iso_code: iso,
                subdivision_iso: r.subdivision_iso,
                subdivision_en: r.subdivision_en,
                city_en: r.city_en,
                tz: r.tz,
                lat_e5: quantize_opt(r.lat),
                lon_e5: quantize_opt(r.lon),
            };
            cloud_regions.insert((meta.provider.clone(), meta.region.clone()), meta);
        }

        Ok(Self {
            countries,
            country_aliases,
            cn_provinces_by_iso,
            cn_provinces_by_key,
            cn_cities_by_prov_and_key,
            cn_cities_by_key,
            prov_prefixes,
            cloud_regions,
        })
    }

    #[inline]
    pub fn validate_iso(&self, iso: IsoCode) -> Option<IsoCode> {
        if self.countries.contains_key(&iso) {
            Some(iso)
        } else {
            None
        }
    }

    pub fn resolve_country(&self, raw: &str) -> Option<IsoCode> {
        let s = raw.trim();
        if s.is_empty()
            || matches!(
                s,
                "0" | "-" | "*" | "N/A" | "Unknown" | "未知" | "保留地址" | "局域网"
            )
        {
            return None;
        }
        if let Some(iso) = IsoCode::parse_raw(s)
            && self.countries.contains_key(&iso)
        {
            return Some(iso);
        }
        let lower = s.to_lowercase();
        if let Some(&iso) = self.country_aliases.get(&lower)
            && self.countries.contains_key(&iso)
        {
            return Some(iso);
        }
        if let Some(rest) = s.strip_prefix("中国")
            && matches!(rest.trim(), "" | "大陆" | "内地")
        {
            return Some(IsoCode::CN);
        }
        if lower.contains("香港") || lower == "hong kong" {
            return Some(IsoCode::HK);
        }
        if lower.contains("澳门") || lower == "macau" || lower == "macao" {
            return Some(IsoCode::MO);
        }
        if lower.contains("台湾") || lower == "taiwan" {
            return Some(IsoCode::TW);
        }
        // Check if string is a Chinese Mainland province directly (as in QQWry `"广东省深圳市"`)
        if self.split_cn_location(s).is_some() {
            return Some(IsoCode::CN);
        }
        None
    }

    pub fn resolve_cn_province(&self, raw: &str) -> Option<&CnDivisionMeta> {
        let trimmed = raw
            .trim()
            .trim_start_matches("CN-")
            .trim_start_matches("cn-");
        if trimmed.is_empty() || trimmed == "0" || trimmed == "-" {
            return None;
        }
        if let Some(m) = self.cn_provinces_by_iso.get(&trimmed.to_ascii_uppercase()) {
            return Some(m);
        }
        let stem = strip_cn_admin_suffix(trimmed).to_lowercase();
        self.cn_provinces_by_key
            .get(&stem)
            .or_else(|| self.cn_provinces_by_key.get(&trimmed.to_lowercase()))
    }

    pub fn resolve_cn_division(
        &self,
        prov_raw: &str,
        city_raw: &str,
    ) -> (Option<&CnDivisionMeta>, Option<&CnDivisionMeta>) {
        let prov = self.resolve_cn_province(prov_raw);
        let city_clean = clean_cn_city_token(city_raw);
        let city = if !city_clean.is_empty() {
            let city_stem =
                strip_cn_district_suffix(strip_cn_admin_suffix(city_clean)).to_lowercase();
            let admin_stem = strip_cn_admin_suffix(city_clean).to_lowercase();
            if let Some(p) = prov {
                self.cn_cities_by_prov_and_key
                    .get(&(p.iso_code.clone(), admin_stem.clone()))
                    .or_else(|| {
                        self.cn_cities_by_prov_and_key
                            .get(&(p.iso_code.clone(), city_stem.clone()))
                    })
                    .or_else(|| {
                        self.cn_cities_by_prov_and_key
                            .get(&(p.iso_code.clone(), city_clean.to_lowercase()))
                    })
                    .or_else(|| self.cn_cities_by_key.get(&admin_stem))
            } else {
                self.cn_cities_by_key
                    .get(&admin_stem)
                    .or_else(|| self.cn_cities_by_key.get(&city_stem))
                    .or_else(|| self.cn_cities_by_key.get(&city_clean.to_lowercase()))
            }
        } else {
            None
        };
        let resolved_prov =
            prov.or_else(|| city.and_then(|c| self.cn_provinces_by_iso.get(&c.iso_code)));
        (resolved_prov, city)
    }

    /// Parses concatenated Chinese location strings such as `"广东省深圳市南山区"` or `"北京市海淀区"` or `"内蒙古呼和浩特市"`.
    pub fn split_cn_location(
        &self,
        text: &str,
    ) -> Option<(&CnDivisionMeta, Option<&CnDivisionMeta>)> {
        let mut s = text.trim();
        if let Some(rest) = s.strip_prefix("中国") {
            s = rest.trim_start_matches(['|', '-', ' ', '\t', '·']);
        }
        if s.is_empty() {
            return None;
        }

        for prefix in &self.prov_prefixes {
            if let Some(rest) = s.strip_prefix(prefix.as_str())
                && let Some(prov) = self.resolve_cn_province(prefix)
            {
                let rest = rest.trim();
                if rest.is_empty() {
                    let muni_city = if matches!(prov.iso_code.as_str(), "BJ" | "TJ" | "SH" | "CQ") {
                        Some(prov)
                    } else {
                        None
                    };
                    return Some((prov, muni_city));
                }
                let city_candidate = if let Some(pos) = rest.find('市') {
                    let first_end = pos + '市'.len_utf8();
                    let trailing_raw = rest[first_end..].trim();
                    if let Some(pos2) = trailing_raw.find('市') {
                        let trailing_city = &trailing_raw[..pos2 + '市'.len_utf8()];
                        if self
                            .resolve_cn_division(&prov.iso_code, trailing_city)
                            .1
                            .is_some()
                        {
                            trailing_city
                        } else {
                            &rest[..first_end]
                        }
                    } else {
                        &rest[..first_end]
                    }
                } else {
                    rest
                };
                let (_, city) = self.resolve_cn_division(&prov.iso_code, city_candidate);
                let city = city.or(
                    if matches!(prov.iso_code.as_str(), "BJ" | "TJ" | "SH" | "CQ") {
                        Some(prov)
                    } else {
                        None
                    },
                );
                return Some((prov, city));
            }
        }
        None
    }

    pub fn resolve_cloud_region(&self, provider: &str, region: &str) -> Option<&CloudRegionMeta> {
        let prov = provider.trim().to_ascii_lowercase();
        let reg = region.trim().to_ascii_lowercase();
        if reg.is_empty() || reg == "global" {
            return None;
        }
        if let Some(m) = self.cloud_regions.get(&(prov.clone(), reg.clone())) {
            return Some(m);
        }
        // Handle sub-zones / local zones such as `us-east-1-bos-1` -> `us-east-1` or `us-central1-a` -> `us-central1`
        let parts: Vec<&str> = reg.split('-').collect();
        if parts.len() >= 3 {
            let base3 = format!("{}-{}-{}", parts[0], parts[1], parts[2]);
            if let Some(m) = self.cloud_regions.get(&(prov.clone(), base3)) {
                return Some(m);
            }
            // Strip trailing single zone letter e.g. `us-east-1a`
            let trimmed_zone = reg.trim_end_matches(|c: char| c.is_ascii_lowercase());
            let trimmed_zone = trimmed_zone.trim_end_matches('-');
            if let Some(m) = self
                .cloud_regions
                .get(&(prov.clone(), trimmed_zone.to_string()))
            {
                return Some(m);
            }
        }
        if parts.len() >= 2 {
            let base2 = format!("{}-{}", parts[0], parts[1]);
            if let Some(m) = self.cloud_regions.get(&(prov, base2)) {
                return Some(m);
            }
        }
        None
    }
}

pub fn strip_cn_admin_suffix(s: &str) -> &str {
    let s = s.trim();
    for suffix in [
        "维吾尔自治区",
        "壮族自治区",
        "回族自治区",
        "特别行政区",
        "自治区",
        "自治州",
        "地区",
        "省",
        "市",
        "盟",
    ] {
        if let Some(stripped) = s.strip_suffix(suffix)
            && !stripped.is_empty()
        {
            return stripped;
        }
    }
    s
}

fn strip_cn_district_suffix(s: &str) -> &str {
    let s = s.trim();
    for suffix in ["新区", "自治县", "自治旗", "林区", "特区", "区", "县", "旗"] {
        if let Some(stripped) = s.strip_suffix(suffix)
            && stripped.chars().count() >= 2
        {
            return stripped;
        }
    }
    s
}

fn clean_cn_city_token(raw: &str) -> &str {
    let s = raw.trim();
    if matches!(s, "" | "0" | "-" | "*" | "未知" | "内网IP" | "局域网") {
        ""
    } else {
        s
    }
}

/// Normalizes Chinese and English ISP strings to clean canonical names.
pub fn normalize_isp_name(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let lower = s.to_lowercase();
    if matches!(
        lower.as_str(),
        "0" | "-"
            | "*"
            | "unknown"
            | "n/a"
            | "null"
            | "cz88.net"
            | "纯真网络"
            | "局域网"
            | "对方和您在同一内部网"
            | "保留地址"
            | "本机地址"
            | "anycast"
    ) {
        return None;
    }

    if lower.contains("中华电信") || lower.contains("hinet") || lower.contains("chunghwa telecom")
    {
        return Some("Chunghwa Telecom".to_string());
    }
    if lower.contains("远传电信") || lower.contains("fareastone") {
        return Some("Far EasTone".to_string());
    }
    if lower.contains("台湾大哥大") || lower.contains("taiwan mobile") {
        return Some("Taiwan Mobile".to_string());
    }
    if lower.contains("香港宽频") || lower.contains("hkbn") {
        return Some("HKBN".to_string());
    }
    if lower.contains("电讯盈科") || lower.contains("pccw") || lower.contains("hkt") {
        return Some("HKT".to_string());
    }

    if lower.contains("电信") || lower.contains("chinanet") || lower == "china telecom" {
        return Some("China Telecom".to_string());
    }
    if lower.contains("联通")
        || lower.contains("网通")
        || lower.contains("china unicom")
        || lower == "unicom"
    {
        return Some("China Unicom".to_string());
    }
    if lower.contains("移动")
        || lower.contains("铁通")
        || lower.contains("china mobile")
        || lower == "cmcc"
    {
        return Some("China Mobile".to_string());
    }
    if lower.contains("广电") || lower.contains("有线通") || lower.contains("china broadnet") {
        return Some("China Broadnet".to_string());
    }
    if lower.contains("教育网") || lower == "cernet" {
        return Some("CERNET".to_string());
    }
    if lower.contains("科技网") || lower == "cstnet" {
        return Some("CSTNET".to_string());
    }
    if lower.contains("鹏博士")
        || lower.contains("长城宽带")
        || lower.contains("宽带通")
        || lower.contains("dr.peng")
    {
        return Some("Dr.Peng".to_string());
    }
    if lower.contains("阿里云") || lower.contains("alibaba cloud") || lower == "aliyun" {
        return Some("Alibaba Cloud".to_string());
    }
    if lower.contains("腾讯云") || lower.contains("tencent cloud") {
        return Some("Tencent Cloud".to_string());
    }
    if lower.contains("华为云") || lower.contains("huawei cloud") {
        return Some("Huawei Cloud".to_string());
    }
    if lower.contains("百度云") || lower.contains("baidu cloud") || lower == "baidu" {
        return Some("Baidu".to_string());
    }
    if lower.contains("火山引擎") || lower.contains("字节跳动") || lower.contains("bytedance")
    {
        return Some("ByteDance".to_string());
    }
    if lower.contains("京东云") || lower.contains("jd cloud") {
        return Some("JD Cloud".to_string());
    }
    if lower.contains("金山云") || lower.contains("kingsoft cloud") {
        return Some("Kingsoft Cloud".to_string());
    }
    if lower.contains("美团云") || lower.contains("美团") {
        return Some("Meituan".to_string());
    }

    Some(s.to_string())
}
