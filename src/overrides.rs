use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rustc_hash::FxHashMap;
use serde::Deserialize;

use crate::config::MetadataRegistry;
use crate::model::{IsoCode, TraitFlags};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawSpecialNetworkEntry {
    pub cidr: String,
    pub network_type: String,
    #[serde(default)]
    pub virtual_network: Option<String>,
    pub organization: String,
    pub is_bogon: bool,
    pub is_private: bool,
    pub is_virtual_mesh: bool,
    pub rfc_or_doc: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawCountryOverrideEntry {
    pub cidr: String,
    pub iso_code: String,
    #[serde(default)]
    pub registered_iso_code: Option<String>,
    #[serde(default)]
    pub subdivision_iso_code: Option<String>,
    #[serde(default)]
    pub city_en: Option<String>,
    #[serde(default)]
    pub city_zh_cn: Option<String>,
    #[serde(default)]
    pub isp: Option<String>,
    #[serde(default)]
    pub organization: Option<String>,
    #[serde(default)]
    pub is_anycast: Option<bool>,
    #[serde(default)]
    pub clear_city: Option<bool>,
    pub rationale: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawCnExclusionEntry {
    pub cidr: String,
    #[serde(default)]
    pub fallback_iso_code: Option<String>,
    #[serde(default)]
    pub asn: Option<u32>,
    pub rationale: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawAsnOverrideEntry {
    pub asn: u32,
    pub organization: String,
    #[serde(default)]
    pub isp: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub country_hint: Option<String>,
    #[serde(default)]
    pub province_hint_zh_cn: Option<String>,
    #[serde(default)]
    pub is_hosting: Option<bool>,
    #[serde(default)]
    pub is_cdn: Option<bool>,
    #[serde(default)]
    pub is_anycast: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawOverridesBundle {
    pub schema_version: u32,
    pub special_networks: Vec<RawSpecialNetworkEntry>,
    pub country_overrides: Vec<RawCountryOverrideEntry>,
    pub cn_exclusions: Vec<RawCnExclusionEntry>,
    pub asn_overrides: Vec<RawAsnOverrideEntry>,
}

#[derive(Clone, Debug)]
pub struct SpecialNetworkRule {
    pub net: IpNet,
    pub prefix_len: u8,
    pub network_type: String,
    pub virtual_network: Option<String>,
    pub organization: String,
    pub traits: TraitFlags,
}

#[derive(Clone, Debug)]
pub struct CountryOverrideRule {
    pub net: IpNet,
    pub prefix_len: u8,
    pub iso_code: IsoCode,
    pub registered_iso_code: Option<IsoCode>,
    pub subdivision_iso_code: Option<String>,
    pub city_en: Option<String>,
    pub city_zh_cn: Option<String>,
    pub isp: Option<String>,
    pub organization: Option<String>,
    pub is_anycast: bool,
    pub clear_city: bool,
}

#[derive(Clone, Debug)]
pub struct CnExclusionRule {
    pub net: IpNet,
    pub prefix_len: u8,
    pub fallback_iso_code: Option<IsoCode>,
    pub asn: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct CompiledOverrides {
    pub special_v4: Vec<(Ipv4Net, SpecialNetworkRule)>,
    pub special_v6: Vec<(Ipv6Net, SpecialNetworkRule)>,
    pub country_v4: Vec<(Ipv4Net, CountryOverrideRule)>,
    pub country_v6: Vec<(Ipv6Net, CountryOverrideRule)>,
    pub cn_excl_v4: Vec<(Ipv4Net, CnExclusionRule)>,
    pub cn_excl_v6: Vec<(Ipv6Net, CnExclusionRule)>,
    pub asn_overrides: FxHashMap<u32, RawAsnOverrideEntry>,
}

impl CompiledOverrides {
    pub fn load_from_path(path: &Path, metadata: &MetadataRegistry) -> Result<Self> {
        let raw_str = fs::read_to_string(path)
            .with_context(|| format!("failed to read overrides {}", path.display()))?;
        let raw: RawOverridesBundle = serde_json::from_str(&raw_str)
            .with_context(|| format!("failed to parse overrides {}", path.display()))?;
        if raw.schema_version != 1 {
            bail!(
                "unsupported overrides schemaVersion {} in {}",
                raw.schema_version,
                path.display()
            );
        }

        let mut special_v4 = Vec::new();
        let mut special_v6 = Vec::new();
        for item in raw.special_networks {
            let net: IpNet = item
                .cidr
                .parse::<IpNet>()
                .with_context(|| format!("invalid specialNetwork CIDR '{}'", item.cidr))?
                .trunc();
            let mut traits = TraitFlags::EMPTY;
            if item.is_bogon {
                traits.insert(TraitFlags::IS_BOGON);
            }
            if item.is_private {
                traits.insert(TraitFlags::IS_PRIVATE);
            }
            if item.is_virtual_mesh {
                traits.insert(TraitFlags::IS_VIRTUAL_MESH);
            }
            let rule = SpecialNetworkRule {
                net,
                prefix_len: net.prefix_len(),
                network_type: item.network_type,
                virtual_network: item.virtual_network,
                organization: item.organization,
                traits,
            };
            match net {
                IpNet::V4(v4) => special_v4.push((v4, rule)),
                IpNet::V6(v6) => {
                    if v6.to_string() == "::/96" || v6.to_string() == "::ffff:0:0/96" {
                        bail!("IPv4 subtree mount '{}' must not be in special_v6", v6);
                    }
                    special_v6.push((v6, rule));
                }
            }
        }

        let mut country_v4 = Vec::new();
        let mut country_v6 = Vec::new();
        for item in raw.country_overrides {
            let net: IpNet = item
                .cidr
                .parse::<IpNet>()
                .with_context(|| format!("invalid countryOverride CIDR '{}'", item.cidr))?
                .trunc();
            let iso = IsoCode::parse_raw(&item.iso_code)
                .and_then(|c| metadata.validate_iso(c))
                .with_context(|| {
                    format!(
                        "invalid countryOverride isoCode '{}' on {}",
                        item.iso_code, item.cidr
                    )
                })?;
            let registered_iso_code = match item.registered_iso_code.as_deref() {
                Some(rc) => Some(
                    IsoCode::parse_raw(rc)
                        .and_then(|c| metadata.validate_iso(c))
                        .with_context(|| {
                            format!("invalid registeredIsoCode '{}' on {}", rc, item.cidr)
                        })?,
                ),
                None => None,
            };
            let rule = CountryOverrideRule {
                net,
                prefix_len: net.prefix_len(),
                iso_code: iso,
                registered_iso_code,
                subdivision_iso_code: item.subdivision_iso_code,
                city_en: item.city_en,
                city_zh_cn: item.city_zh_cn,
                isp: item.isp,
                organization: item.organization,
                is_anycast: item.is_anycast.unwrap_or(false),
                clear_city: item.clear_city.unwrap_or(false),
            };
            match net {
                IpNet::V4(v4) => country_v4.push((v4, rule)),
                IpNet::V6(v6) => country_v6.push((v6, rule)),
            }
        }

        let mut cn_excl_v4 = Vec::new();
        let mut cn_excl_v6 = Vec::new();
        for item in raw.cn_exclusions {
            let net: IpNet = item
                .cidr
                .parse::<IpNet>()
                .with_context(|| format!("invalid cnExclusion CIDR '{}'", item.cidr))?
                .trunc();
            let fallback_iso_code = match item.fallback_iso_code.as_deref() {
                Some(fc) => Some(
                    IsoCode::parse_raw(fc)
                        .and_then(|c| metadata.validate_iso(c))
                        .with_context(|| {
                            format!("invalid fallbackIsoCode '{}' on {}", fc, item.cidr)
                        })?,
                ),
                None => None,
            };
            let rule = CnExclusionRule {
                net,
                prefix_len: net.prefix_len(),
                fallback_iso_code,
                asn: item.asn,
            };
            match net {
                IpNet::V4(v4) => cn_excl_v4.push((v4, rule)),
                IpNet::V6(v6) => cn_excl_v6.push((v6, rule)),
            }
        }

        let mut asn_overrides = FxHashMap::default();
        for item in raw.asn_overrides {
            if item.asn == 0 {
                bail!("asnOverride cannot specify ASN 0");
            }
            asn_overrides.insert(item.asn, item);
        }

        Ok(Self {
            special_v4,
            special_v6,
            country_v4,
            country_v6,
            cn_excl_v4,
            cn_excl_v6,
            asn_overrides,
        })
    }
}
