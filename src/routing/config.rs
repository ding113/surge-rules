use std::fmt;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};

use crate::config::EndpointConfig;
use crate::fetch::FetchableSource;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingTarget {
    Direct,
    Ai,
    Proxy,
}

impl RoutingTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Ai => "ai",
            Self::Proxy => "proxy",
        }
    }

    pub fn filename(self) -> &'static str {
        match self {
            Self::Direct => "Direct.list",
            Self::Ai => "AI.list",
            Self::Proxy => "Proxy.list",
        }
    }
}

impl fmt::Display for RoutingTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingSourceFormat {
    SurgeRuleset,
    DomainSet,
    ClashClassical,
    ClashYaml,
    Geosite,
    DnsmasqChina,
    GfwlistBase64,
    IpCidr,
    AsnList,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeositeTagFilter {
    AllNonAds,
    OnlyCn,
    ExcludeCn,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
pub enum RoutingRuleKind {
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainWildcard,
    IpCidr,
    IpCidr6,
    IpAsn,
    UrlRegex,
    UserAgent,
    ProcessName,
    And,
}

impl RoutingRuleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "DOMAIN",
            Self::DomainSuffix => "DOMAIN-SUFFIX",
            Self::DomainKeyword => "DOMAIN-KEYWORD",
            Self::DomainWildcard => "DOMAIN-WILDCARD",
            Self::IpCidr => "IP-CIDR",
            Self::IpCidr6 => "IP-CIDR6",
            Self::IpAsn => "IP-ASN",
            Self::UrlRegex => "URL-REGEX",
            Self::UserAgent => "USER-AGENT",
            Self::ProcessName => "PROCESS-NAME",
            Self::And => "AND",
        }
    }

    pub fn parse_token(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_uppercase().as_str() {
            "DOMAIN" => Some(Self::Domain),
            "DOMAIN-SUFFIX" => Some(Self::DomainSuffix),
            "DOMAIN-KEYWORD" => Some(Self::DomainKeyword),
            "DOMAIN-WILDCARD" => Some(Self::DomainWildcard),
            "IP-CIDR" => Some(Self::IpCidr),
            "IP-CIDR6" => Some(Self::IpCidr6),
            "IP-ASN" => Some(Self::IpAsn),
            "URL-REGEX" => Some(Self::UrlRegex),
            "USER-AGENT" => Some(Self::UserAgent),
            "PROCESS-NAME" => Some(Self::ProcessName),
            "AND" => Some(Self::And),
            _ => None,
        }
    }

    pub fn supports_extended_matching(self) -> bool {
        matches!(
            self,
            Self::Domain
                | Self::DomainSuffix
                | Self::DomainKeyword
                | Self::DomainWildcard
                | Self::UrlRegex
        )
    }

    pub fn requires_no_resolve(self) -> bool {
        matches!(self, Self::IpCidr | Self::IpCidr6 | Self::IpAsn)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingSourceConfig {
    pub id: String,
    pub name: String,
    pub target: RoutingTarget,
    pub lineage: String,
    pub format: RoutingSourceFormat,
    #[serde(default)]
    pub geosite_filter: Option<GeositeTagFilter>,
    pub weight: u16,
    #[serde(default)]
    pub core: bool,
    pub endpoints: Vec<EndpointConfig>,
}

impl FetchableSource for RoutingSourceConfig {
    fn id(&self) -> &str {
        &self.id
    }

    fn is_core(&self) -> bool {
        self.core
    }

    fn endpoints(&self) -> &[EndpointConfig] {
        &self.endpoints
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingSourceCatalog {
    pub schema_version: u32,
    pub sources: Vec<RoutingSourceConfig>,
}

impl RoutingSourceCatalog {
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read routing catalog {}", path.display()))?;
        let catalog: Self = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse routing catalog {}", path.display()))?;
        if catalog.schema_version != 1 {
            bail!(
                "unsupported routing catalog schemaVersion {} in {}",
                catalog.schema_version,
                path.display()
            );
        }
        if catalog.sources.is_empty() {
            bail!("routing catalog {} contains zero sources", path.display());
        }
        let mut seen = FxHashSet::default();
        for src in &catalog.sources {
            if src.id.trim().is_empty() {
                bail!("routing source with empty id in {}", path.display());
            }
            if !seen.insert(src.id.clone()) {
                bail!("duplicate routing source id '{}'", src.id);
            }
            if src.endpoints.is_empty() {
                bail!("routing source '{}' has no endpoints", src.id);
            }
            if src.lineage.trim().is_empty() {
                bail!("routing source '{}' has empty lineage", src.id);
            }
            if src.weight == 0 {
                bail!("routing source '{}' must have positive weight", src.id);
            }
            if src.format == RoutingSourceFormat::Geosite && src.geosite_filter.is_none() {
                bail!(
                    "geosite routing source '{}' is missing geositeFilter",
                    src.id
                );
            }
        }
        Ok(catalog)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedInfraRootEntry {
    pub domain: String,
    #[allow(dead_code)]
    pub rationale: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingRuleOverride {
    pub target: RoutingTarget,
    pub kind: RoutingRuleKind,
    pub value: String,
    #[serde(default)]
    pub extended_matching: bool,
    #[allow(dead_code)]
    pub rationale: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingExclusionOverride {
    pub target: RoutingTarget,
    pub kind: RoutingRuleKind,
    pub value: String,
    #[allow(dead_code)]
    pub rationale: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingOverrides {
    pub schema_version: u32,
    pub shared_infra_roots: Vec<SharedInfraRootEntry>,
    pub force_entries: Vec<RoutingRuleOverride>,
    pub exclude_entries: Vec<RoutingExclusionOverride>,
}

impl RoutingOverrides {
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read routing overrides {}", path.display()))?;
        let parsed: Self = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse routing overrides {}", path.display()))?;
        if parsed.schema_version != 1 {
            bail!(
                "unsupported routing overrides schemaVersion {} in {}",
                parsed.schema_version,
                path.display()
            );
        }
        Ok(parsed)
    }

    pub fn empty() -> Self {
        Self {
            schema_version: 1,
            shared_infra_roots: Vec::new(),
            force_entries: Vec::new(),
            exclude_entries: Vec::new(),
        }
    }
}
