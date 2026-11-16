use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use rustc_hash::FxHashSet;
use serde::Deserialize;

use crate::config::EndpointConfig;
use crate::fetch::FetchableSource;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdblockSourceRole {
    Allowlist,
    ComplexFirst,
    RulesetFallback,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdblockCategory {
    #[default]
    Ad,
    Privacy,
    AdMixed,
    Both,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdblockRuleTarget {
    #[default]
    Ad,
    Privacy,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdblockSourceFormat {
    SurgeModule,
    QxRewrite,
    SurgeRuleset,
    SurgeDomainset,
    AbpFilter,
    Hosts,
    DomainList,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdblockPlatformScope {
    Universal,
    Mobile,
    Desktop,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdblockSourceConfig {
    pub id: String,
    pub role: AdblockSourceRole,
    #[serde(default)]
    pub category: AdblockCategory,
    pub format: AdblockSourceFormat,
    pub platform: AdblockPlatformScope,
    pub lineage: String,
    pub weight: u16,
    #[serde(default)]
    pub core: bool,
    #[serde(default)]
    pub extract_complex_network_rules: bool,
    #[serde(default)]
    pub extract_fallback_domain_rules: bool,
    pub endpoints: Vec<EndpointConfig>,
}

impl FetchableSource for AdblockSourceConfig {
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
pub struct AdblockSourceCatalog {
    pub schema_version: u32,
    pub sources: Vec<AdblockSourceConfig>,
}

impl AdblockSourceCatalog {
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read adblock catalog {}", path.display()))?;
        let catalog: Self = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse adblock catalog {}", path.display()))?;
        if catalog.schema_version != 1 {
            bail!(
                "unsupported adblock catalog schemaVersion {} in {}",
                catalog.schema_version,
                path.display()
            );
        }
        if catalog.sources.is_empty() {
            bail!("adblock catalog {} contains zero sources", path.display());
        }
        let mut seen = FxHashSet::default();
        for src in &catalog.sources {
            if !seen.insert(src.id.as_str()) {
                bail!(
                    "duplicate adblock source id '{}' in {}",
                    src.id,
                    path.display()
                );
            }
            if src.endpoints.is_empty() {
                bail!("adblock source '{}' has zero endpoints", src.id);
            }
            match src.role {
                AdblockSourceRole::Allowlist => {
                    if src.category == AdblockCategory::AdMixed {
                        bail!(
                            "allowlist source '{}' cannot use category 'ad_mixed'",
                            src.id
                        );
                    }
                }
                AdblockSourceRole::ComplexFirst | AdblockSourceRole::RulesetFallback => {
                    if src.category == AdblockCategory::Both {
                        bail!(
                            "blocklist/complex source '{}' cannot use category 'both'",
                            src.id
                        );
                    }
                }
            }
        }
        Ok(catalog)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowDomainMatchType {
    Exact,
    Suffix,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowDomainOverride {
    pub match_type: AllowDomainMatchType,
    pub domain: String,
    #[allow(dead_code)]
    pub rationale: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectedApexDomainOverride {
    pub domain: String,
    #[allow(dead_code)]
    pub rationale: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForceRuleSetOverride {
    #[serde(default)]
    pub target: AdblockRuleTarget,
    pub kind: String,
    pub value: String,
    #[allow(dead_code)]
    pub rationale: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MitmHostOverride {
    pub pattern: String,
    #[allow(dead_code)]
    pub rationale: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleUrlRewriteOverride {
    pub pattern: String,
    pub replacement: String,
    pub mode: String,
    #[allow(dead_code)]
    pub rationale: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleMapLocalOverride {
    pub pattern: String,
    pub data_type: String,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default)]
    pub status_code: Option<u16>,
    #[serde(default)]
    pub header: Option<String>,
    #[allow(dead_code)]
    pub rationale: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleHeaderRewriteOverride {
    pub direction: String,
    pub pattern: String,
    pub action: String,
    pub field: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub replace_regex: Option<String>,
    #[allow(dead_code)]
    pub rationale: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleBodyRewriteOverride {
    pub kind: String,
    pub pattern: String,
    pub expression: String,
    #[serde(default)]
    pub replacement: Option<String>,
    #[allow(dead_code)]
    pub rationale: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleScriptOverride {
    pub name: String,
    pub script_type: String,
    pub pattern: String,
    pub script_path: String,
    #[serde(default)]
    pub requires_body: bool,
    #[serde(default)]
    pub binary_body_mode: bool,
    #[serde(default)]
    pub max_size: Option<i64>,
    #[serde(default)]
    pub argument: Option<String>,
    #[allow(dead_code)]
    pub rationale: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdblockOverrides {
    pub schema_version: u32,
    pub allow_domains: Vec<AllowDomainOverride>,
    pub protected_apex_domains: Vec<ProtectedApexDomainOverride>,
    pub force_rule_set_entries: Vec<ForceRuleSetOverride>,
    pub mitm_excluded_hosts: Vec<MitmHostOverride>,
    pub mitm_added_hosts: Vec<MitmHostOverride>,
    pub disabled_url_patterns: Vec<String>,
    pub url_rewrites: Vec<ModuleUrlRewriteOverride>,
    pub map_locals: Vec<ModuleMapLocalOverride>,
    pub header_rewrites: Vec<ModuleHeaderRewriteOverride>,
    pub body_rewrites: Vec<ModuleBodyRewriteOverride>,
    pub scripts: Vec<ModuleScriptOverride>,
}

impl AdblockOverrides {
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read adblock overrides {}", path.display()))?;
        let parsed: Self = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse adblock overrides {}", path.display()))?;
        if parsed.schema_version != 1 {
            bail!(
                "unsupported adblock overrides schemaVersion {} in {}",
                parsed.schema_version,
                path.display()
            );
        }
        Ok(parsed)
    }

    pub fn empty() -> Self {
        Self {
            schema_version: 1,
            allow_domains: Vec::new(),
            protected_apex_domains: Vec::new(),
            force_rule_set_entries: Vec::new(),
            mitm_excluded_hosts: Vec::new(),
            mitm_added_hosts: Vec::new(),
            disabled_url_patterns: Vec::new(),
            url_rewrites: Vec::new(),
            map_locals: Vec::new(),
            header_rewrites: Vec::new(),
            body_rewrites: Vec::new(),
            scripts: Vec::new(),
        }
    }
}
