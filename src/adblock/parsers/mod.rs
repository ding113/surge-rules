pub mod abp;
pub mod qx_rewrite;
pub mod ruleset;
pub mod surge_module;

use anyhow::Result;

use crate::adblock::config::{AdblockSourceConfig, AdblockSourceFormat};
use crate::adblock::model::ParsedAdblockSource;

/// Parses raw upstream feed bytes according to its declared Adblock source format and role.
pub fn parse_adblock_source(src: &AdblockSourceConfig, raw: &[u8]) -> Result<ParsedAdblockSource> {
    let text = String::from_utf8_lossy(raw);
    let mut parsed = ParsedAdblockSource {
        category: src.category,
        lineage: src.lineage.clone(),
        weight: src.weight,
        ..Default::default()
    };

    match src.format {
        AdblockSourceFormat::AbpFilter => {
            abp::parse_abp(&text, src, &mut parsed);
        }
        AdblockSourceFormat::SurgeModule => {
            surge_module::parse_surge_module(&text, src.weight, &mut parsed);
        }
        AdblockSourceFormat::QxRewrite => {
            qx_rewrite::parse_qx_rewrite(&text, src.weight, &mut parsed);
        }
        AdblockSourceFormat::SurgeRuleset => {
            ruleset::parse_surge_ruleset(&text, src, &mut parsed);
        }
        AdblockSourceFormat::SurgeDomainset => {
            ruleset::parse_surge_domainset(&text, src, &mut parsed);
        }
        AdblockSourceFormat::Hosts => {
            ruleset::parse_hosts(&text, src, &mut parsed);
        }
        AdblockSourceFormat::DomainList => {
            ruleset::parse_domain_list(&text, src, &mut parsed);
        }
    }

    Ok(parsed)
}
