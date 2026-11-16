pub mod dnsmasq;
pub mod geosite;
pub mod gfwlist;
pub mod surge_clash;

use anyhow::Result;

use crate::routing::config::{GeositeTagFilter, RoutingSourceConfig, RoutingSourceFormat};
use crate::routing::model::ParsedRoutingSource;

pub fn parse_routing_source(
    bytes: &[u8],
    src: &RoutingSourceConfig,
) -> Result<ParsedRoutingSource> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = ParsedRoutingSource::new(&src.id, src.target, &src.lineage, src.weight);

    match src.format {
        RoutingSourceFormat::SurgeRuleset => {
            surge_clash::parse_surge_ruleset(&text, &mut out);
        }
        RoutingSourceFormat::DomainSet => {
            surge_clash::parse_domain_set(&text, &mut out);
        }
        RoutingSourceFormat::AbpFilter => {
            surge_clash::parse_abp_routing(&text, &mut out);
        }
        RoutingSourceFormat::Hosts => {
            surge_clash::parse_hosts_routing(&text, &mut out);
        }
        RoutingSourceFormat::ClashClassical => {
            surge_clash::parse_clash_classical(&text, &mut out);
        }
        RoutingSourceFormat::ClashYaml => {
            surge_clash::parse_clash_yaml(&text, &mut out);
        }
        RoutingSourceFormat::Geosite => {
            let filter = src.geosite_filter.unwrap_or(GeositeTagFilter::AllNonAds);
            geosite::parse_geosite(&text, filter, &mut out);
        }
        RoutingSourceFormat::DnsmasqChina => {
            dnsmasq::parse_dnsmasq_china(&text, &mut out);
        }
        RoutingSourceFormat::GfwlistBase64 => {
            gfwlist::parse_gfwlist_base64(&text, &mut out)?;
        }
        RoutingSourceFormat::IpCidr => {
            surge_clash::parse_ip_cidr_list(&text, &mut out);
        }
        RoutingSourceFormat::AsnList => {
            surge_clash::parse_asn_list(&text, &mut out);
        }
    }

    Ok(out)
}
