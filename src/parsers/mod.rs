pub mod bgp_rir;
pub mod cidr_list;
pub mod geofeed;
pub mod ip2location;
pub mod ipapi;
pub mod ipdb;
pub mod libloc;
pub mod mmdb;
pub mod qqwry;
pub mod sypex;
pub mod xdb;

use anyhow::Result;

use crate::config::{MetadataRegistry, SourceConfig, SourceFormat};
use crate::model::ParsedSource;

#[inline]
pub(crate) fn checked_slice(bytes: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    bytes.get(offset..offset.checked_add(len)?)
}

#[inline]
pub(crate) fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let arr: [u8; 2] = checked_slice(bytes, offset, 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(arr))
}

#[inline]
pub(crate) fn read_u16_be(bytes: &[u8], offset: usize) -> Option<u16> {
    let arr: [u8; 2] = checked_slice(bytes, offset, 2)?.try_into().ok()?;
    Some(u16::from_be_bytes(arr))
}

#[inline]
pub(crate) fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let arr: [u8; 4] = checked_slice(bytes, offset, 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(arr))
}

#[inline]
pub(crate) fn read_u32_be(bytes: &[u8], offset: usize) -> Option<u32> {
    let arr: [u8; 4] = checked_slice(bytes, offset, 4)?.try_into().ok()?;
    Some(u32::from_be_bytes(arr))
}

#[inline]
pub(crate) fn read_u128_le(bytes: &[u8], offset: usize) -> Option<u128> {
    let arr: [u8; 16] = checked_slice(bytes, offset, 16)?.try_into().ok()?;
    Some(u128::from_le_bytes(arr))
}

#[inline]
pub(crate) fn read_u128_be(bytes: &[u8], offset: usize) -> Option<u128> {
    let arr: [u8; 16] = checked_slice(bytes, offset, 16)?.try_into().ok()?;
    Some(u128::from_be_bytes(arr))
}

#[inline]
pub(crate) fn read_f32_be(bytes: &[u8], offset: usize) -> Option<f32> {
    let arr: [u8; 4] = checked_slice(bytes, offset, 4)?.try_into().ok()?;
    Some(f32::from_be_bytes(arr))
}

#[inline]
pub(crate) fn read_f64_be(bytes: &[u8], offset: usize) -> Option<f64> {
    let arr: [u8; 8] = checked_slice(bytes, offset, 8)?.try_into().ok()?;
    Some(f64::from_be_bytes(arr))
}

pub fn parse_source_bytes(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    match src.format {
        SourceFormat::GeofeedParquet => geofeed::parse_geofeed_parquet(src, bytes, metadata),
        SourceFormat::Rfc8805Csv => geofeed::parse_rfc8805_csv(src, bytes, metadata),
        SourceFormat::AwsIpRangesJson => geofeed::parse_aws_ip_ranges(src, bytes, metadata),
        SourceFormat::GcpCloudJson => geofeed::parse_gcp_cloud_json(src, bytes, metadata),
        SourceFormat::OracleCloudJson => geofeed::parse_oracle_cloud_json(src, bytes, metadata),
        SourceFormat::AzureServiceTagsJson => {
            geofeed::parse_azure_service_tags_json(src, bytes, metadata)
        }
        SourceFormat::CloudflareJdcloudJson => {
            geofeed::parse_cloudflare_jdcloud_json(src, bytes, metadata)
        }
        SourceFormat::IpapiCsvZip => ipapi::parse_ipapi_csv_zip(src, bytes, metadata),
        SourceFormat::FastlyJson => geofeed::parse_fastly_json(src, bytes),
        SourceFormat::GcoreJson => geofeed::parse_gcore_json(src, bytes),
        SourceFormat::GithubMetaJson => geofeed::parse_github_meta_json(src, bytes),
        SourceFormat::Xdb => xdb::parse_xdb(src, bytes, metadata),
        SourceFormat::QqwryDat => qqwry::parse_qqwry(src, bytes, metadata),
        SourceFormat::Ipdb => ipdb::parse_ipdb(src, bytes, metadata),
        SourceFormat::CidrCountry | SourceFormat::CidrIsp | SourceFormat::CidrTrait => {
            cidr_list::parse_cidr_list(src, bytes, metadata)
        }
        SourceFormat::Mmdb => mmdb::parse_mmdb(src, bytes, metadata),
        SourceFormat::Ip2locationBin => ip2location::parse_ip2location_bin(src, bytes, metadata),
        SourceFormat::Ip2locationCsv => ip2location::parse_ip2location_csv(src, bytes, metadata),
        SourceFormat::Libloc => libloc::parse_libloc(src, bytes, metadata),
        SourceFormat::IpscopeCsv => bgp_rir::parse_ipscope_csv(src, bytes, metadata),
        SourceFormat::SypexDat => sypex::parse_sypex(src, bytes, metadata),
        SourceFormat::BgptoolsTable => bgp_rir::parse_bgptools_table(src, bytes),
        SourceFormat::BgptoolsAsnsCsv => bgp_rir::parse_bgptools_asns_csv(src, bytes, metadata),
        SourceFormat::BgptoolsTagCsv => cidr_list::parse_bgptools_tag_csv(src, bytes),
        SourceFormat::IpverseAsCsv => bgp_rir::parse_ipverse_as_csv(src, bytes, metadata),
        SourceFormat::IptoasnTsv => bgp_rir::parse_iptoasn_tsv(src, bytes, metadata),
        SourceFormat::RirDelegated => bgp_rir::parse_rir_delegated(src, bytes, metadata),
        SourceFormat::OnionooJson => cidr_list::parse_onionoo_json(src, bytes),
        SourceFormat::OpenproxydbCsv => cidr_list::parse_openproxydb_csv(src, bytes),
        SourceFormat::SatGeoipJsonl => cidr_list::parse_sat_geoip_jsonl(src, bytes),
        SourceFormat::SatAsnsCsv => cidr_list::parse_sat_asns_csv(src, bytes),
        SourceFormat::SpamhausDrop => cidr_list::parse_spamhaus_drop(src, bytes),
    }
}
