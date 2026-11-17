use std::io::Cursor;

use anyhow::{Context, Result};
use bytes::Bytes;
use ipnet::IpNet;
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::record::Field;
use rustc_hash::FxHashMap;
use serde::Deserialize;

use crate::config::{MetadataRegistry, SourceConfig};
use crate::model::{IsoCode, ObsPayload, ParsedSource, TraitFlags};

pub fn parse_rfc8805_csv(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    let mut out = ParsedSource::new(&src.id);
    let base_traits = src.base_traits();

    let text = String::from_utf8_lossy(bytes);
    let mut clean_buf = String::with_capacity(text.len());
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with('<') || t.starts_with(';') {
            continue;
        }
        clean_buf.push_str(t);
        clean_buf.push('\n');
    }

    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(Cursor::new(clean_buf.as_bytes()));

    for rec_res in rdr.records() {
        let Ok(rec) = rec_res else {
            continue;
        };
        if rec.is_empty() {
            continue;
        }
        let prefix_str = rec.get(0).unwrap_or("");
        let Ok(net) = prefix_str.parse::<IpNet>() else {
            continue;
        };
        let min_plen = match net {
            IpNet::V4(_) => 8,
            IpNet::V6(_) => 19,
        };
        if net.prefix_len() < min_plen {
            continue;
        }
        let alpha2 = rec.get(1).unwrap_or("");
        let region = rec.get(2).unwrap_or("");
        let city = rec.get(3).unwrap_or("");
        let postal = rec.get(4).unwrap_or("");

        if let Some(pid) = build_geofeed_record_payload(
            alpha2,
            region,
            city,
            postal,
            base_traits,
            metadata,
            &mut out,
        ) {
            out.push_ipnet(net, pid);
        }
    }

    out.finalize();
    Ok(out)
}

pub fn parse_geofeed_parquet(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    let reader = SerializedFileReader::new(Bytes::copy_from_slice(bytes))
        .with_context(|| format!("failed to open Parquet reader for '{}'", src.id))?;

    let mut out = ParsedSource::new(&src.id);
    let base_traits = src.base_traits();

    let iter = reader
        .get_row_iter(None)
        .with_context(|| format!("failed to iterate Parquet rows in '{}'", src.id))?;

    for row_res in iter {
        let Ok(row) = row_res else {
            continue;
        };
        let mut prefix = "";
        let mut country = "";
        let mut region = "";
        let mut city = "";
        let mut postal = "";
        let mut bgp_valid: Option<bool> = None;
        let mut confidence: Option<f64> = None;

        for (col_name, field) in row.get_column_iter() {
            match (col_name.as_str(), field) {
                ("prefix", Field::Str(s)) => prefix = s.as_str(),
                ("country", Field::Str(s)) => country = s.as_str(),
                ("region", Field::Str(s)) => region = s.as_str(),
                ("city", Field::Str(s)) => city = s.as_str(),
                ("postal_code", Field::Str(s)) => postal = s.as_str(),
                ("bgp_valid", &Field::Bool(b)) => bgp_valid = Some(b),
                ("confidence", &Field::Double(d)) => confidence = Some(d),
                ("confidence", &Field::Float(f)) => confidence = Some(f as f64),
                _ => {}
            }
        }

        if bgp_valid == Some(false) {
            continue;
        }
        if let Some(conf) = confidence
            && conf < 0.25
        {
            continue;
        }

        let Ok(net) = prefix.trim().parse::<IpNet>() else {
            continue;
        };
        let min_plen = match net {
            IpNet::V4(_) => 8,
            IpNet::V6(_) => 19,
        };
        if net.prefix_len() < min_plen {
            continue;
        }
        if let Some(pid) = build_geofeed_record_payload(
            country,
            region,
            city,
            postal,
            base_traits,
            metadata,
            &mut out,
        ) {
            out.push_ipnet(net, pid);
        }
    }

    out.finalize();
    Ok(out)
}

fn build_geofeed_record_payload(
    alpha2: &str,
    region: &str,
    city: &str,
    postal: &str,
    base_traits: TraitFlags,
    metadata: &MetadataRegistry,
    out: &mut ParsedSource,
) -> Option<u32> {
    let mut iso = IsoCode::parse_raw(alpha2).and_then(|c| metadata.validate_iso(c));
    let mut region_norm = region.trim();
    if iso == Some(IsoCode::CN) {
        match region_norm.to_ascii_uppercase().as_str() {
            "CN-HK" | "HK" => {
                iso = metadata.validate_iso(IsoCode::HK);
                region_norm = "";
            }
            "CN-MO" | "MO" => {
                iso = metadata.validate_iso(IsoCode::MO);
                region_norm = "";
            }
            "CN-TW" | "TW" => {
                iso = metadata.validate_iso(IsoCode::TW);
                region_norm = "";
            }
            _ => {}
        }
    }
    if iso.is_none() && base_traits.is_empty() {
        return None;
    }

    let mut p = ObsPayload {
        country: iso,
        traits: base_traits,
        ..ObsPayload::default()
    };

    let sub_code = strip_country_prefix_on_iso3166_2(region_norm, iso);

    if iso == Some(IsoCode::CN) {
        let (prov, cm) = metadata.resolve_cn_division(sub_code, city);
        if let Some(pm) = prov {
            p.subdiv1_iso = out.intern_str(&pm.iso_code);
            p.subdiv1_en = out.intern_str(&pm.province_en);
            p.subdiv1_zh = out.intern_str(&pm.province_zh);
            p.subdiv1_geoname_id = pm.geoname_id;
            p.latitude_e5 = pm.lat_e5;
            p.longitude_e5 = pm.lon_e5;
        } else if !sub_code.is_empty() {
            p.subdiv1_iso = out.intern_str(sub_code);
        }
        if let Some(c_meta) = cm {
            p.city_en = out.intern_str(&c_meta.city_en);
            p.city_zh = out.intern_str(&c_meta.city_zh);
            p.city_geoname_id = c_meta.geoname_id;
            p.latitude_e5 = c_meta.lat_e5;
            p.longitude_e5 = c_meta.lon_e5;
        } else if !city.trim().is_empty() {
            p.city_en = out.intern_str(city);
        }
    } else {
        if !sub_code.is_empty() {
            p.subdiv1_iso = out.intern_str(sub_code);
        }
        if !city.trim().is_empty() {
            p.city_en = out.intern_str(city);
        }
    }

    if !postal.trim().is_empty() {
        p.postal_code = out.intern_str(postal);
    }

    out.intern_payload(p)
}

fn strip_country_prefix_on_iso3166_2(region: &str, iso: Option<IsoCode>) -> &str {
    let r = region.trim();
    if r.is_empty() {
        return "";
    }
    if let Some(cc) = iso
        && r.len() > 3
        && r.as_bytes()[2] == b'-'
        && r[..2].eq_ignore_ascii_case(cc.as_str())
    {
        return &r[3..];
    }
    if let Some((_, rhs)) = r.split_once('-')
        && !rhs.is_empty()
    {
        return rhs;
    }
    r
}

#[derive(Deserialize)]
struct AwsRangesDoc {
    #[serde(default)]
    prefixes: Vec<AwsV4Prefix>,
    #[serde(default)]
    ipv6_prefixes: Vec<AwsV6Prefix>,
}

#[derive(Deserialize)]
struct AwsV4Prefix {
    ip_prefix: String,
    region: String,
    #[serde(default)]
    service: String,
}

#[derive(Deserialize)]
struct AwsV6Prefix {
    ipv6_prefix: String,
    region: String,
    #[serde(default)]
    service: String,
}

pub fn parse_aws_ip_ranges(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    let doc: AwsRangesDoc = serde_json::from_slice(bytes)
        .with_context(|| format!("invalid AWS ip-ranges.json in '{}'", src.id))?;
    let mut out = ParsedSource::new(&src.id);
    let base_traits = src.base_traits();
    let org_id = out.intern_str("Amazon Web Services");

    let mut apply_aws = |cidr: &str, region: &str, service: &str| {
        let Ok(net) = cidr.trim().parse::<IpNet>() else {
            return;
        };
        let mut traits = base_traits;
        if service.eq_ignore_ascii_case("CLOUDFRONT") {
            traits.insert(TraitFlags::IS_CDN);
            traits.insert(TraitFlags::IS_ANYCAST);
        }
        let mut p = ObsPayload {
            organization: org_id,
            traits,
            ..ObsPayload::default()
        };
        if let Some(rm) = metadata.resolve_cloud_region("aws", region) {
            p.country = Some(rm.iso_code);
            p.subdiv1_iso = out.intern_str(&rm.subdivision_iso);
            p.subdiv1_en = out.intern_str(&rm.subdivision_en);
            p.city_en = out.intern_str(&rm.city_en);
            p.time_zone = out.intern_str(&rm.tz);
            p.latitude_e5 = rm.lat_e5;
            p.longitude_e5 = rm.lon_e5;
        }
        if let Some(pid) = out.intern_payload(p) {
            out.push_ipnet(net, pid);
        }
    };

    for item in &doc.prefixes {
        apply_aws(&item.ip_prefix, &item.region, &item.service);
    }
    for item in &doc.ipv6_prefixes {
        apply_aws(&item.ipv6_prefix, &item.region, &item.service);
    }

    out.finalize();
    Ok(out)
}

#[derive(Deserialize)]
struct GcpCloudDoc {
    #[serde(default)]
    prefixes: Vec<GcpPrefix>,
}

#[derive(Deserialize)]
struct GcpPrefix {
    #[serde(rename = "ipv4Prefix")]
    ipv4_prefix: Option<String>,
    #[serde(rename = "ipv6Prefix")]
    ipv6_prefix: Option<String>,
    #[serde(default)]
    scope: String,
}

pub fn parse_gcp_cloud_json(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    let doc: GcpCloudDoc = serde_json::from_slice(bytes)
        .with_context(|| format!("invalid GCP cloud.json in '{}'", src.id))?;
    let mut out = ParsedSource::new(&src.id);
    let base_traits = src.base_traits();
    let org_id = out.intern_str("Google Cloud");

    for item in doc.prefixes {
        let Some(cidr_str) = item.ipv4_prefix.as_deref().or(item.ipv6_prefix.as_deref()) else {
            continue;
        };
        let Ok(net) = cidr_str.trim().parse::<IpNet>() else {
            continue;
        };
        let mut p = ObsPayload {
            organization: org_id,
            traits: base_traits,
            ..ObsPayload::default()
        };
        if let Some(rm) = metadata.resolve_cloud_region("gcp", &item.scope) {
            p.country = Some(rm.iso_code);
            p.subdiv1_iso = out.intern_str(&rm.subdivision_iso);
            p.subdiv1_en = out.intern_str(&rm.subdivision_en);
            p.city_en = out.intern_str(&rm.city_en);
            p.time_zone = out.intern_str(&rm.tz);
            p.latitude_e5 = rm.lat_e5;
            p.longitude_e5 = rm.lon_e5;
        }
        if let Some(pid) = out.intern_payload(p) {
            out.push_ipnet(net, pid);
        }
    }

    out.finalize();
    Ok(out)
}

#[derive(Deserialize)]
struct OracleDoc {
    #[serde(default)]
    regions: Vec<OracleRegion>,
}

#[derive(Deserialize)]
struct OracleRegion {
    region: String,
    #[serde(default)]
    cidrs: Vec<OracleCidr>,
    #[serde(default)]
    ipv6_cidrs: Vec<OracleCidr>,
}

#[derive(Deserialize)]
struct OracleCidr {
    cidr: String,
}

pub fn parse_oracle_cloud_json(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    let doc: OracleDoc = serde_json::from_slice(bytes)
        .with_context(|| format!("invalid Oracle Cloud JSON in '{}'", src.id))?;
    let mut out = ParsedSource::new(&src.id);
    let base_traits = src.base_traits();
    let org_id = out.intern_str("Oracle Cloud");

    for reg in doc.regions {
        let mut p = ObsPayload {
            organization: org_id,
            traits: base_traits,
            ..ObsPayload::default()
        };
        if let Some(rm) = metadata.resolve_cloud_region("oracle", &reg.region) {
            p.country = Some(rm.iso_code);
            p.subdiv1_iso = out.intern_str(&rm.subdivision_iso);
            p.subdiv1_en = out.intern_str(&rm.subdivision_en);
            p.city_en = out.intern_str(&rm.city_en);
            p.time_zone = out.intern_str(&rm.tz);
            p.latitude_e5 = rm.lat_e5;
            p.longitude_e5 = rm.lon_e5;
        }
        let Some(pid) = out.intern_payload(p) else {
            continue;
        };
        for c in reg.cidrs.iter().chain(reg.ipv6_cidrs.iter()) {
            if let Ok(net) = c.cidr.trim().parse::<IpNet>() {
                out.push_ipnet(net, pid);
            }
        }
    }

    out.finalize();
    Ok(out)
}

#[derive(Deserialize)]
struct FastlyDoc {
    #[serde(default)]
    addresses: Vec<String>,
    #[serde(default)]
    ipv6_addresses: Vec<String>,
}

pub fn parse_fastly_json(src: &SourceConfig, bytes: &[u8]) -> Result<ParsedSource> {
    let doc: FastlyDoc = serde_json::from_slice(bytes)
        .with_context(|| format!("invalid Fastly JSON in '{}'", src.id))?;
    let mut out = ParsedSource::new(&src.id);
    let org_id = out.intern_str("Fastly");
    let pid = out
        .intern_payload(ObsPayload {
            organization: org_id,
            traits: src.base_traits(),
            ..ObsPayload::default()
        })
        .unwrap();

    for s in doc.addresses.iter().chain(doc.ipv6_addresses.iter()) {
        if let Ok(net) = s.trim().parse::<IpNet>() {
            out.push_ipnet(net, pid);
        }
    }
    out.finalize();
    Ok(out)
}

#[derive(Deserialize)]
struct GcoreDoc {
    #[serde(default)]
    addresses: Vec<String>,
    #[serde(default)]
    addresses_v6: Vec<String>,
}

pub fn parse_gcore_json(src: &SourceConfig, bytes: &[u8]) -> Result<ParsedSource> {
    let doc: GcoreDoc = serde_json::from_slice(bytes)
        .with_context(|| format!("invalid Gcore JSON in '{}'", src.id))?;
    let mut out = ParsedSource::new(&src.id);
    let org_id = out.intern_str("Gcore");
    let pid = out
        .intern_payload(ObsPayload {
            organization: org_id,
            traits: src.base_traits(),
            ..ObsPayload::default()
        })
        .unwrap();

    for s in doc.addresses.iter().chain(doc.addresses_v6.iter()) {
        if let Ok(net) = s.trim().parse::<IpNet>() {
            out.push_ipnet(net, pid);
        }
    }
    out.finalize();
    Ok(out)
}

pub fn parse_github_meta_json(src: &SourceConfig, bytes: &[u8]) -> Result<ParsedSource> {
    let root: serde_json::Value = serde_json::from_slice(bytes)
        .with_context(|| format!("invalid GitHub meta JSON in '{}'", src.id))?;
    let mut out = ParsedSource::new(&src.id);
    let org_id = out.intern_str("GitHub");
    let pid = out
        .intern_payload(ObsPayload {
            organization: org_id,
            traits: src.base_traits(),
            ..ObsPayload::default()
        })
        .unwrap();

    if let Some(obj) = root.as_object() {
        for (_k, val) in obj {
            if let Some(arr) = val.as_array() {
                for elem in arr {
                    if let Some(s) = elem.as_str()
                        && let Ok(net) = s.trim().parse::<IpNet>()
                    {
                        out.push_ipnet(net, pid);
                    }
                }
            }
        }
    }

    out.finalize();
    Ok(out)
}

#[derive(Deserialize)]
struct CloudflareJdcloudDoc {
    result: Option<CloudflareJdcloudResult>,
}

#[derive(Deserialize)]
struct CloudflareJdcloudResult {
    #[serde(default)]
    jdcloud_cidrs: Vec<String>,
}

/// Partial-extraction parser for `https://api.cloudflare.com/client/v4/ips?networks=jdcloud`.
/// Strictly extracts ONLY `.result.jdcloud_cidrs[]` as Mainland China (`CN`) CDN observations,
/// completely ignoring `.result.ipv4_cidrs` and `.result.ipv6_cidrs` global Anycast prefixes.
pub fn parse_cloudflare_jdcloud_json(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    let doc: CloudflareJdcloudDoc = serde_json::from_slice(bytes)
        .with_context(|| format!("invalid Cloudflare JD Cloud JSON in '{}'", src.id))?;
    let mut out = ParsedSource::new(&src.id);

    let Some(cn_iso) = metadata.validate_iso(IsoCode::CN) else {
        return Ok(out);
    };
    let mut traits = src.base_traits();
    traits.insert(TraitFlags::IS_CDN);
    let org_id = out.intern_str("Cloudflare China (JD Cloud)");

    let Some(pid) = out.intern_payload(ObsPayload {
        country: Some(cn_iso),
        organization: org_id,
        traits,
        ..ObsPayload::default()
    }) else {
        return Ok(out);
    };

    if let Some(res) = doc.result {
        for cidr_str in &res.jdcloud_cidrs {
            let Ok(net) = cidr_str.trim().parse::<IpNet>() else {
                continue;
            };
            let min_plen = match net {
                IpNet::V4(_) => 8,
                IpNet::V6(_) => 19,
            };
            if net.prefix_len() < min_plen {
                continue;
            }
            out.push_ipnet(net, pid);
        }
    }

    out.finalize();
    Ok(out)
}

#[derive(Deserialize)]
struct AzureServiceTagsDoc {
    #[serde(default)]
    values: Vec<AzureServiceTagValue>,
}

#[derive(Deserialize)]
struct AzureServiceTagValue {
    #[serde(default)]
    name: String,
    #[serde(default)]
    id: String,
    properties: Option<AzureServiceTagProps>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureServiceTagProps {
    #[serde(default)]
    region: String,
    #[serde(default)]
    system_service: String,
    #[serde(default)]
    address_prefixes: Vec<String>,
}

fn is_non_physical_azure_tag(name: &str, id: &str, system_service: &str) -> bool {
    for raw in [name, id, system_service] {
        let lower = raw.trim().to_ascii_lowercase();
        if lower.contains("azurefrontdoor")
            || lower.contains("azurecdn")
            || lower.contains("anycast")
            || lower.contains("m365")
            || lower.contains("office365")
        {
            return true;
        }
    }
    false
}

/// Maps verified physical Azure `properties.region` slugs to `(ISO-2, subdiv_iso, city_en, tz)`.
/// Unverified, empty, or global region strings return `None` and are safely skipped.
fn resolve_azure_physical_region(
    region_lower: &str,
) -> Option<(&'static str, &'static str, &'static str, &'static str)> {
    match region_lower {
        // United States
        "eastus" | "eastusstg" | "usstagee" => Some(("US", "VA", "Ashburn", "America/New_York")),
        "eastus2" | "eastus2euap" => Some(("US", "VA", "Boydton", "America/New_York")),
        "eastus3" => Some(("US", "GA", "Atlanta", "America/New_York")),
        "westus" => Some(("US", "CA", "San Francisco", "America/Los_Angeles")),
        "westus2" => Some(("US", "WA", "Quincy", "America/Los_Angeles")),
        "westus3" => Some(("US", "AZ", "Phoenix", "America/Phoenix")),
        "centralus" | "centraluseuap" => Some(("US", "IA", "Des Moines", "America/Chicago")),
        "northcentralus" => Some(("US", "IL", "Chicago", "America/Chicago")),
        "southcentralus" | "southcentralus2" | "usstagec" => {
            Some(("US", "TX", "San Antonio", "America/Chicago"))
        }
        "westcentralus" => Some(("US", "WY", "Cheyenne", "America/Denver")),
        "northeastus5" | "southeastus" | "southeastus3" | "southeastus5" | "southwestus" => {
            Some(("US", "", "", "America/New_York"))
        }
        // Americas
        "canadacentral" => Some(("CA", "ON", "Toronto", "America/Toronto")),
        "canadaeast" => Some(("CA", "QC", "Quebec City", "America/Toronto")),
        "brazilsouth" => Some(("BR", "SP", "Sao Paulo", "America/Sao_Paulo")),
        "brazilsoutheast" | "brazilse" => Some(("BR", "RJ", "Rio de Janeiro", "America/Sao_Paulo")),
        "brazilne" => Some(("BR", "CE", "Fortaleza", "America/Fortaleza")),
        "chilecentral" | "chilec" => Some(("CL", "RM", "Santiago", "America/Santiago")),
        "mexicocentral" => Some(("MX", "QUE", "Queretaro", "America/Mexico_City")),
        // Europe
        "northeurope" => Some(("IE", "L", "Dublin", "Europe/Dublin")),
        "westeurope" => Some(("NL", "NH", "Amsterdam", "Europe/Amsterdam")),
        "uksouth" => Some(("GB", "ENG", "London", "Europe/London")),
        "ukwest" => Some(("GB", "WLS", "Cardiff", "Europe/London")),
        "francecentral" | "centralfrance" => Some(("FR", "IDF", "Paris", "Europe/Paris")),
        "francesouth" | "southfrance" => Some(("FR", "PAC", "Marseille", "Europe/Paris")),
        "germanywestcentral" | "germanywc" => Some(("DE", "HE", "Frankfurt", "Europe/Berlin")),
        "germanynorth" | "germanyn" => Some(("DE", "BE", "Berlin", "Europe/Berlin")),
        "switzerlandnorth" | "switzerlandn" => Some(("CH", "ZH", "Zurich", "Europe/Zurich")),
        "switzerlandwest" | "switzerlandw" => Some(("CH", "GE", "Geneva", "Europe/Zurich")),
        "swedencentral" => Some(("SE", "X", "Gavle", "Europe/Stockholm")),
        "swedensouth" => Some(("SE", "M", "Staffanstorp", "Europe/Stockholm")),
        "norwayeast" | "norwaye" => Some(("NO", "03", "Oslo", "Europe/Oslo")),
        "norwaywest" | "norwayw" => Some(("NO", "11", "Stavanger", "Europe/Oslo")),
        "polandcentral" => Some(("PL", "14", "Warsaw", "Europe/Warsaw")),
        "italynorth" => Some(("IT", "25", "Milan", "Europe/Rome")),
        "spaincentral" => Some(("ES", "MD", "Madrid", "Europe/Madrid")),
        "austriaeast" => Some(("AT", "9", "Vienna", "Europe/Vienna")),
        "belgiumcentral" => Some(("BE", "BRU", "Brussels", "Europe/Brussels")),
        "denmarkeast" => Some(("DK", "84", "Copenhagen", "Europe/Copenhagen")),
        "finlandcentral" => Some(("FI", "18", "Helsinki", "Europe/Helsinki")),
        "greececentral" => Some(("GR", "I", "Athens", "Europe/Athens")),
        // Middle East & Africa
        "israelcentral" => Some(("IL", "M", "Tel Aviv", "Asia/Jerusalem")),
        "israelnorthwest" => Some(("IL", "HA", "Haifa", "Asia/Jerusalem")),
        "qatarcentral" => Some(("QA", "DA", "Doha", "Asia/Qatar")),
        "uaenorth" => Some(("AE", "DU", "Dubai", "Asia/Dubai")),
        "uaecentral" => Some(("AE", "AZ", "Abu Dhabi", "Asia/Dubai")),
        "saudiarabiaeast" => Some(("SA", "04", "Dammam", "Asia/Riyadh")),
        "southafricanorth" => Some(("ZA", "GP", "Johannesburg", "Africa/Johannesburg")),
        "southafricawest" => Some(("ZA", "WC", "Cape Town", "Africa/Johannesburg")),
        // Asia-Pacific
        "japaneast" => Some(("JP", "13", "Tokyo", "Asia/Tokyo")),
        "japanwest" => Some(("JP", "27", "Osaka", "Asia/Tokyo")),
        "koreacentral" => Some(("KR", "11", "Seoul", "Asia/Seoul")),
        "koreasouth" => Some(("KR", "26", "Busan", "Asia/Seoul")),
        "eastasia" => Some(("HK", "", "Hong Kong", "Asia/Hong_Kong")),
        "southeastasia" => Some(("SG", "", "Singapore", "Asia/Singapore")),
        "malaysiawest" => Some(("MY", "14", "Kuala Lumpur", "Asia/Kuala_Lumpur")),
        "malaysiasouth" => Some(("MY", "01", "Johor Bahru", "Asia/Kuala_Lumpur")),
        "indonesiacentral" => Some(("ID", "JK", "Jakarta", "Asia/Jakarta")),
        "taiwannorth" | "taiwannorthwest" => Some(("TW", "", "Taipei", "Asia/Taipei")),
        "australiaeast" => Some(("AU", "NSW", "Sydney", "Australia/Sydney")),
        "australiasoutheast" => Some(("AU", "VIC", "Melbourne", "Australia/Melbourne")),
        "australiacentral" | "australiacentral2" => {
            Some(("AU", "ACT", "Canberra", "Australia/Sydney"))
        }
        "newzealandnorth" => Some(("NZ", "AUK", "Auckland", "Pacific/Auckland")),
        "centralindia" => Some(("IN", "MH", "Pune", "Asia/Kolkata")),
        "southindia" => Some(("IN", "TN", "Chennai", "Asia/Kolkata")),
        "westindia" => Some(("IN", "MH", "Mumbai", "Asia/Kolkata")),
        "indiasouthcentral" => Some(("IN", "TG", "Hyderabad", "Asia/Kolkata")),
        "jioindiawest" => Some(("IN", "GJ", "Jamnagar", "Asia/Kolkata")),
        "jioindiacentral" => Some(("IN", "MH", "Nagpur", "Asia/Kolkata")),
        // Mainland China (21Vianet / Azure China)
        "chinanorth3" => Some(("CN", "HE", "Zhangjiakou", "Asia/Shanghai")),
        s if s.starts_with("chinanorth") => Some(("CN", "BJ", "Beijing", "Asia/Shanghai")),
        s if s.starts_with("chinaeast") => Some(("CN", "SH", "Shanghai", "Asia/Shanghai")),
        _ => None,
    }
}

pub fn parse_azure_service_tags_json(
    src: &SourceConfig,
    bytes: &[u8],
    metadata: &MetadataRegistry,
) -> Result<ParsedSource> {
    let doc: AzureServiceTagsDoc = serde_json::from_slice(bytes)
        .with_context(|| format!("invalid Azure ServiceTags JSON in '{}'", src.id))?;
    let mut out = ParsedSource::new(&src.id);
    let base_traits = src.base_traits();
    let org_id = out.intern_str("Microsoft Azure");
    let mut region_cache: FxHashMap<String, Option<u32>> = FxHashMap::default();

    for entry in doc.values {
        let Some(props) = entry.properties else {
            continue;
        };
        let reg = props.region.trim().to_ascii_lowercase();
        if reg.is_empty() || reg == "global" {
            continue;
        }
        if is_non_physical_azure_tag(&entry.name, &entry.id, &props.system_service) {
            continue;
        }

        let pid_opt = if let Some(&cached) = region_cache.get(&reg) {
            cached
        } else {
            let built = resolve_azure_physical_region(&reg).and_then(
                |(iso_str, subdiv_iso, city_en, tz)| {
                    let iso = IsoCode::parse_raw(iso_str).and_then(|c| metadata.validate_iso(c))?;
                    let mut p = ObsPayload {
                        country: Some(iso),
                        organization: org_id,
                        traits: base_traits,
                        ..ObsPayload::default()
                    };
                    if !tz.is_empty() {
                        p.time_zone = out.intern_str(tz);
                    }
                    if iso == IsoCode::CN {
                        let (prov, cm) = metadata.resolve_cn_division(subdiv_iso, city_en);
                        if let Some(pm) = prov {
                            p.subdiv1_iso = out.intern_str(&pm.iso_code);
                            p.subdiv1_en = out.intern_str(&pm.province_en);
                            p.subdiv1_zh = out.intern_str(&pm.province_zh);
                            p.subdiv1_geoname_id = pm.geoname_id;
                            p.latitude_e5 = pm.lat_e5;
                            p.longitude_e5 = pm.lon_e5;
                        } else if !subdiv_iso.is_empty() {
                            p.subdiv1_iso = out.intern_str(subdiv_iso);
                        }
                        if let Some(c_meta) = cm {
                            p.city_en = out.intern_str(&c_meta.city_en);
                            p.city_zh = out.intern_str(&c_meta.city_zh);
                            p.city_geoname_id = c_meta.geoname_id;
                            p.latitude_e5 = c_meta.lat_e5;
                            p.longitude_e5 = c_meta.lon_e5;
                        } else if !city_en.is_empty() {
                            p.city_en = out.intern_str(city_en);
                        }
                    } else {
                        if !subdiv_iso.is_empty() {
                            p.subdiv1_iso = out.intern_str(subdiv_iso);
                        }
                        if !city_en.is_empty() {
                            p.city_en = out.intern_str(city_en);
                        }
                    }
                    out.intern_payload(p)
                },
            );
            region_cache.insert(reg, built);
            built
        };

        let Some(pid) = pid_opt else {
            continue;
        };

        for cidr_str in &props.address_prefixes {
            let Ok(net) = cidr_str.trim().parse::<IpNet>() else {
                continue;
            };
            let min_plen = match net {
                IpNet::V4(_) => 8,
                IpNet::V6(_) => 19,
            };
            if net.prefix_len() < min_plen {
                continue;
            }
            out.push_ipnet(net, pid);
        }
    }

    out.finalize();
    Ok(out)
}
