use std::io::Cursor;

use anyhow::{Context, Result};
use bytes::Bytes;
use ipnet::IpNet;
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::record::Field;
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
