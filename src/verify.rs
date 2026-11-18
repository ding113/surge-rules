use std::fs;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use maxminddb::{MaxMindDBError, Reader, geoip2};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub fn lookup_opt<'a, T, S>(reader: &'a Reader<S>, ip: IpAddr) -> Result<Option<T>>
where
    T: Deserialize<'a>,
    S: AsRef<[u8]>,
{
    match reader.lookup::<T>(ip) {
        Ok(val) => Ok(Some(val)),
        Err(MaxMindDBError::AddressNotFoundError(_)) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

#[derive(Clone, Debug)]
pub struct ArtifactSummary {
    pub file_name: String,
    pub database_type: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub node_count: u64,
    pub record_size: u16,
    pub build_epoch: u64,
}

#[derive(Clone, Debug)]
pub struct VerificationReport {
    pub country: ArtifactSummary,
    pub country_only: ArtifactSummary,
    pub country_cn: ArtifactSummary,
    pub asn: ArtifactSummary,
    pub canaries_checked: usize,
}

pub fn verify_artifact_dir(
    dir: &Path,
    enforce_production_gates: bool,
) -> Result<VerificationReport> {
    let country_path = dir.join("Country.mmdb");
    let country_only_path = dir.join("Country-only.mmdb");
    let cn_path = dir.join("Country-cn.mmdb");
    let asn_path = dir.join("ASN.mmdb");

    let country_reader = Reader::open_readfile(&country_path)
        .with_context(|| format!("failed to open {}", country_path.display()))?;
    let country_only_reader = Reader::open_readfile(&country_only_path)
        .with_context(|| format!("failed to open {}", country_only_path.display()))?;
    let cn_reader = Reader::open_readfile(&cn_path)
        .with_context(|| format!("failed to open {}", cn_path.display()))?;
    let asn_reader = Reader::open_readfile(&asn_path)
        .with_context(|| format!("failed to open {}", asn_path.display()))?;

    let country_sum = inspect_summary(&country_path, &country_reader, "GeoLite2-City")?;
    let country_only_sum =
        inspect_summary(&country_only_path, &country_only_reader, "GeoLite2-Country")?;
    let cn_sum = inspect_summary(&cn_path, &cn_reader, "GeoLite2-Country")?;
    let asn_sum = inspect_summary(&asn_path, &asn_reader, "GeoLite2-ASN")?;

    if enforce_production_gates {
        if country_sum.node_count < 400_000 || country_sum.size_bytes > 350 * 1024 * 1024 {
            bail!(
                "Country.mmdb failed size/node gate: nodes={} size={}",
                country_sum.node_count,
                country_sum.size_bytes
            );
        }
        if country_only_sum.node_count < 50_000 || country_only_sum.size_bytes > 20 * 1024 * 1024 {
            bail!(
                "Country-only.mmdb failed size/node gate: nodes={} size={}",
                country_only_sum.node_count,
                country_only_sum.size_bytes
            );
        }
        if cn_sum.node_count < 10_000 || cn_sum.size_bytes > 30 * 1024 * 1024 {
            bail!(
                "Country-cn.mmdb failed size/node gate: nodes={} size={}",
                cn_sum.node_count,
                cn_sum.size_bytes
            );
        }
        if asn_sum.node_count < 200_000 || asn_sum.size_bytes > 50 * 1024 * 1024 {
            bail!(
                "ASN.mmdb failed size/node gate: nodes={} size={}",
                asn_sum.node_count,
                asn_sum.size_bytes
            );
        }
    }

    let mut canaries = 0usize;

    // 1. Validate Priority-0 LAN, Surge Fake-IP/VIF, Tailscale, Cloudflare Zero Trust Mesh, ZeroTier
    let special_canaries: &[(&str, Option<&str>)] = &[
        ("127.0.0.1", None),
        ("10.0.0.1", None),
        ("172.16.10.1", None),
        ("192.168.1.1", None),
        ("169.254.1.1", None),
        ("fe80::1", None),
        ("fd12:3456:789a::1", None),
        ("198.18.0.1", Some("surge_vif")),
        ("198.18.0.2", Some("surge_vif")),
        ("100.64.0.1", Some("tailscale")),
        ("100.100.100.100", Some("tailscale")),
        ("fd7a:115c:a1e0::1", Some("tailscale")),
        ("fd7a:115c:a1e0::53", Some("tailscale")),
        ("100.96.0.1", Some("cloudflare_mesh")),
        ("100.112.0.1", Some("cloudflare_mesh")),
        ("172.16.0.1", Some("cloudflare_mesh")),
        ("172.16.0.2", Some("cloudflare_mesh")),
        ("fd01:db8:1111::1", Some("cloudflare_mesh")),
        ("fc00::1", Some("zerotier")),
    ];

    for &(ip_str, expected_vnet) in special_canaries {
        let ip: IpAddr = ip_str.parse()?;
        let val: Option<serde_json::Value> = lookup_opt(&country_reader, ip)
            .with_context(|| format!("Country.mmdb lookup error for {}", ip_str))?;
        let Some(doc) = val else {
            bail!("Priority-0 special IP {} missing from Country.mmdb", ip_str);
        };
        if doc.get("country").is_some() {
            bail!(
                "Priority-0 special IP {} leaked country in Country.mmdb: {}",
                ip_str,
                doc
            );
        }
        if doc.get("registered_country").is_some() {
            bail!(
                "Priority-0 special IP {} leaked registered_country in Country.mmdb: {}",
                ip_str,
                doc
            );
        }
        if doc.get("autonomous_system_number").is_some() {
            bail!(
                "Priority-0 special IP {} leaked ASN in Country.mmdb: {}",
                ip_str,
                doc
            );
        }
        let is_bogon = doc
            .pointer("/traits/is_bogon")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !is_bogon {
            bail!(
                "Priority-0 special IP {} missing traits.is_bogon=true: {}",
                ip_str,
                doc
            );
        }
        if let Some(vnet) = expected_vnet {
            let actual_vnet = doc
                .pointer("/traits/virtual_network")
                .and_then(|v| v.as_str());
            if actual_vnet != Some(vnet) {
                bail!(
                    "Priority-0 virtual mesh IP {} expected virtual_network='{}', got {:?}",
                    ip_str,
                    vnet,
                    actual_vnet
                );
            }
        }

        // Must be completely absent from Country-only.mmdb, Country-cn.mmdb, and ASN.mmdb
        let country_only_hit: Option<serde_json::Value> = lookup_opt(&country_only_reader, ip)?;
        if country_only_hit.is_some() {
            bail!(
                "Priority-0 special IP {} leaked into Country-only.mmdb",
                ip_str
            );
        }
        let cn_hit: Option<serde_json::Value> = lookup_opt(&cn_reader, ip)?;
        if cn_hit.is_some() {
            bail!(
                "Priority-0 special IP {} leaked into Country-cn.mmdb",
                ip_str
            );
        }
        let asn_hit: Option<serde_json::Value> = lookup_opt(&asn_reader, ip)?;
        if asn_hit.is_some() {
            bail!("Priority-0 special IP {} leaked into ASN.mmdb", ip_str);
        }
        canaries += 1;
    }

    if enforce_production_gates {
        // 2. Validate Mainland China public canaries
        for &(ip_str, expected_asns) in &[
            ("223.5.5.5", &[37963u32, 45102u32][..]),
            ("2400:3200::1", &[37963u32, 45102u32][..]),
            ("114.114.114.114", &[][..]),
            ("182.254.118.119", &[][..]),
        ] {
            let ip: IpAddr = ip_str.parse()?;
            // Verify typed MaxMind structs decode cleanly
            let typed_city: geoip2::City<'_> = lookup_opt(&country_reader, ip)?
                .with_context(|| format!("{} missing in Country.mmdb", ip_str))?;
            if typed_city.country.and_then(|c| c.iso_code) != Some("CN") {
                bail!("expected {} -> CN in Country.mmdb", ip_str);
            }
            if ip_str == "223.5.5.5"
                && let Some(doc) = lookup_opt::<serde_json::Value, _>(&country_reader, ip)?
                && (doc.pointer("/traits/is_anonymous_vpn") == Some(&serde_json::json!(true))
                    || doc.pointer("/traits/is_vpn") == Some(&serde_json::json!(true))
                    || doc.pointer("/traits/is_anonymous_proxy") == Some(&serde_json::json!(true)))
            {
                bail!("223.5.5.5 unexpectedly flagged as VPN/proxy in Country.mmdb");
            }
            let typed_cn: geoip2::Country<'_> = lookup_opt(&cn_reader, ip)?
                .with_context(|| format!("{} missing in Country-cn.mmdb", ip_str))?;
            if typed_cn.country.and_then(|c| c.iso_code) != Some("CN") {
                bail!("expected {} -> CN in Country-cn.mmdb", ip_str);
            }
            assert_country_only_record(&country_only_reader, ip_str, ip, "CN")?;
            if !expected_asns.is_empty() {
                let typed_asn: geoip2::Asn<'_> = lookup_opt(&asn_reader, ip)?
                    .with_context(|| format!("{} missing in ASN.mmdb", ip_str))?;
                let actual_asn = typed_asn.autonomous_system_number;
                if !actual_asn.is_some_and(|a| expected_asns.contains(&a)) {
                    bail!(
                        "expected {} -> AS in {:?} in ASN.mmdb, got {:?}",
                        ip_str,
                        expected_asns,
                        actual_asn
                    );
                }
            }
            canaries += 1;
        }

        // Also check IPv4-mapped IPv6 lookup `::ffff:223.5.5.5`
        let mapped_ip: IpAddr = "::ffff:223.5.5.5".parse()?;
        let mapped_city: geoip2::City<'_> = lookup_opt(&country_reader, mapped_ip)?
            .context("::ffff:223.5.5.5 missing via IPv4-mapped subtree")?;
        if mapped_city.country.and_then(|c| c.iso_code) != Some("CN") {
            bail!("::ffff:223.5.5.5 did not resolve to CN");
        }
        assert_country_only_record(&country_only_reader, "::ffff:223.5.5.5", mapped_ip, "CN")?;
        canaries += 1;

        // 3. Validate Global / Anycast / Cloud Geofeed / HK-MO-TW separation canaries
        for &(ip_str, exp_iso, exp_asn) in &[
            ("1.1.1.1", None, Some(13335u32)),
            ("2606:4700:4700::1111", None, Some(13335u32)),
            ("8.8.8.8", Some("US"), Some(15169u32)),
            ("2001:4860:4860::8888", Some("US"), Some(15169u32)),
            ("16.192.0.1", Some("SE"), Some(16509u32)),
            ("1.178.103.1", Some("HK"), Some(16509u32)),
            ("168.95.1.1", Some("TW"), Some(3462u32)),
            ("114.24.27.200", Some("TW"), Some(3462u32)),
        ] {
            let ip: IpAddr = ip_str.parse()?;
            let doc: serde_json::Value = lookup_opt(&country_reader, ip)?
                .with_context(|| format!("{} missing in Country.mmdb", ip_str))?;
            if let Some(cc) = exp_iso {
                let actual = doc.pointer("/country/iso_code").and_then(|v| v.as_str());
                if actual != Some(cc) {
                    bail!(
                        "canary {} expected country '{}', got {:?} ({})",
                        ip_str,
                        cc,
                        actual,
                        doc
                    );
                }
                assert_country_only_record(&country_only_reader, ip_str, ip, cc)?;
            } else if let Some(full_cc) = doc.pointer("/country/iso_code").and_then(|v| v.as_str())
            {
                assert_country_only_record(&country_only_reader, ip_str, ip, full_cc)?;
            } else {
                let co_leak: Option<serde_json::Value> = lookup_opt(&country_only_reader, ip)?;
                if co_leak.is_some() {
                    bail!(
                        "countryless anycast {} unexpectedly leaked into Country-only.mmdb",
                        ip_str
                    );
                }
            }
            if matches!(ip_str, "8.8.8.8" | "1.178.103.1" | "16.192.0.1")
                && (doc.pointer("/traits/is_anonymous_vpn") == Some(&serde_json::json!(true))
                    || doc.pointer("/traits/is_vpn") == Some(&serde_json::json!(true))
                    || doc.pointer("/traits/is_anonymous_proxy") == Some(&serde_json::json!(true)))
            {
                bail!(
                    "{} unexpectedly flagged as VPN/proxy in Country.mmdb",
                    ip_str
                );
            }
            if ip_str == "114.24.27.200"
                && (doc.pointer("/traits/is_cdn") == Some(&serde_json::json!(true))
                    || doc.pointer("/traits/is_hosting_provider") == Some(&serde_json::json!(true)))
            {
                bail!(
                    "residential HiNet canary 114.24.27.200 unexpectedly flagged as CDN/hosting: {}",
                    doc
                );
            }
            if ip_str == "168.95.1.1"
                && doc
                    .pointer("/subdivisions")
                    .and_then(|v| v.as_array())
                    .is_some_and(|arr| {
                        arr.iter().any(|s| {
                            s.pointer("/names/zh-CN").and_then(|n| n.as_str()) == Some("台湾省")
                        })
                    })
            {
                bail!("168.95.1.1 unexpectedly leaked Mainland-style '台湾省' subdivision");
            }
            if let Some(asn) = exp_asn {
                let typed_asn: geoip2::Asn<'_> = lookup_opt(&asn_reader, ip)?
                    .with_context(|| format!("{} missing in ASN.mmdb", ip_str))?;
                if typed_asn.autonomous_system_number != Some(asn) {
                    bail!(
                        "canary {} expected AS{}, got {:?}",
                        ip_str,
                        asn,
                        typed_asn.autonomous_system_number
                    );
                }
            }
            // Non-CN canaries must NOT appear in Country-cn.mmdb
            let cn_leak: Option<serde_json::Value> = lookup_opt(&cn_reader, ip)?;
            if cn_leak.is_some() {
                bail!("non-CN canary {} leaked into Country-cn.mmdb", ip_str);
            }
            canaries += 1;
        }
    }

    Ok(VerificationReport {
        country: country_sum,
        country_only: country_only_sum,
        country_cn: cn_sum,
        asn: asn_sum,
        canaries_checked: canaries,
    })
}

fn assert_country_only_record<S: AsRef<[u8]>>(
    reader: &Reader<S>,
    ip_str: &str,
    ip: IpAddr,
    expected_cc: &str,
) -> Result<()> {
    let typed: geoip2::Country<'_> = lookup_opt(reader, ip)?
        .with_context(|| format!("{} missing in Country-only.mmdb", ip_str))?;
    if typed.country.and_then(|c| c.iso_code) != Some(expected_cc) {
        bail!(
            "canary {} expected country '{}' in Country-only.mmdb",
            ip_str,
            expected_cc
        );
    }
    let doc: serde_json::Value = lookup_opt(reader, ip)?
        .with_context(|| format!("{} missing JSON in Country-only.mmdb", ip_str))?;
    let is_only_country = doc
        .as_object()
        .is_some_and(|obj| obj.len() == 1 && obj.contains_key("country"));
    if !is_only_country {
        bail!(
            "Country-only.mmdb leaked non-country top-level fields for {}: {}",
            ip_str,
            doc
        );
    }
    Ok(())
}

fn inspect_summary<S: AsRef<[u8]>>(
    path: &Path,
    reader: &Reader<S>,
    expected_db_type: &str,
) -> Result<ArtifactSummary> {
    let bytes = fs::read(path).with_context(|| format!("failed reading {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha256 = hex::encode(hasher.finalize());

    let md = &reader.metadata;
    if md.binary_format_major_version != 2 || md.binary_format_minor_version != 0 {
        bail!(
            "{} invalid MMDB version {}.{}",
            path.display(),
            md.binary_format_major_version,
            md.binary_format_minor_version
        );
    }
    if md.ip_version != 6 {
        bail!(
            "{} expected ip_version=6, got {}",
            path.display(),
            md.ip_version
        );
    }
    if md.database_type != expected_db_type {
        bail!(
            "{} expected database_type='{}', got '{}'",
            path.display(),
            expected_db_type,
            md.database_type
        );
    }

    Ok(ArtifactSummary {
        file_name: path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
        database_type: md.database_type.clone(),
        size_bytes: bytes.len() as u64,
        sha256,
        node_count: md.node_count as u64,
        record_size: md.record_size,
        build_epoch: md.build_epoch,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn render_release_notes(
    report: &VerificationReport,
    ingested_sources: usize,
    total_catalog_sources: usize,
    country_v4_cidrs: usize,
    country_v6_cidrs: usize,
    cn_v4_cidrs: usize,
    cn_v6_cidrs: usize,
) -> String {
    let dt = DateTime::<Utc>::from_timestamp(report.country.build_epoch as i64, 0)
        .unwrap_or_else(Utc::now);
    let ts_str = dt.format("%Y-%m-%d %H:%M:%S UTC");

    let fmt_mb = |b: u64| format!("{:.2} MiB", (b as f64) / (1024.0 * 1024.0));

    format!(
        "## 构建信息\n\n\
- 构建时间：`{ts_str}`\n\
- 活跃上游数据源：`{ingested_sources} / {total_catalog_sources}`\n\
- 金丝雀校验项：`{}` 项全部通过（含 RFC 6890 私有网段、Surge Fake-IP、Tailscale、Cloudflare Mesh、ZeroTier 隔离校验）\n\n\
## 产物清单\n\n\
| 文件 | 数据库类型 | 大小 | 树节点数 | 记录位宽 | SHA-256 |\n\
| :--- | :--- | ---: | ---: | ---: | :--- |\n\
| `{}` | `{}` | {} | {} | {}-bit | `{}` |\n\
| `{}` | `{}` | {} | {} | {}-bit | `{}` |\n\
| `{}` | `{}` | {} | {} | {}-bit | `{}` |\n\
| `{}` | `{}` | {} | {} | {}-bit | `{}` |\n\n\
## 覆盖统计\n\n\
- `Country.mmdb`：合并后 IPv4 `{country_v4_cidrs}` 段 / IPv6 `{country_v6_cidrs}` 段\n\
- `Country-cn.mmdb`：合并后中国大陆 IPv4 `{cn_v4_cidrs}` 段 / IPv6 `{cn_v6_cidrs}` 段\n\n\
## Surge 配置\n\n\
```ini\n\
[General]\n\
geoip-maxmind-url = https://rule-set.ygxz.de/Country.mmdb\n\
```\n",
        report.canaries_checked,
        report.country.file_name,
        report.country.database_type,
        fmt_mb(report.country.size_bytes),
        report.country.node_count,
        report.country.record_size,
        report.country.sha256,
        report.country_only.file_name,
        report.country_only.database_type,
        fmt_mb(report.country_only.size_bytes),
        report.country_only.node_count,
        report.country_only.record_size,
        report.country_only.sha256,
        report.country_cn.file_name,
        report.country_cn.database_type,
        fmt_mb(report.country_cn.size_bytes),
        report.country_cn.node_count,
        report.country_cn.record_size,
        report.country_cn.sha256,
        report.asn.file_name,
        report.asn.database_type,
        fmt_mb(report.asn.size_bytes),
        report.asn.node_count,
        report.asn.record_size,
        report.asn.sha256,
    )
}
