pub mod adblock;
pub mod config;
pub mod fetch;
pub mod fusion;
pub mod mmdb_encode;
pub mod model;
pub mod overrides;
pub mod parsers;
pub mod verify;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use tracing::{info, warn};

use crate::config::{MetadataRegistry, SourceCatalog, SourceConfig};
use crate::fetch::{FetchOptions, SourceFetcher};
use crate::fusion::run_fusion;
use crate::mmdb_encode::{write_asn_mmdb, write_geo_mmdb};
use crate::model::GlobalArena;
use crate::overrides::CompiledOverrides;
use crate::parsers::parse_source_bytes;
use crate::verify::{VerificationReport, render_release_notes, verify_artifact_dir};

pub struct BuildGeoIpOptions {
    pub catalog_path: PathBuf,
    pub metadata_path: PathBuf,
    pub overrides_path: PathBuf,
    pub output_dir: PathBuf,
    pub fetch: FetchOptions,
}

impl Default for BuildGeoIpOptions {
    fn default() -> Self {
        Self {
            catalog_path: PathBuf::from("sources/generated/geoip-sources.json"),
            metadata_path: PathBuf::from("metadata/generated/geoip-metadata.json"),
            overrides_path: PathBuf::from("overrides/generated/geoip-overrides.json"),
            output_dir: PathBuf::from("dist"),
            fetch: FetchOptions::default(),
        }
    }
}

pub async fn build_geoip_pipeline(opts: BuildGeoIpOptions) -> Result<VerificationReport> {
    let t0 = Instant::now();
    let metadata = MetadataRegistry::load_from_path(&opts.metadata_path)?;
    let catalog = SourceCatalog::load_from_path(&opts.catalog_path)?;
    let overrides = CompiledOverrides::load_from_path(&opts.overrides_path, &metadata)?;
    let total_catalog_sources = catalog.sources.len();

    info!(
        sources = total_catalog_sources,
        countries = metadata.countries.len(),
        special_v4 = overrides.special_v4.len(),
        special_v6 = overrides.special_v6.len(),
        "loaded GeoIP catalog, metadata, and human overrides"
    );

    let fetcher = Arc::new(SourceFetcher::new(opts.fetch.clone())?);
    let fetched = fetcher.fetch_all(&catalog.sources).await?;
    info!(
        fetched = fetched.len(),
        total = total_catalog_sources,
        elapsed_secs = t0.elapsed().as_secs_f64(),
        "completed upstream fetch stage"
    );

    let cfg_by_id: rustc_hash::FxHashMap<&str, &SourceConfig> =
        catalog.sources.iter().map(|s| (s.id.as_str(), s)).collect();

    // Parse all downloaded sources in parallel across CPU cores
    let t_parse = Instant::now();
    let parsed_outcomes: Vec<(SourceConfig, Result<crate::model::ParsedSource>)> = fetched
        .par_iter()
        .filter_map(|item| {
            let src_cfg = (*cfg_by_id.get(item.source_id.as_str())?).clone();
            let res = fs::read(&item.data_path)
                .with_context(|| format!("failed reading cached {}", item.data_path.display()))
                .and_then(|bytes| parse_source_bytes(&src_cfg, &bytes, &metadata));
            Some((src_cfg, res))
        })
        .collect();

    let mut arena = GlobalArena::new();
    let mut sources_for_fusion = Vec::with_capacity(parsed_outcomes.len());
    let mut core_parse_errors = Vec::new();

    for (src_cfg, res) in parsed_outcomes {
        match res {
            Ok(parsed) => {
                info!(
                    source = %src_cfg.id,
                    v4_ranges = parsed.v4.len(),
                    v6_ranges = parsed.v6.len(),
                    payloads = parsed.payloads.len(),
                    asn_meta = parsed.asn_meta.len(),
                    "parsed source"
                );
                let (v4, v6) = arena.ingest_parsed_source(parsed, src_cfg.asn_weight.max(60));
                sources_for_fusion.push((src_cfg, v4, v6));
            }
            Err(err) => {
                if src_cfg.core {
                    core_parse_errors.push(format!("{}: {:#}", src_cfg.id, err));
                } else {
                    warn!(source = %src_cfg.id, error = %format!("{:#}", err), "non-core source failed to parse; skipping");
                }
            }
        }
    }

    if !core_parse_errors.is_empty() {
        bail!(
            "{} core source(s) failed to parse:\n  - {}",
            core_parse_errors.len(),
            core_parse_errors.join("\n  - ")
        );
    }

    let ingested_count = sources_for_fusion.len();
    info!(
        ingested = ingested_count,
        global_strings = arena.strings.len(),
        global_payloads = arena.payloads.len(),
        asn_dict = arena.asn_dict.len(),
        elapsed_secs = t_parse.elapsed().as_secs_f64(),
        "interned all upstream observations"
    );

    // Run dual-stack sweep-line fusion
    let t_fuse = Instant::now();
    let fused = run_fusion(&mut arena, &metadata, &overrides, sources_for_fusion);
    let country_v4_cidrs = fused.country_v4_cidr_count();
    let country_v6_cidrs = fused.country_v6_cidr_count();
    let cn_v4_cidrs = fused.cn_v4_cidr_count();
    let cn_v6_cidrs = fused.cn_v6_cidr_count();

    info!(
        country_records = fused.country_records.len(),
        asn_records = fused.asn_records.len(),
        country_v4_spans = fused.country_v4.len(),
        country_v6_spans = fused.country_v6.len(),
        cn_v4_spans = fused.cn_v4.len(),
        cn_v6_spans = fused.cn_v6.len(),
        elapsed_secs = t_fuse.elapsed().as_secs_f64(),
        "completed sweep-line multi-source fusion"
    );

    // Encode all three MMDB artifacts in parallel
    fs::create_dir_all(&opts.output_dir)
        .with_context(|| format!("failed creating output dir {}", opts.output_dir.display()))?;
    let build_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let t_enc = Instant::now();
    let country_out = opts.output_dir.join("Country.mmdb");
    let cn_out = opts.output_dir.join("Country-cn.mmdb");
    let asn_out = opts.output_dir.join("ASN.mmdb");

    let (country_res, (cn_res, asn_res)) = rayon::join(
        || {
            write_geo_mmdb(
                &country_out,
                "GeoLite2-City",
                "Surge Global Multi-Source GeoIP, ASN & Network Trait Database",
                "Surge 全球多源融合高精度 GeoIP、ASN 与网络特征数据库",
                build_epoch,
                &fused.country_records,
                &fused.country_v4,
                &fused.country_v6,
                &arena.strings,
                &metadata,
            )
        },
        || {
            rayon::join(
                || {
                    write_geo_mmdb(
                        &cn_out,
                        "GeoLite2-Country",
                        "Surge Mainland China Multi-Source GeoIP Database",
                        "Surge 中国大陆多源融合高精度 GeoIP 数据库",
                        build_epoch,
                        &fused.country_records,
                        &fused.cn_v4,
                        &fused.cn_v6,
                        &arena.strings,
                        &metadata,
                    )
                },
                || {
                    write_asn_mmdb(
                        &asn_out,
                        build_epoch,
                        &fused.asn_records,
                        &fused.asn_v4,
                        &fused.asn_v6,
                        &arena.strings,
                    )
                },
            )
        },
    );

    let s_country = country_res?;
    let s_cn = cn_res?;
    let s_asn = asn_res?;

    info!(
        country_bytes = s_country.size_bytes,
        cn_bytes = s_cn.size_bytes,
        asn_bytes = s_asn.size_bytes,
        elapsed_secs = t_enc.elapsed().as_secs_f64(),
        "encoded Country.mmdb, Country-cn.mmdb, and ASN.mmdb"
    );

    // Post-build verification & release notes
    let report = verify_artifact_dir(&opts.output_dir, true)?;
    let notes = render_release_notes(
        &report,
        ingested_count,
        total_catalog_sources,
        country_v4_cidrs,
        country_v6_cidrs,
        cn_v4_cidrs,
        cn_v6_cidrs,
    );
    let notes_path = opts.output_dir.join("release-notes.md");
    fs::write(&notes_path, notes)
        .with_context(|| format!("failed writing {}", notes_path.display()))?;

    info!(
        total_secs = t0.elapsed().as_secs_f64(),
        canaries = report.canaries_checked,
        "GeoIP build and verification succeeded"
    );

    Ok(report)
}

pub fn inspect_ip_in_dir(dir: &Path, ip_str: &str) -> Result<serde_json::Value> {
    let ip: std::net::IpAddr = ip_str
        .parse()
        .with_context(|| format!("invalid IP address '{}'", ip_str))?;
    let mut out = serde_json::Map::new();
    for file in ["Country.mmdb", "Country-cn.mmdb", "ASN.mmdb"] {
        let p = dir.join(file);
        if p.exists() {
            let reader = maxminddb::Reader::open_readfile(&p)?;
            let val: Option<serde_json::Value> = crate::verify::lookup_opt(&reader, ip)?;
            out.insert(file.to_string(), val.unwrap_or(serde_json::Value::Null));
        }
    }
    Ok(serde_json::Value::Object(out))
}
