pub mod compiler;
pub mod config;
pub mod model;
pub mod parsers;
pub mod verify;

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use tracing::{info, warn};

use crate::adblock::config::AdblockOverrides;
use crate::fetch::{FetchOptions, SourceFetcher};
use crate::routing::compiler::{RoutingSourceCounts, compile_routing};
use crate::routing::config::{
    RoutingOverrides, RoutingSourceCatalog, RoutingSourceConfig, RoutingTarget,
};
use crate::routing::model::ParsedRoutingSource;
use crate::routing::parsers::parse_routing_source;
use crate::routing::verify::{RoutingVerificationReport, render_routing_notes, verify_routing_dir};

pub struct BuildRoutingOptions {
    pub catalog_path: PathBuf,
    pub overrides_path: PathBuf,
    pub adblock_overrides_path: PathBuf,
    pub output_dir: PathBuf,
    pub fetch: FetchOptions,
    pub min_direct_lines: usize,
    pub min_ai_lines: usize,
    pub min_proxy_lines: usize,
}

impl Default for BuildRoutingOptions {
    fn default() -> Self {
        Self {
            catalog_path: PathBuf::from("sources/generated/routing-sources.json"),
            overrides_path: PathBuf::from("overrides/generated/routing-overrides.json"),
            adblock_overrides_path: PathBuf::from("overrides/generated/adblock-overrides.json"),
            output_dir: PathBuf::from("dist"),
            fetch: FetchOptions {
                cache_dir: PathBuf::from(".cache/routing"),
                concurrency: 16,
                offline: false,
                max_cache_age_secs: 1800,
                timeout_secs: 120,
            },
            min_direct_lines: 5_000,
            min_ai_lines: 200,
            min_proxy_lines: 5_000,
        }
    }
}

pub async fn build_routing_pipeline(
    opts: BuildRoutingOptions,
) -> Result<RoutingVerificationReport> {
    let started = Instant::now();
    let catalog = RoutingSourceCatalog::load_from_path(&opts.catalog_path)?;
    let overrides = RoutingOverrides::load_from_path(&opts.overrides_path)?;
    let adblock_overrides = if opts.adblock_overrides_path.exists() {
        AdblockOverrides::load_from_path(&opts.adblock_overrides_path)?
    } else {
        AdblockOverrides::empty()
    };

    fs::create_dir_all(&opts.output_dir)
        .with_context(|| format!("failed to create output dir {}", opts.output_dir.display()))?;

    let fetcher = Arc::new(SourceFetcher::new(opts.fetch.clone())?);
    let fetched = fetcher.fetch_all(&catalog.sources).await?;

    let total_direct = catalog
        .sources
        .iter()
        .filter(|s| s.target == RoutingTarget::Direct)
        .count();
    let total_ai = catalog
        .sources
        .iter()
        .filter(|s| s.target == RoutingTarget::Ai)
        .count();
    let total_proxy = catalog
        .sources
        .iter()
        .filter(|s| s.target == RoutingTarget::Proxy)
        .count();

    let source_map: std::collections::HashMap<&str, &RoutingSourceConfig> =
        catalog.sources.iter().map(|s| (s.id.as_str(), s)).collect();

    let parsed_results: Vec<(String, bool, RoutingTarget, Result<ParsedRoutingSource>)> = fetched
        .par_iter()
        .map(|item| {
            let src = source_map
                .get(item.source_id.as_str())
                .copied()
                .expect("fetched source must exist in catalog");
            let res = fs::read(&item.data_path)
                .with_context(|| format!("failed to read cached {}", item.data_path.display()))
                .and_then(|bytes| parse_routing_source(&bytes, src));
            (item.source_id.clone(), src.core, src.target, res)
        })
        .collect();

    let mut parsed_sources = Vec::with_capacity(parsed_results.len());
    let mut active_direct = 0usize;
    let mut active_ai = 0usize;
    let mut active_proxy = 0usize;

    for (id, is_core, target, res) in parsed_results {
        match res {
            Ok(parsed) => {
                if parsed.rules.is_empty() {
                    if is_core {
                        bail!("core routing source '{}' produced zero rules", id);
                    }
                    warn!(source = %id, "non-core routing source produced zero rules; skipping");
                    continue;
                }
                match target {
                    RoutingTarget::Direct => active_direct += 1,
                    RoutingTarget::Ai => active_ai += 1,
                    RoutingTarget::Proxy => active_proxy += 1,
                }
                parsed_sources.push(parsed);
            }
            Err(err) => {
                if is_core {
                    bail!("failed parsing core routing source '{}': {:#}", id, err);
                }
                warn!(source = %id, error = %format!("{:#}", err), "skipping non-core routing source");
            }
        }
    }

    info!(
        direct = format!("{}/{}", active_direct, total_direct),
        ai = format!("{}/{}", active_ai, total_ai),
        proxy = format!("{}/{}", active_proxy, total_proxy),
        "parsed routing sources; compiling RULE-SET artifacts"
    );

    let compiled = compile_routing(
        &parsed_sources,
        &overrides,
        &adblock_overrides,
        RoutingSourceCounts {
            active_direct,
            total_direct,
            active_ai,
            total_ai,
            active_proxy,
            total_proxy,
        },
    );

    info!(
        direct = compiled.direct_stats.total_rules,
        ai = compiled.ai_stats.total_rules,
        proxy = compiled.proxy_stats.total_rules,
        ad_filtered = compiled.ad_domains_filtered,
        conflicts = compiled.conflicts_resolved,
        ai_merged = compiled.ai_merged_into_proxy,
        "compiled routing RULE-SETs; writing and verifying artifacts"
    );

    fs::write(
        opts.output_dir.join(RoutingTarget::Direct.filename()),
        &compiled.direct_text,
    )?;
    fs::write(
        opts.output_dir.join(RoutingTarget::Ai.filename()),
        &compiled.ai_text,
    )?;
    fs::write(
        opts.output_dir.join(RoutingTarget::Proxy.filename()),
        &compiled.proxy_text,
    )?;

    let report = verify_routing_dir(
        &opts.output_dir,
        &overrides,
        opts.min_direct_lines,
        opts.min_ai_lines,
        opts.min_proxy_lines,
        true,
    )?;
    let notes = render_routing_notes(&report);
    fs::write(opts.output_dir.join("routing-notes.md"), &notes)?;

    info!(
        elapsed_secs = started.elapsed().as_secs_f32(),
        direct = report.direct_total,
        ai = report.ai_total,
        proxy = report.proxy_total,
        "routing build and verification succeeded"
    );

    Ok(report)
}
