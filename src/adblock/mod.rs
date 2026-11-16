pub mod compiler;
pub mod config;
pub mod jq_transpile;
pub mod model;
pub mod parsers;
pub mod regex_util;
pub mod verify;

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use tracing::{info, warn};

use crate::adblock::compiler::{TelemetryProtectionSet, compile_adblock_with_telemetry_guard};
use crate::adblock::config::{AdblockOverrides, AdblockSourceCatalog, AdblockSourceConfig};
use crate::adblock::model::ParsedAdblockSource;
use crate::adblock::parsers::parse_adblock_source;
use crate::adblock::verify::{
    AdblockVerificationReport, render_adblock_release_notes, verify_adblock_dir,
};
use crate::fetch::{FetchOptions, SourceFetcher};

pub struct BuildAdblockOptions {
    pub catalog_path: PathBuf,
    pub overrides_path: PathBuf,
    pub output_dir: PathBuf,
    pub fetch: FetchOptions,
    pub min_ruleset_lines: usize,
    pub min_privacy_lines: usize,
}

impl Default for BuildAdblockOptions {
    fn default() -> Self {
        Self {
            catalog_path: PathBuf::from("sources/generated/adblock-sources.json"),
            overrides_path: PathBuf::from("overrides/generated/adblock-overrides.json"),
            output_dir: PathBuf::from("dist"),
            fetch: FetchOptions {
                cache_dir: PathBuf::from(".cache/adblock"),
                concurrency: 16,
                ..FetchOptions::default()
            },
            min_ruleset_lines: 10_000,
            min_privacy_lines: 2_000,
        }
    }
}

pub async fn build_adblock_pipeline(
    opts: BuildAdblockOptions,
) -> Result<AdblockVerificationReport> {
    let t0 = Instant::now();
    let catalog = AdblockSourceCatalog::load_from_path(&opts.catalog_path)?;
    let overrides = AdblockOverrides::load_from_path(&opts.overrides_path)?;
    let total_sources = catalog.sources.len();

    info!(
        sources = total_sources,
        allow_domains = overrides.allow_domains.len(),
        protected_apex = overrides.protected_apex_domains.len(),
        "loaded Adblock catalog and human overrides"
    );

    let fetcher = Arc::new(SourceFetcher::new(opts.fetch.clone())?);
    let fetched = fetcher.fetch_all(&catalog.sources).await?;

    let cfg_by_id: FxHashMap<&str, &AdblockSourceConfig> =
        catalog.sources.iter().map(|s| (s.id.as_str(), s)).collect();

    let parsed_outcomes: Vec<(AdblockSourceConfig, Result<ParsedAdblockSource>)> = fetched
        .par_iter()
        .filter_map(|item| {
            let cfg = (*cfg_by_id.get(item.source_id.as_str())?).clone();
            let res = fs::read(&item.data_path)
                .with_context(|| format!("failed reading {}", item.data_path.display()))
                .and_then(|bytes| parse_adblock_source(&cfg, &bytes));
            Some((cfg, res))
        })
        .collect();

    let mut parsed_sources = Vec::with_capacity(parsed_outcomes.len());
    let mut core_errors = Vec::new();
    for (cfg, res) in parsed_outcomes {
        match res {
            Ok(p) => parsed_sources.push(p),
            Err(err) => {
                if cfg.core {
                    core_errors.push(format!("{}: {:#}", cfg.id, err));
                } else {
                    warn!(source = %cfg.id, error = %format!("{:#}", err), "non-core adblock source failed to parse");
                }
            }
        }
    }
    if !core_errors.is_empty() {
        bail!(
            "{} core adblock source(s) failed to parse:\n  - {}",
            core_errors.len(),
            core_errors.join("\n  - ")
        );
    }

    let telemetry_path = opts.output_dir.join("Telemetry.list");
    let telemetry_guard = if telemetry_path.exists() {
        let tel_raw = fs::read_to_string(&telemetry_path).with_context(|| {
            format!(
                "failed reading Telemetry.list at {}",
                telemetry_path.display()
            )
        })?;
        let guard = TelemetryProtectionSet::from_ruleset_text(&tel_raw);
        info!(
            telemetry_exact = guard.exact_domains.len(),
            telemetry_suffixes = guard.suffix_domains.len(),
            "loaded Telemetry.list protection guard for Adblock & Privacy compilation"
        );
        Some(guard)
    } else {
        None
    };

    let active_sources = parsed_sources.len();
    let compiled = compile_adblock_with_telemetry_guard(
        &parsed_sources,
        &overrides,
        telemetry_guard.as_ref(),
        active_sources,
        total_sources,
    );

    fs::create_dir_all(&opts.output_dir)
        .with_context(|| format!("failed creating {}", opts.output_dir.display()))?;
    fs::write(opts.output_dir.join("Adblock.list"), &compiled.ruleset_text)?;
    fs::write(
        opts.output_dir.join("Privacy.list"),
        &compiled.privacy_ruleset_text,
    )?;
    fs::write(
        opts.output_dir.join("Adblock.sgmodule"),
        &compiled.module_text,
    )?;

    let report = verify_adblock_dir(
        &opts.output_dir,
        &overrides,
        opts.min_ruleset_lines,
        opts.min_privacy_lines,
    )?;
    let notes = render_adblock_release_notes(
        &report,
        active_sources,
        total_sources,
        compiled.ruleset_counts.suppressed_by_protection,
        compiled.ruleset_counts.subsumed_by_trie,
    );
    fs::write(opts.output_dir.join("adblock-notes.md"), notes)?;

    info!(
        total_secs = t0.elapsed().as_secs_f64(),
        adblock_rules = report.ruleset_total,
        privacy_rules = report.privacy_ruleset_total,
        module_scripts = report.module_scripts,
        module_mitm = report.module_mitm_hosts,
        canaries = report.canaries_checked,
        "Adblock & Privacy build and verification succeeded"
    );

    Ok(report)
}
