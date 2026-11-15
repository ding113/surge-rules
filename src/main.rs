use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use surge_rules::adblock::config::AdblockOverrides;
use surge_rules::adblock::verify::verify_adblock_dir;
use surge_rules::adblock::{BuildAdblockOptions, build_adblock_pipeline};
use surge_rules::fetch::FetchOptions;
use surge_rules::verify::verify_artifact_dir;
use surge_rules::{BuildGeoIpOptions, build_geoip_pipeline, inspect_ip_in_dir};

#[derive(Parser)]
#[command(
    name = "surge-rules",
    version,
    about = "Multi-source GeoIP MMDB and Surge Adblock RULE-SET / Module builder"
)]
struct Cli {
    #[command(subcommand)]
    command: TopCommand,
}

#[derive(Subcommand)]
enum TopCommand {
    /// Build, verify, or inspect Surge MMDB GeoIP artifacts
    Geoip {
        #[command(subcommand)]
        action: GeoipCommand,
    },
    /// Build or verify Surge Adblock RULE-SET (Adblock.list) and Module (Adblock.sgmodule)
    Adblock {
        #[command(subcommand)]
        action: AdblockCommand,
    },
}

#[derive(Subcommand)]
enum AdblockCommand {
    /// Fetch upstream adblock/module feeds, compile Surge RULE-SET and Module, and run verification
    Build {
        #[arg(long, default_value = "sources/generated/adblock-sources.json")]
        catalog: PathBuf,
        #[arg(long, default_value = "overrides/generated/adblock-overrides.json")]
        overrides: PathBuf,
        #[arg(long, default_value = ".cache/adblock")]
        cache_dir: PathBuf,
        #[arg(long, default_value = "dist")]
        output: PathBuf,
        #[arg(long, default_value_t = 16)]
        concurrency: usize,
        #[arg(long, default_value_t = false)]
        offline: bool,
        #[arg(long, default_value_t = 1800)]
        max_cache_age_secs: u64,
    },
    /// Verify generated Adblock.list and Adblock.sgmodule in a directory
    Verify {
        #[arg(long, default_value = "dist")]
        dir: PathBuf,
        #[arg(long, default_value = "overrides/generated/adblock-overrides.json")]
        overrides: PathBuf,
        #[arg(long, default_value_t = 10_000)]
        min_ruleset_lines: usize,
    },
}

#[derive(Subcommand)]
enum GeoipCommand {
    /// Fetch upstream feeds, fuse observations, encode MMDBs, and run verification
    Build {
        #[arg(long, default_value = "sources/generated/geoip-sources.json")]
        catalog: PathBuf,
        #[arg(long, default_value = "metadata/generated/geoip-metadata.json")]
        metadata: PathBuf,
        #[arg(long, default_value = "overrides/generated/geoip-overrides.json")]
        overrides: PathBuf,
        #[arg(long, default_value = ".cache/upstream")]
        cache_dir: PathBuf,
        #[arg(long, default_value = "dist")]
        output: PathBuf,
        #[arg(long, default_value_t = 12)]
        concurrency: usize,
        #[arg(long, default_value_t = false)]
        offline: bool,
        #[arg(long, default_value_t = 1800)]
        max_cache_age_secs: u64,
    },
    /// Verify generated Country.mmdb, Country-cn.mmdb, and ASN.mmdb in a directory
    Verify {
        #[arg(long, default_value = "dist")]
        dir: PathBuf,
    },
    /// Inspect an IPv4 or IPv6 address across Country.mmdb, Country-cn.mmdb, and ASN.mmdb
    Inspect {
        ip: String,
        #[arg(long, default_value = "dist")]
        dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    match cli.command {
        TopCommand::Geoip { action } => match action {
            GeoipCommand::Build {
                catalog,
                metadata,
                overrides,
                cache_dir,
                output,
                concurrency,
                offline,
                max_cache_age_secs,
            } => {
                let opts = BuildGeoIpOptions {
                    catalog_path: catalog,
                    metadata_path: metadata,
                    overrides_path: overrides,
                    output_dir: output,
                    fetch: FetchOptions {
                        cache_dir,
                        concurrency,
                        offline,
                        max_cache_age_secs,
                        timeout_secs: 120,
                    },
                };
                let report = build_geoip_pipeline(opts).await?;
                println!(
                    "Built and verified {} ({} B), {} ({} B), {} ({} B) [{} canaries passed]",
                    report.country.file_name,
                    report.country.size_bytes,
                    report.country_cn.file_name,
                    report.country_cn.size_bytes,
                    report.asn.file_name,
                    report.asn.size_bytes,
                    report.canaries_checked
                );
            }
            GeoipCommand::Verify { dir } => {
                let report = verify_artifact_dir(&dir, true)?;
                println!(
                    "Verified {} ({} nodes), {} ({} nodes), {} ({} nodes) [{} canaries passed]",
                    report.country.file_name,
                    report.country.node_count,
                    report.country_cn.file_name,
                    report.country_cn.node_count,
                    report.asn.file_name,
                    report.asn.node_count,
                    report.canaries_checked
                );
            }
            GeoipCommand::Inspect { ip, dir } => {
                let res = inspect_ip_in_dir(&dir, &ip)?;
                println!("{}", serde_json::to_string_pretty(&res)?);
            }
        },
        TopCommand::Adblock { action } => match action {
            AdblockCommand::Build {
                catalog,
                overrides,
                cache_dir,
                output,
                concurrency,
                offline,
                max_cache_age_secs,
            } => {
                let opts = BuildAdblockOptions {
                    catalog_path: catalog,
                    overrides_path: overrides,
                    output_dir: output,
                    fetch: FetchOptions {
                        cache_dir,
                        concurrency,
                        offline,
                        max_cache_age_secs,
                        timeout_secs: 120,
                    },
                    min_ruleset_lines: 10_000,
                };
                let report = build_adblock_pipeline(opts).await?;
                println!(
                    "Built and verified {} ({} rules, {} B), {} ({} scripts, {} MITM hosts, {} B) [{} canaries passed]",
                    report.ruleset.file_name,
                    report.ruleset_total,
                    report.ruleset.size_bytes,
                    report.module.file_name,
                    report.module_scripts,
                    report.module_mitm_hosts,
                    report.module.size_bytes,
                    report.canaries_checked
                );
            }
            AdblockCommand::Verify {
                dir,
                overrides,
                min_ruleset_lines,
            } => {
                let ov = AdblockOverrides::load_from_path(&overrides)?;
                let report = verify_adblock_dir(&dir, &ov, min_ruleset_lines)?;
                println!(
                    "Verified {} ({} rules), {} ({} scripts, {} MITM hosts) [{} canaries passed]",
                    report.ruleset.file_name,
                    report.ruleset_total,
                    report.module.file_name,
                    report.module_scripts,
                    report.module_mitm_hosts,
                    report.canaries_checked
                );
            }
        },
    }

    Ok(())
}
