#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use surge_rules::adblock::config::AdblockOverrides;
use surge_rules::adblock::verify::verify_adblock_dir;
use surge_rules::adblock::{BuildAdblockOptions, build_adblock_pipeline};
use surge_rules::fetch::FetchOptions;
use surge_rules::routing::config::RoutingOverrides;
use surge_rules::routing::verify::{RoutingThresholds, verify_routing_dir};
use surge_rules::routing::{BuildRoutingOptions, build_routing_pipeline};
use surge_rules::verify::verify_artifact_dir;
use surge_rules::{BuildGeoIpOptions, build_geoip_pipeline, inspect_ip_in_dir};

#[derive(Parser)]
#[command(
    name = "surge-rules",
    version,
    about = "Multi-source GeoIP MMDB, Surge Adblock, and Routing RULE-SET builder"
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
    /// Build or verify Surge Adblock & Privacy RULE-SETs (Adblock.list, Privacy.list) and Module (Adblock.sgmodule)
    Adblock {
        #[command(subcommand)]
        action: AdblockCommand,
    },
    /// Build or verify Surge Routing RULE-SETs (Direct.list, AI.list, Payment.list, Telemetry.list, Proxy.list)
    Routing {
        #[command(subcommand)]
        action: RoutingCommand,
    },
}

#[derive(Subcommand)]
enum RoutingCommand {
    /// Fetch upstream routing feeds, compile Direct/AI/Payment/Telemetry/Proxy RULE-SETs, and run verification
    Build {
        #[arg(long, default_value = "sources/generated/routing-sources.json")]
        catalog: PathBuf,
        #[arg(long, default_value = "overrides/generated/routing-overrides.json")]
        overrides: PathBuf,
        #[arg(long, default_value = "overrides/generated/adblock-overrides.json")]
        adblock_overrides: PathBuf,
        #[arg(long, default_value = ".cache/routing")]
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
    /// Verify generated Direct.list, AI.list, Payment.list, Telemetry.list, and Proxy.list in a directory
    Verify {
        #[arg(long, default_value = "dist")]
        dir: PathBuf,
        #[arg(long, default_value = "overrides/generated/routing-overrides.json")]
        overrides: PathBuf,
        #[arg(long, default_value_t = 5_000)]
        min_direct_lines: usize,
        #[arg(long, default_value_t = 200)]
        min_ai_lines: usize,
        #[arg(long, default_value_t = 200)]
        min_payment_lines: usize,
        #[arg(long, default_value_t = 100)]
        min_telemetry_lines: usize,
        #[arg(long, default_value_t = 5_000)]
        min_proxy_lines: usize,
    },
}

#[derive(Subcommand)]
enum AdblockCommand {
    /// Fetch upstream adblock/module feeds, compile Adblock.list, Privacy.list, and Adblock.sgmodule, and run verification
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
    /// Verify generated Adblock.list, Privacy.list, and Adblock.sgmodule in a directory
    Verify {
        #[arg(long, default_value = "dist")]
        dir: PathBuf,
        #[arg(long, default_value = "overrides/generated/adblock-overrides.json")]
        overrides: PathBuf,
        #[arg(long, default_value_t = 10_000)]
        min_ruleset_lines: usize,
        #[arg(long, default_value_t = 2_000)]
        min_privacy_lines: usize,
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
                    "Built and verified {} ({} B), {} ({} B), {} ({} B), {} ({} B) [{} canaries passed]",
                    report.country.file_name,
                    report.country.size_bytes,
                    report.country_only.file_name,
                    report.country_only.size_bytes,
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
                    "Verified {} ({} nodes), {} ({} nodes), {} ({} nodes), {} ({} nodes) [{} canaries passed]",
                    report.country.file_name,
                    report.country.node_count,
                    report.country_only.file_name,
                    report.country_only.node_count,
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
                    min_privacy_lines: 2_000,
                };
                let report = build_adblock_pipeline(opts).await?;
                println!(
                    "Built and verified {} ({} rules, {} B), {} ({} rules, {} B), {} ({} scripts, {} MITM hosts, {} B) [{} canaries passed]",
                    report.ruleset.file_name,
                    report.ruleset_total,
                    report.ruleset.size_bytes,
                    report.privacy_ruleset.file_name,
                    report.privacy_ruleset_total,
                    report.privacy_ruleset.size_bytes,
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
                min_privacy_lines,
            } => {
                let ov = AdblockOverrides::load_from_path(&overrides)?;
                let report = verify_adblock_dir(&dir, &ov, min_ruleset_lines, min_privacy_lines)?;
                println!(
                    "Verified {} ({} rules), {} ({} rules), {} ({} scripts, {} MITM hosts) [{} canaries passed]",
                    report.ruleset.file_name,
                    report.ruleset_total,
                    report.privacy_ruleset.file_name,
                    report.privacy_ruleset_total,
                    report.module.file_name,
                    report.module_scripts,
                    report.module_mitm_hosts,
                    report.canaries_checked
                );
            }
        },
        TopCommand::Routing { action } => match action {
            RoutingCommand::Build {
                catalog,
                overrides,
                adblock_overrides,
                cache_dir,
                output,
                concurrency,
                offline,
                max_cache_age_secs,
            } => {
                let opts = BuildRoutingOptions {
                    catalog_path: catalog,
                    overrides_path: overrides,
                    adblock_overrides_path: adblock_overrides,
                    output_dir: output,
                    fetch: FetchOptions {
                        cache_dir,
                        concurrency,
                        offline,
                        max_cache_age_secs,
                        timeout_secs: 120,
                    },
                    ..BuildRoutingOptions::default()
                };
                let report = build_routing_pipeline(opts).await?;
                println!(
                    "Built and verified {} ({} rules, {} B), {} ({} rules, {} B), {} ({} rules, {} B), {} ({} rules, {} B), {} ({} rules, {} B) [{} canaries passed]",
                    report.direct.file_name,
                    report.direct_total,
                    report.direct.size_bytes,
                    report.ai.file_name,
                    report.ai_total,
                    report.ai.size_bytes,
                    report.payment.file_name,
                    report.payment_total,
                    report.payment.size_bytes,
                    report.telemetry.file_name,
                    report.telemetry_total,
                    report.telemetry.size_bytes,
                    report.proxy.file_name,
                    report.proxy_total,
                    report.proxy.size_bytes,
                    report.canaries_checked
                );
            }
            RoutingCommand::Verify {
                dir,
                overrides,
                min_direct_lines,
                min_ai_lines,
                min_payment_lines,
                min_telemetry_lines,
                min_proxy_lines,
            } => {
                let ov = RoutingOverrides::load_from_path(&overrides)?;
                let report = verify_routing_dir(
                    &dir,
                    &ov,
                    RoutingThresholds {
                        min_direct_lines,
                        min_ai_lines,
                        min_payment_lines,
                        min_telemetry_lines,
                        min_proxy_lines,
                    },
                    true,
                )?;
                println!(
                    "Verified {} ({} rules), {} ({} rules), {} ({} rules), {} ({} rules), {} ({} rules) [{} canaries passed]",
                    report.direct.file_name,
                    report.direct_total,
                    report.ai.file_name,
                    report.ai_total,
                    report.payment.file_name,
                    report.payment_total,
                    report.telemetry.file_name,
                    report.telemetry_total,
                    report.proxy.file_name,
                    report.proxy_total,
                    report.canaries_checked
                );
            }
        },
    }

    Ok(())
}
