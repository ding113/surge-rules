use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use surge_rules::fetch::FetchOptions;
use surge_rules::verify::verify_artifact_dir;
use surge_rules::{BuildGeoIpOptions, build_geoip_pipeline, inspect_ip_in_dir};

#[derive(Parser)]
#[command(
    name = "surge-rules",
    version,
    about = "Multi-source GeoIP, Geofeed, BGP/ASN, and network-trait fusion builder for Surge"
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
    }

    Ok(())
}
