use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use flate2::read::MultiGzDecoder;
use regex::Regex;
use reqwest::header::{
    ETAG, HeaderMap, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, USER_AGENT,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::config::{EndpointConfig, SourceConfig};

pub trait FetchableSource: Send + Sync + Clone + 'static {
    fn id(&self) -> &str;
    fn is_core(&self) -> bool;
    fn endpoints(&self) -> &[EndpointConfig];
}

impl FetchableSource for SourceConfig {
    fn id(&self) -> &str {
        &self.id
    }

    fn is_core(&self) -> bool {
        self.core
    }

    fn endpoints(&self) -> &[EndpointConfig] {
        &self.endpoints
    }
}

pub const BUILDER_USER_AGENT: &str =
    "surge-rules-geoip-builder/0.1 (+https://github.com/ding113/surge-rules)";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedSourceMeta {
    pub source_id: String,
    pub resolved_url: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub sha256: String,
    pub size_bytes: u64,
    pub fetched_at_epoch: u64,
}

#[derive(Clone, Debug)]
pub struct FetchedSource {
    pub source_id: String,
    pub data_path: PathBuf,
    pub meta: CachedSourceMeta,
    pub from_cache: bool,
}

#[derive(Clone, Debug)]
pub struct FetchOptions {
    pub cache_dir: PathBuf,
    pub concurrency: usize,
    pub offline: bool,
    pub max_cache_age_secs: u64,
    pub timeout_secs: u64,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            cache_dir: PathBuf::from(".cache/upstream"),
            concurrency: 12,
            offline: false,
            max_cache_age_secs: 1800,
            timeout_secs: 120,
        }
    }
}

#[derive(Deserialize)]
struct GhRelease {
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    assets: Vec<GhAsset>,
}

#[derive(Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Deserialize)]
struct NpmLatestMeta {
    dist: NpmDist,
}

#[derive(Deserialize)]
struct NpmDist {
    tarball: String,
}

pub struct SourceFetcher {
    client: reqwest::Client,
    github_token: Option<String>,
    opts: FetchOptions,
}

impl SourceFetcher {
    pub fn new(opts: FetchOptions) -> Result<Self> {
        fs::create_dir_all(&opts.cache_dir)
            .with_context(|| format!("failed to create cache dir {}", opts.cache_dir.display()))?;

        let mut default_headers = HeaderMap::new();
        default_headers.insert(USER_AGENT, HeaderValue::from_static(BUILDER_USER_AGENT));

        let client = reqwest::Client::builder()
            .default_headers(default_headers)
            .connect_timeout(Duration::from_secs(20))
            .timeout(Duration::from_secs(opts.timeout_secs))
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
            .context("failed to build HTTP client")?;

        let github_token = std::env::var("GITHUB_TOKEN")
            .ok()
            .or_else(|| std::env::var("GH_TOKEN").ok())
            .filter(|s| !s.trim().is_empty());

        Ok(Self {
            client,
            github_token,
            opts,
        })
    }

    pub async fn fetch_all<S: FetchableSource>(
        self: Arc<Self>,
        sources: &[S],
    ) -> Result<Vec<FetchedSource>> {
        let sem = Arc::new(Semaphore::new(self.opts.concurrency.max(1)));
        let mut handles = Vec::with_capacity(sources.len());

        for src in sources.iter().cloned() {
            let fetcher = Arc::clone(&self);
            let sem = Arc::clone(&sem);
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire_owned().await?;
                let res = fetcher.fetch_one(&src).await;
                Ok::<(S, Result<FetchedSource>), anyhow::Error>((src, res))
            }));
        }

        let mut fetched = Vec::with_capacity(sources.len());
        let mut core_failures = Vec::new();

        for handle in handles {
            let (src, outcome) = handle.await.context("fetch worker task panicked")??;
            match outcome {
                Ok(item) => fetched.push(item),
                Err(err) => {
                    if src.is_core() {
                        core_failures.push(format!("{}: {:#}", src.id(), err));
                    } else {
                        warn!(source = %src.id(), error = %format!("{:#}", err), "non-core source unavailable; continuing");
                    }
                }
            }
        }

        if !core_failures.is_empty() {
            bail!(
                "{} core source(s) failed to fetch:\n  - {}",
                core_failures.len(),
                core_failures.join("\n  - ")
            );
        }

        Ok(fetched)
    }

    pub async fn fetch_one<S: FetchableSource>(&self, src: &S) -> Result<FetchedSource> {
        let id = src.id();
        let endpoints = src.endpoints();
        let data_path = self.opts.cache_dir.join(format!("{}.bin", id));
        let meta_path = self.opts.cache_dir.join(format!("{}.meta.json", id));

        let existing_meta: Option<CachedSourceMeta> = if data_path.exists() && meta_path.exists() {
            fs::read_to_string(&meta_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
        } else {
            None
        };

        let now = now_epoch();

        if self.opts.offline {
            if let Some(meta) = existing_meta {
                return Ok(FetchedSource {
                    source_id: id.to_string(),
                    data_path,
                    meta,
                    from_cache: true,
                });
            }
            bail!("offline mode enabled and no cached file for '{}'", id);
        }

        if let Some(ref meta) = existing_meta {
            let url_matches_endpoints = !endpoints
                .iter()
                .all(|ep| matches!(ep, EndpointConfig::Direct { .. }))
                || endpoints.iter().any(|ep| match ep {
                    EndpointConfig::Direct { url } => {
                        url == &meta.resolved_url
                            || (is_microsoft_download_page(url)
                                && meta
                                    .resolved_url
                                    .starts_with("https://download.microsoft.com/download/"))
                    }
                    _ => false,
                });
            if url_matches_endpoints
                && now.saturating_sub(meta.fetched_at_epoch) < self.opts.max_cache_age_secs
                && meta.size_bytes > 0
            {
                info!(source = %id, size = meta.size_bytes, "using fresh cached upstream artifact");
                return Ok(FetchedSource {
                    source_id: id.to_string(),
                    data_path,
                    meta: meta.clone(),
                    from_cache: true,
                });
            }
        }

        let mut errors = Vec::new();

        for endpoint in endpoints {
            match self
                .fetch_from_endpoint(id, endpoint, existing_meta.as_ref(), &data_path, &meta_path)
                .await
            {
                Ok(res) => return Ok(res),
                Err(err) => {
                    warn!(
                        source = %id,
                        endpoint = ?endpoint,
                        error = %format!("{:#}", err),
                        "endpoint attempt failed; trying next fallback if available"
                    );
                    errors.push(format!("{:?}: {:#}", endpoint, err));
                }
            }
        }

        if let Some(meta) = existing_meta {
            warn!(
                source = %id,
                cached_url = %meta.resolved_url,
                "all live endpoints failed; falling back to previously cached artifact"
            );
            return Ok(FetchedSource {
                source_id: id.to_string(),
                data_path,
                meta,
                from_cache: true,
            });
        }

        Err(anyhow!(
            "all endpoints failed for '{}': {}",
            id,
            errors.join(" | ")
        ))
    }

    async fn fetch_from_endpoint(
        &self,
        source_id: &str,
        endpoint: &EndpointConfig,
        existing_meta: Option<&CachedSourceMeta>,
        data_path: &Path,
        meta_path: &Path,
    ) -> Result<FetchedSource> {
        let (resolved_url, npm_member_path) = match endpoint {
            EndpointConfig::Direct { url } => {
                if is_microsoft_download_page(url) {
                    let dyn_url = self.resolve_microsoft_download_url(url).await?;
                    (dyn_url, None)
                } else {
                    (url.clone(), None)
                }
            }
            EndpointConfig::GithubRelease {
                repo,
                asset_pattern,
            } => {
                let url = self
                    .resolve_github_release_asset(repo, asset_pattern)
                    .await?;
                (url, None)
            }
            EndpointConfig::NpmTarball {
                package,
                member_path,
            } => {
                let url = self.resolve_npm_tarball(package).await?;
                (url, Some(member_path.as_str()))
            }
        };

        let mut last_err = None;
        for attempt in 1..=3u32 {
            match self
                .download_with_cache(
                    source_id,
                    &resolved_url,
                    npm_member_path,
                    existing_meta,
                    data_path,
                    meta_path,
                )
                .await
            {
                Ok(res) => return Ok(res),
                Err(err) => {
                    last_err = Some(err);
                    if attempt < 3 {
                        tokio::time::sleep(Duration::from_millis(600 * (1 << (attempt - 1)))).await;
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("download failed")))
    }

    async fn resolve_github_release_asset(
        &self,
        repo: &str,
        asset_pattern: &str,
    ) -> Result<String> {
        let re = Regex::new(asset_pattern)
            .with_context(|| format!("invalid asset_pattern regex '{}'", asset_pattern))?;
        let api_url = format!("https://api.github.com/repos/{}/releases?per_page=10", repo);

        let mut req = self
            .client
            .get(&api_url)
            .header("Accept", "application/vnd.github+json");
        if let Some(ref token) = self.github_token {
            req = req.bearer_auth(token);
        }

        let resp = req
            .send()
            .await
            .with_context(|| format!("GET {}", api_url))?;
        if resp.status().is_success() {
            let releases: Vec<GhRelease> = resp
                .json()
                .await
                .with_context(|| format!("decode GitHub releases JSON for {}", repo))?;
            for rel in releases {
                if rel.draft {
                    continue;
                }
                for asset in rel.assets {
                    if re.is_match(&asset.name) {
                        return Ok(asset.browser_download_url);
                    }
                }
            }
            bail!(
                "no release asset matching '{}' found in recent releases of {}",
                asset_pattern,
                repo
            );
        }

        // Unauthenticated fallback when GitHub REST API is rate-limited (403/429):
        // derive literal filename from simple anchored patterns like `^GeoLite2-City\.mmdb$`
        // and use `/releases/latest/download/{filename}`.
        if let Some(literal_name) = simple_anchored_filename(asset_pattern) {
            let direct_latest = format!(
                "https://github.com/{}/releases/latest/download/{}",
                repo, literal_name
            );
            return Ok(direct_latest);
        }

        bail!(
            "GitHub API {} returned HTTP {} for {}",
            api_url,
            resp.status(),
            repo
        )
    }

    async fn resolve_npm_tarball(&self, package: &str) -> Result<String> {
        let url = format!("https://registry.npmjs.org/{}/latest", package);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {}", url))?
            .error_for_status()
            .with_context(|| format!("npm registry error for {}", package))?;
        let meta: NpmLatestMeta = resp
            .json()
            .await
            .with_context(|| format!("invalid npm metadata JSON for {}", package))?;
        Ok(meta.dist.tarball)
    }

    async fn resolve_microsoft_download_url(&self, page_url: &str) -> Result<String> {
        let mut candidates = vec![page_url.to_string()];
        if page_url.contains("/download/confirmation.aspx") {
            candidates
                .push(page_url.replace("/download/confirmation.aspx", "/download/details.aspx"));
        } else if page_url.contains("/download/details.aspx") {
            candidates
                .push(page_url.replace("/download/details.aspx", "/download/confirmation.aspx"));
        }

        let mut last_err = None;
        for candidate in &candidates {
            match self.client.get(candidate).send().await {
                Ok(resp) => match resp.error_for_status() {
                    Ok(ok_resp) => match ok_resp.text().await {
                        Ok(html) => {
                            if let Some(json_url) = extract_microsoft_download_json_url(&html) {
                                return Ok(json_url);
                            }
                            last_err = Some(anyhow!(
                                "no download.microsoft.com JSON link found on {}",
                                candidate
                            ));
                        }
                        Err(err) => last_err = Some(err.into()),
                    },
                    Err(err) => last_err = Some(err.into()),
                },
                Err(err) => last_err = Some(err.into()),
            }
        }

        Err(last_err.unwrap_or_else(|| {
            anyhow!(
                "failed resolving Microsoft Download Center URL {}",
                page_url
            )
        }))
    }

    async fn download_with_cache(
        &self,
        source_id: &str,
        url: &str,
        npm_member_path: Option<&str>,
        existing_meta: Option<&CachedSourceMeta>,
        data_path: &Path,
        meta_path: &Path,
    ) -> Result<FetchedSource> {
        let mut req = self.client.get(url);
        if let Some(meta) = existing_meta
            && meta.resolved_url == url
            && data_path.exists()
        {
            if let Some(ref etag) = meta.etag
                && let Ok(hv) = HeaderValue::from_str(etag)
            {
                req = req.header(IF_NONE_MATCH, hv);
            }
            if let Some(ref lm) = meta.last_modified
                && let Ok(hv) = HeaderValue::from_str(lm)
            {
                req = req.header(IF_MODIFIED_SINCE, hv);
            }
        }

        let resp = req
            .send()
            .await
            .with_context(|| format!("HTTP request failed: {}", url))?;

        if resp.status() == reqwest::StatusCode::NOT_MODIFIED
            && let Some(meta) = existing_meta
        {
            let mut refreshed = meta.clone();
            refreshed.fetched_at_epoch = now_epoch();
            let _ = fs::write(meta_path, serde_json::to_vec_pretty(&refreshed)?);
            info!(source = %source_id, "304 Not Modified; reusing cached file");
            return Ok(FetchedSource {
                source_id: source_id.to_string(),
                data_path: data_path.to_path_buf(),
                meta: refreshed,
                from_cache: true,
            });
        }

        let resp = resp
            .error_for_status()
            .with_context(|| format!("HTTP status error for {}", url))?;

        let etag = resp
            .headers()
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let last_modified = resp
            .headers()
            .get(LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        let raw_bytes = resp
            .bytes()
            .await
            .with_context(|| format!("failed reading response body from {}", url))?;

        if raw_bytes.is_empty() {
            bail!("empty response body from {}", url);
        }

        let url_owned = url.to_string();
        let member_owned = npm_member_path.map(str::to_string);
        let unpacked = tokio::task::spawn_blocking(move || {
            unpack_payload(&raw_bytes, &url_owned, member_owned.as_deref())
        })
        .await
        .context("unpack worker panicked")??;

        if unpacked.is_empty() {
            bail!("unpacked payload is empty for {}", url);
        }

        let mut hasher = Sha256::new();
        hasher.update(&unpacked);
        let sha256 = hex::encode(hasher.finalize());
        let size_bytes = unpacked.len() as u64;

        let tmp_path = data_path.with_extension("bin.tmp");
        fs::write(&tmp_path, &unpacked)
            .with_context(|| format!("failed writing {}", tmp_path.display()))?;
        fs::rename(&tmp_path, data_path).with_context(|| {
            format!(
                "failed renaming {} -> {}",
                tmp_path.display(),
                data_path.display()
            )
        })?;

        let meta = CachedSourceMeta {
            source_id: source_id.to_string(),
            resolved_url: url.to_string(),
            etag,
            last_modified,
            sha256,
            size_bytes,
            fetched_at_epoch: now_epoch(),
        };
        fs::write(meta_path, serde_json::to_vec_pretty(&meta)?)
            .with_context(|| format!("failed writing {}", meta_path.display()))?;

        info!(source = %source_id, bytes = size_bytes, url = %url, "fetched and unpacked upstream source");
        Ok(FetchedSource {
            source_id: source_id.to_string(),
            data_path: data_path.to_path_buf(),
            meta,
            from_cache: false,
        })
    }
}

fn unpack_payload(raw: &[u8], url: &str, npm_member_path: Option<&str>) -> Result<Vec<u8>> {
    // 1. npm `.tgz` member extraction
    if let Some(member_target) = npm_member_path {
        let gz = MultiGzDecoder::new(Cursor::new(raw));
        let mut archive = tar::Archive::new(gz);
        for entry_res in archive
            .entries()
            .context("failed reading npm tar entries")?
        {
            let mut entry = entry_res.context("corrupt npm tar entry")?;
            let path = entry.path().context("invalid tar path")?;
            let path_str = path.to_string_lossy();
            if path_str == member_target
                || path_str.ends_with(member_target.trim_start_matches("package/"))
            {
                let mut out = Vec::with_capacity(entry.size() as usize);
                entry.read_to_end(&mut out)?;
                return Ok(out);
            }
        }
        bail!(
            "member '{}' not found in npm tarball {}",
            member_target,
            url
        );
    }

    // 2. Gzip magic `[0x1f, 0x8b]`
    if raw.len() >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
        let mut gz = MultiGzDecoder::new(Cursor::new(raw));
        let mut out = Vec::with_capacity(raw.len() * 2);
        gz.read_to_end(&mut out)
            .with_context(|| format!("gzip decompression failed for {}", url))?;
        return Ok(out);
    }

    // 3. XZ magic `[0xfd, b'7', b'z', b'X', b'Z', 0x00]`
    if raw.len() >= 6 && &raw[..6] == b"\xfd7zXZ\x00" {
        let mut reader = Cursor::new(raw);
        let mut out = Vec::with_capacity(raw.len() * 3);
        lzma_rs::xz_decompress(&mut reader, &mut out)
            .map_err(|e| anyhow!("xz decompression failed for {}: {}", url, e))?;
        return Ok(out);
    }

    // 4. ZIP magic `PK\x03\x04`
    if raw.len() >= 4 && &raw[..4] == b"PK\x03\x04" {
        let mut archive = zip::ZipArchive::new(Cursor::new(raw))
            .with_context(|| format!("invalid zip {}", url))?;
        let mut best_idx: Option<(usize, u64)> = None;
        for i in 0..archive.len() {
            let file = archive.by_index(i)?;
            if file.is_dir() {
                continue;
            }
            let name_lower = file.name().to_ascii_lowercase();
            if name_lower.contains("readme") || name_lower.contains("license") {
                continue;
            }
            let sz = file.size();
            if best_idx.is_none_or(|(_, prev_sz)| sz > prev_sz) {
                best_idx = Some((i, sz));
            }
        }
        let (idx, sz) = best_idx.with_context(|| format!("no data entry found in zip {}", url))?;
        // Keep large ZIP archives (> 64 MiB uncompressed, such as ipapi.is 590 MB CSVs)
        // compressed on disk and in RAM so streaming ZIP parsers read them directly.
        if sz > 64 * 1024 * 1024 {
            return Ok(raw.to_vec());
        }
        let mut file = archive.by_index(idx)?;
        let mut out = Vec::with_capacity(sz as usize);
        file.read_to_end(&mut out)?;
        return Ok(out);
    }

    Ok(raw.to_vec())
}

fn is_microsoft_download_page(url: &str) -> bool {
    (url.starts_with("https://www.microsoft.com/") || url.starts_with("https://microsoft.com/"))
        && (url.contains("/download/confirmation.aspx") || url.contains("/download/details.aspx"))
}

pub fn extract_microsoft_download_json_url(html: &str) -> Option<String> {
    let re = Regex::new(r#"https://download\.microsoft\.com/download/[^"'\s<>]+\.json"#).ok()?;
    let mut service_tags_urls: Vec<String> = Vec::new();
    let mut fallback_url: Option<String> = None;
    for m in re.find_iter(html) {
        let u = m.as_str().to_string();
        if u.contains("ServiceTags_Public_") {
            service_tags_urls.push(u);
        } else if fallback_url.is_none() {
            fallback_url = Some(u);
        }
    }
    service_tags_urls.sort();
    service_tags_urls.pop().or(fallback_url)
}

fn simple_anchored_filename(pattern: &str) -> Option<String> {
    let inner = pattern.strip_prefix('^')?.strip_suffix('$')?;
    let unescaped = inner.replace("\\.", ".").replace("\\-", "-");
    if unescaped
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        Some(unescaped)
    } else {
        None
    }
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
