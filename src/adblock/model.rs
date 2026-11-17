use ipnet::{Ipv4Net, Ipv6Net};
use rustc_hash::FxHashSet;

use crate::adblock::config::AdblockCategory;
use crate::adblock::regex_util::canonical_url_pattern_key;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum HeaderDirection {
    HttpRequest,
    HttpResponse,
}

impl HeaderDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HttpRequest => "http-request",
            Self::HttpResponse => "http-response",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum HeaderAction {
    HeaderDel,
    HeaderAdd,
    HeaderReplace,
    HeaderReplaceRegex,
}

impl HeaderAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HeaderDel => "header-del",
            Self::HeaderAdd => "header-add",
            Self::HeaderReplace => "header-replace",
            Self::HeaderReplaceRegex => "header-replace-regex",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HeaderRewriteRule {
    pub direction: HeaderDirection,
    pub pattern: String,
    pub action: HeaderAction,
    pub field: String,
    pub value: Option<String>,
    pub replace_regex: Option<String>,
    pub weight: u16,
}

impl HeaderRewriteRule {
    pub fn dedup_key(&self) -> (HeaderDirection, String, HeaderAction, String) {
        (
            self.direction,
            canonical_url_pattern_key(&self.pattern),
            self.action,
            self.field.to_ascii_lowercase(),
        )
    }

    pub fn to_surge_line(&self) -> String {
        match self.action {
            HeaderAction::HeaderDel => {
                format!(
                    "{} {} header-del {}",
                    self.direction.as_str(),
                    self.pattern,
                    self.field
                )
            }
            HeaderAction::HeaderAdd | HeaderAction::HeaderReplace => {
                format!(
                    "{} {} {} {} {}",
                    self.direction.as_str(),
                    self.pattern,
                    self.action.as_str(),
                    self.field,
                    self.value.as_deref().unwrap_or("")
                )
            }
            HeaderAction::HeaderReplaceRegex => {
                format!(
                    "{} {} header-replace-regex {} {} {}",
                    self.direction.as_str(),
                    self.pattern,
                    self.field,
                    self.value.as_deref().unwrap_or(""),
                    self.replace_regex.as_deref().unwrap_or("")
                )
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum UrlRewriteMode {
    Header,
    Redirect302,
    Redirect307,
    Reject,
}

impl UrlRewriteMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::Redirect302 => "302",
            Self::Redirect307 => "307",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UrlRewriteRule {
    pub pattern: String,
    pub replacement: String,
    pub mode: UrlRewriteMode,
    pub weight: u16,
}

impl UrlRewriteRule {
    pub fn dedup_key(&self) -> (String, UrlRewriteMode) {
        (canonical_url_pattern_key(&self.pattern), self.mode)
    }

    pub fn to_surge_line(&self) -> String {
        if self.mode == UrlRewriteMode::Reject {
            format!("{} _ reject", self.pattern)
        } else {
            format!(
                "{} {} {}",
                self.pattern,
                self.replacement,
                self.mode.as_str()
            )
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum MapLocalDataType {
    Text,
    TinyGif,
    Base64,
    File,
}

impl MapLocalDataType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::TinyGif => "tiny-gif",
            Self::Base64 => "base64",
            Self::File => "file",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MapLocalRule {
    pub pattern: String,
    pub data_type: MapLocalDataType,
    pub data: Option<String>,
    pub status_code: Option<u16>,
    pub header: Option<String>,
    pub weight: u16,
}

impl MapLocalRule {
    pub fn dedup_key(&self) -> String {
        canonical_url_pattern_key(&self.pattern)
    }

    pub fn to_surge_line(&self) -> String {
        let mut parts = vec![
            self.pattern.clone(),
            format!("data-type={}", self.data_type.as_str()),
        ];
        if self.data_type != MapLocalDataType::TinyGif
            && let Some(ref data) = self.data
        {
            parts.push(format!("data=\"{}\"", escape_quoted_value(data)));
        }
        if let Some(code) = self.status_code {
            parts.push(format!("status-code={}", code));
        }
        if let Some(ref header) = self.header
            && !header.trim().is_empty()
        {
            parts.push(format!("header=\"{}\"", escape_quoted_value(header)));
        }
        parts.join(" ")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum BodyRewriteKind {
    HttpRequest,
    HttpResponse,
    HttpRequestJq,
    HttpResponseJq,
}

impl BodyRewriteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HttpRequest => "http-request",
            Self::HttpResponse => "http-response",
            Self::HttpRequestJq => "http-request-jq",
            Self::HttpResponseJq => "http-response-jq",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BodyRewriteRule {
    pub kind: BodyRewriteKind,
    pub pattern: String,
    pub expression: String,
    pub replacement: Option<String>,
    pub weight: u16,
}

impl BodyRewriteRule {
    pub fn dedup_key(&self) -> (BodyRewriteKind, String, String) {
        (
            self.kind,
            canonical_url_pattern_key(&self.pattern),
            self.expression.clone(),
        )
    }

    pub fn to_surge_line(&self) -> String {
        match self.kind {
            BodyRewriteKind::HttpRequestJq | BodyRewriteKind::HttpResponseJq => {
                let trimmed = self.expression.trim();
                let expr_tok = if trimmed.starts_with('\'') && trimmed.ends_with('\'') {
                    trimmed.to_string()
                } else {
                    format!("'{}'", trimmed)
                };
                format!("{} {} {}", self.kind.as_str(), self.pattern, expr_tok)
            }
            BodyRewriteKind::HttpRequest | BodyRewriteKind::HttpResponse => {
                format!(
                    "{} {} {} {}",
                    self.kind.as_str(),
                    self.pattern,
                    self.expression,
                    self.replacement.as_deref().unwrap_or("")
                )
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum ScriptType {
    HttpRequest,
    HttpResponse,
}

impl ScriptType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HttpRequest => "http-request",
            Self::HttpResponse => "http-response",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ScriptRule {
    pub name: String,
    pub script_type: ScriptType,
    pub pattern: String,
    pub script_path: String,
    pub requires_body: bool,
    pub binary_body_mode: bool,
    pub full_header_mode: bool,
    pub max_size: Option<i64>,
    pub timeout: Option<u32>,
    pub argument: Option<String>,
    pub engine: Option<String>,
    pub weight: u16,
}

pub const DEFAULT_TEXT_SCRIPT_MAX_SIZE: i64 = 524_288;
pub const MAX_BINARY_SCRIPT_MAX_SIZE: i64 = 1_048_576;
pub const MIN_EXPLICIT_SCRIPT_MAX_SIZE: i64 = 16_384;
pub const DEFAULT_SCRIPT_TIMEOUT_SECS: u32 = 5;
pub const MIN_SCRIPT_TIMEOUT_SECS: u32 = 3;
pub const MAX_SCRIPT_TIMEOUT_SECS: u32 = 10;

pub fn normalize_script_limits(
    requires_body: bool,
    binary_body_mode: bool,
    raw_max_size: Option<i64>,
    raw_timeout: Option<u32>,
) -> (Option<i64>, Option<u32>) {
    let max_size = if !requires_body {
        None
    } else if binary_body_mode {
        Some(match raw_max_size {
            Some(sz)
                if (MIN_EXPLICIT_SCRIPT_MAX_SIZE..=MAX_BINARY_SCRIPT_MAX_SIZE).contains(&sz) =>
            {
                sz
            }
            _ => MAX_BINARY_SCRIPT_MAX_SIZE,
        })
    } else {
        Some(match raw_max_size {
            Some(sz)
                if (MIN_EXPLICIT_SCRIPT_MAX_SIZE..=DEFAULT_TEXT_SCRIPT_MAX_SIZE).contains(&sz) =>
            {
                sz
            }
            _ => DEFAULT_TEXT_SCRIPT_MAX_SIZE,
        })
    };
    let timeout = Some(
        raw_timeout
            .unwrap_or(DEFAULT_SCRIPT_TIMEOUT_SECS)
            .clamp(MIN_SCRIPT_TIMEOUT_SECS, MAX_SCRIPT_TIMEOUT_SECS),
    );
    (max_size, timeout)
}

impl ScriptRule {
    pub fn trigger_key(&self) -> (ScriptType, String) {
        (self.script_type, canonical_url_pattern_key(&self.pattern))
    }

    /// Enforces iOS PacketTunnelProvider memory & concurrency invariants:
    /// - `engine=jsc` (prevents WKWebView ~40 MB memory spikes on iOS NE)
    /// - Bounded `max-size` (`<= 512 KiB` for JSON/text, `<= 1 MiB` for binary protobuf; never `-1` or `0`)
    /// - Bounded `timeout` (`3..=10` seconds)
    pub fn normalize_runtime_bounds(&mut self) {
        let (max_size, timeout) = normalize_script_limits(
            self.requires_body,
            self.binary_body_mode,
            self.max_size,
            self.timeout,
        );
        self.max_size = max_size;
        self.timeout = timeout;
        self.engine = Some("jsc".to_string());
    }

    pub fn to_surge_line(&self, unique_name: &str) -> String {
        let pattern_param = if self.pattern.contains(',')
            || self.pattern.contains('"')
            || self.pattern.chars().any(char::is_whitespace)
        {
            format!("pattern=\"{}\"", escape_quoted_value(&self.pattern))
        } else {
            format!("pattern={}", self.pattern)
        };
        let mut params = vec![
            format!("type={}", self.script_type.as_str()),
            pattern_param,
            format!("script-path={}", self.script_path),
        ];
        if self.requires_body {
            params.push("requires-body=true".to_string());
        }
        if self.binary_body_mode {
            params.push("binary-body-mode=true".to_string());
        }
        if self.full_header_mode {
            params.push("full-header-mode=true".to_string());
        }
        if let Some(sz) = self.max_size {
            params.push(format!("max-size={}", sz));
        }
        if let Some(t) = self.timeout {
            params.push(format!("timeout={}", t));
        }
        if let Some(ref eng) = self.engine
            && matches!(eng.as_str(), "auto" | "jsc" | "webview")
        {
            params.push(format!("engine={}", eng));
        }
        if let Some(ref arg) = self.argument
            && !arg.is_empty()
        {
            params.push(format!("argument=\"{}\"", escape_quoted_value(arg)));
        }
        format!("{} = {}", unique_name, params.join(","))
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RemoveParamRule {
    pub host_scope: String,
    pub param: String,
    pub weight: u16,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, serde::Serialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum AdguardTransformOp {
    Replace {
        pat: String,
        rep: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        flags: String,
    },
    Hls {
        pat: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        flags: String,
    },
    XmlPrune {
        expr: String,
    },
    JsonPrune {
        expr: String,
    },
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AdguardTransformRule {
    pub pattern: String,
    pub op: AdguardTransformOp,
    pub weight: u16,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ModuleGeneralHostItem {
    pub key: String,
    pub host: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ModuleRuleLine {
    pub line: String,
    pub weight: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum HeaderModKind {
    Cookie,
    Csp,
    Permissions,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct HeaderModRule {
    pub kind: HeaderModKind,
    pub host_scope: String,
    pub spec: String,
    pub weight: u16,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct HeaderModException {
    pub kind: HeaderModKind,
    pub scope_key: String,
    pub spec: String,
}

#[derive(Default, Clone, Debug)]
pub struct ParsedAdblockSource {
    pub category: AdblockCategory,
    pub lineage: String,
    pub weight: u16,
    pub filter_direct_collisions: bool,
    pub allow_exact_domains: FxHashSet<String>,
    pub allow_suffix_domains: FxHashSet<String>,
    pub complex_protected_hosts: FxHashSet<String>,
    pub mitm_hosts: FxHashSet<String>,
    pub module_general_hosts: Vec<ModuleGeneralHostItem>,
    pub module_rules: Vec<ModuleRuleLine>,
    pub header_rewrites: Vec<HeaderRewriteRule>,
    pub url_rewrites: Vec<UrlRewriteRule>,
    pub map_locals: Vec<MapLocalRule>,
    pub body_rewrites: Vec<BodyRewriteRule>,
    pub adguard_transforms: Vec<AdguardTransformRule>,
    pub fallback_header_rewrites: Vec<HeaderRewriteRule>,
    pub fallback_map_locals: Vec<MapLocalRule>,
    pub fallback_body_rewrites: Vec<BodyRewriteRule>,
    pub fallback_adguard_transforms: Vec<AdguardTransformRule>,
    pub scripts: Vec<ScriptRule>,
    pub remove_params: Vec<RemoveParamRule>,
    pub removeparam_exceptions: Vec<(String, String)>,
    pub header_mods: Vec<HeaderModRule>,
    pub header_mod_exceptions: Vec<HeaderModException>,
    pub removeheader_exceptions: Vec<(HeaderDirection, String, String)>,
    pub ruleset_domains: FxHashSet<String>,
    pub ruleset_suffixes: FxHashSet<String>,
    pub ruleset_keywords: FxHashSet<String>,
    pub ruleset_wildcards: FxHashSet<String>,
    pub ruleset_cidrs_v4: FxHashSet<Ipv4Net>,
    pub ruleset_cidrs_v6: FxHashSet<Ipv6Net>,
    pub ruleset_asns: FxHashSet<u32>,
    pub ruleset_user_agents: FxHashSet<String>,
    pub ruleset_process_names: FxHashSet<String>,
}

impl ParsedAdblockSource {
    pub fn register_host_info(&mut self, info: crate::adblock::regex_util::RegexHostInfo) {
        for h in info.positive_mitm_hosts {
            self.mitm_hosts.insert(h);
        }
        for ch in info.concrete_hosts {
            self.complex_protected_hosts.insert(ch);
        }
    }
}

fn escape_quoted_value(raw: &str) -> String {
    raw.replace('\\', "\\\\").replace('"', "\\\"")
}
