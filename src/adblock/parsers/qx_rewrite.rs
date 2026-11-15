use crate::adblock::model::{
    MapLocalDataType, MapLocalRule, ParsedAdblockSource, ScriptRule, ScriptType, UrlRewriteMode,
    UrlRewriteRule,
};
use crate::adblock::parsers::surge_module::sanitize_script_name;
use crate::adblock::regex_util::{
    extract_hosts_from_regex, is_valid_mitm_host, normalize_surge_regex,
};

/// Parses Quantumult X `[rewrite_local]` / `.conf` rules into official Surge Module IR.
pub fn parse_qx_rewrite(text: &str, weight: u16, out: &mut ParsedAdblockSource) {
    let mut script_idx = 0usize;

    for raw_line in text.lines() {
        let line = raw_line.trim_start_matches('\u{feff}').trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with("//")
            || line.starts_with('[')
        {
            continue;
        }

        if let Some(rest) = line.strip_prefix("hostname") {
            let rhs = rest.trim_start();
            if let Some(hosts) = rhs.strip_prefix('=') {
                for item in hosts.split(',').map(str::trim) {
                    if !item.is_empty() && !item.starts_with('-') && is_valid_mitm_host(item) {
                        out.mitm_hosts.insert(item.to_ascii_lowercase());
                    }
                }
                continue;
            }
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 3 || tokens[1] != "url" {
            continue;
        }

        let Some(pattern) = normalize_surge_regex(tokens[0]) else {
            continue;
        };
        let host_info = extract_hosts_from_regex(&pattern);

        match tokens[2] {
            "reject" => {
                out.register_host_info(host_info);
                out.url_rewrites.push(UrlRewriteRule {
                    pattern,
                    replacement: "_".to_string(),
                    mode: UrlRewriteMode::Reject,
                    weight,
                });
            }
            "reject-200" => {
                out.register_host_info(host_info);
                out.map_locals.push(MapLocalRule {
                    pattern,
                    data_type: MapLocalDataType::Text,
                    data: Some(String::new()),
                    status_code: Some(200),
                    header: None,
                    weight,
                });
            }
            "reject-dict" => {
                out.register_host_info(host_info);
                out.map_locals.push(MapLocalRule {
                    pattern,
                    data_type: MapLocalDataType::Text,
                    data: Some("{}".to_string()),
                    status_code: Some(200),
                    header: Some("Content-Type: application/json; charset=utf-8".to_string()),
                    weight,
                });
            }
            "reject-array" => {
                out.register_host_info(host_info);
                out.map_locals.push(MapLocalRule {
                    pattern,
                    data_type: MapLocalDataType::Text,
                    data: Some("[]".to_string()),
                    status_code: Some(200),
                    header: Some("Content-Type: application/json; charset=utf-8".to_string()),
                    weight,
                });
            }
            "reject-img" => {
                out.register_host_info(host_info);
                out.map_locals.push(MapLocalRule {
                    pattern,
                    data_type: MapLocalDataType::TinyGif,
                    data: None,
                    status_code: Some(200),
                    header: None,
                    weight,
                });
            }
            "302" | "307" => {
                if let Some(target) = tokens.get(3) {
                    out.register_host_info(host_info);
                    out.url_rewrites.push(UrlRewriteRule {
                        pattern,
                        replacement: (*target).to_string(),
                        mode: if tokens[2] == "302" {
                            UrlRewriteMode::Redirect302
                        } else {
                            UrlRewriteMode::Redirect307
                        },
                        weight,
                    });
                }
            }
            "script-response-body" | "script-request-body" | "script-request-header" => {
                let Some(script_url) = tokens.get(3) else {
                    continue;
                };
                if !script_url.starts_with("https://") {
                    continue;
                }
                // Only use QX scripts that don't rely on QX-only `$prefs` API; ddgksf/app2smile modern JS scripts include cross-client $env bridges
                let (script_type, requires_body) = match tokens[2] {
                    "script-response-body" => (ScriptType::HttpResponse, true),
                    "script-request-body" => (ScriptType::HttpRequest, true),
                    "script-request-header" => (ScriptType::HttpRequest, false),
                    _ => continue,
                };
                out.register_host_info(host_info);
                let base = script_url
                    .rsplit('/')
                    .next()
                    .unwrap_or("qx_script")
                    .trim_end_matches(".js");
                script_idx += 1;
                out.scripts.push(ScriptRule {
                    name: format!("qx_{}_{}", sanitize_script_name(base), script_idx),
                    script_type,
                    pattern,
                    script_path: (*script_url).to_string(),
                    requires_body,
                    binary_body_mode: false,
                    max_size: Some(-1),
                    timeout: None,
                    argument: None,
                    engine: None,
                    weight,
                });
            }
            _ => {}
        }
    }
}
