use std::collections::HashMap;

use crate::adblock::model::{
    BodyRewriteKind, BodyRewriteRule, HeaderAction, HeaderDirection, HeaderRewriteRule,
    MapLocalDataType, MapLocalRule, ModuleGeneralHostItem, ModuleRuleLine, ParsedAdblockSource,
    ScriptRule, ScriptType, UrlRewriteMode, UrlRewriteRule,
};
use crate::adblock::parsers::ruleset::{insert_ruleset_entry, parse_canonical_cidr};
use crate::adblock::regex_util::{
    extract_hosts_from_regex, is_valid_domain, is_valid_mitm_host, normalize_surge_regex,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum ModuleSection {
    None,
    General,
    Rule,
    UrlRewrite,
    HeaderRewrite,
    BodyRewrite,
    MapLocal,
    Script,
    Mitm,
    Other,
}

/// Parses an upstream `.sgmodule` or `.module` file into Surge IR.
/// Expands `#!arguments=` default values, translates legacy/Loon/QX rewrite shorthands into
/// official Surge `[Map Local]` / `[URL Rewrite]` forms, and extracts protected MITM hostnames.
pub fn parse_surge_module(raw_text: &str, weight: u16, out: &mut ParsedAdblockSource) {
    let arg_defaults = extract_argument_defaults(raw_text);
    let mut section = ModuleSection::None;

    for raw_line in raw_text.lines() {
        let mut line = raw_line.trim_start_matches('\u{feff}').trim().to_string();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with("//")
        {
            continue;
        }
        if !arg_defaults.is_empty() && line.contains("{{{") {
            line = apply_argument_defaults(&line, &arg_defaults);
        }
        // Skip any line that still has unresolved module arguments
        if line.contains("{{{") && line.contains("}}}") {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            section = match line.as_str() {
                "[General]" => ModuleSection::General,
                "[Rule]" => ModuleSection::Rule,
                "[URL Rewrite]" => ModuleSection::UrlRewrite,
                "[Header Rewrite]" => ModuleSection::HeaderRewrite,
                "[Body Rewrite]" => ModuleSection::BodyRewrite,
                "[Map Local]" => ModuleSection::MapLocal,
                "[Script]" => ModuleSection::Script,
                "[MITM]" => ModuleSection::Mitm,
                _ => ModuleSection::Other,
            };
            continue;
        }

        match section {
            ModuleSection::General => parse_general_line(&line, out),
            ModuleSection::Rule => parse_module_rule_line(&line, weight, out),
            ModuleSection::UrlRewrite => parse_url_rewrite_line(&line, weight, out),
            ModuleSection::HeaderRewrite => parse_header_rewrite_line(&line, weight, out),
            ModuleSection::BodyRewrite => parse_body_rewrite_line(&line, weight, out),
            ModuleSection::MapLocal => parse_map_local_line(&line, weight, out),
            ModuleSection::Script => parse_script_line(&line, weight, out),
            ModuleSection::Mitm => parse_mitm_line(&line, out),
            ModuleSection::None | ModuleSection::Other => {}
        }
    }
}

fn extract_argument_defaults(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("#!arguments=") {
            for pair in rest.split(',') {
                if let Some(idx) = pair.find(':') {
                    let k = pair[..idx].trim();
                    let v = pair[idx + 1..].trim();
                    if !k.is_empty() {
                        map.insert(k.to_string(), v.to_string());
                    }
                }
            }
        }
    }
    map
}

fn apply_argument_defaults(line: &str, defaults: &HashMap<String, String>) -> String {
    let mut out = line.to_string();
    for (k, v) in defaults {
        let placeholder = format!("{{{{{{{}}}}}}}", k);
        if out.contains(&placeholder) {
            out = out.replace(&placeholder, v);
        }
    }
    out
}

fn parse_general_line(line: &str, out: &mut ParsedAdblockSource) {
    let Some((k, v)) = split_kv(line) else {
        return;
    };
    let key_lower = k.to_ascii_lowercase();
    if !matches!(
        key_lower.as_str(),
        "force-http-engine-hosts" | "always-real-ip"
    ) {
        return;
    }
    let val = v
        .strip_prefix("%APPEND%")
        .or_else(|| v.strip_prefix("%INSERT%"))
        .unwrap_or(v)
        .trim();
    for item in val.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(bare) = item.strip_prefix('-') {
            if is_valid_mitm_host(bare) {
                out.module_general_hosts.push(ModuleGeneralHostItem {
                    key: key_lower.clone(),
                    host: item.to_string(),
                });
            }
        } else if is_valid_mitm_host(item) {
            out.module_general_hosts.push(ModuleGeneralHostItem {
                key: key_lower.clone(),
                host: item.to_string(),
            });
        }
    }
}

fn parse_module_rule_line(line: &str, weight: u16, out: &mut ParsedAdblockSource) {
    let parts: Vec<&str> = line.split(',').map(str::trim).collect();
    if parts.len() < 3 {
        return;
    }
    let rtype = parts[0].to_ascii_uppercase();
    let val = parts[1].trim_matches('"');

    // Logical / composite rules (`AND,((PROTOCOL,UDP),(...)),REJECT`)
    if matches!(rtype.as_str(), "AND" | "OR" | "NOT") {
        let last_policy = find_builtin_policy(&parts);
        if last_policy.is_some() {
            out.module_rules.push(ModuleRuleLine {
                line: line.to_string(),
                weight,
            });
        }
        return;
    }

    let policy = parts[2].to_ascii_uppercase();
    if !matches!(
        policy.as_str(),
        "DIRECT" | "REJECT" | "REJECT-DROP" | "REJECT-NO-DROP" | "REJECT-TINYGIF"
    ) {
        return;
    }

    if policy == "DIRECT" {
        match rtype.as_str() {
            "DOMAIN" => {
                let dom = val.trim_end_matches('.').to_ascii_lowercase();
                if is_valid_domain(&dom) {
                    out.allow_exact_domains.insert(dom);
                    out.module_rules.push(ModuleRuleLine {
                        line: format!("DOMAIN,{},DIRECT", val.trim()),
                        weight,
                    });
                }
            }
            "DOMAIN-SUFFIX" => {
                let dom = val
                    .trim_start_matches('.')
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                if is_valid_domain(&dom) {
                    out.allow_suffix_domains.insert(dom);
                    out.module_rules.push(ModuleRuleLine {
                        line: format!("DOMAIN-SUFFIX,{},DIRECT", val.trim()),
                        weight,
                    });
                }
            }
            _ => {}
        }
        return;
    }

    let flags: Vec<&str> = parts[3..]
        .iter()
        .map(|f| f.trim())
        .filter(|f| !f.is_empty())
        .collect();
    let has_pre_match = flags.iter().any(|f| f.eq_ignore_ascii_case("pre-matching"));

    if rtype == "URL-REGEX" {
        if let Some(regex) = normalize_surge_regex(val) {
            let host_info = extract_hosts_from_regex(&regex);
            for h in host_info.mitm_patterns {
                out.mitm_hosts.insert(h);
            }
            for ch in host_info.concrete_hosts {
                out.complex_protected_hosts.insert(ch);
            }
            out.url_rewrites.push(UrlRewriteRule {
                pattern: regex,
                replacement: "_".to_string(),
                mode: UrlRewriteMode::Reject,
                weight,
            });
        }
        return;
    }

    if has_pre_match {
        match rtype.as_str() {
            "DOMAIN" | "DOMAIN-SUFFIX" => {
                let clean = val
                    .trim_start_matches('.')
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                if is_valid_domain(&clean) {
                    let rule = format!("{},{},{},pre-matching", rtype, clean, policy);
                    out.module_rules.push(ModuleRuleLine { line: rule, weight });
                }
            }
            "IP-CIDR" | "IP-CIDR6" => {
                if let Some(net) = parse_canonical_cidr(val) {
                    let rule = format!("{},{},{},no-resolve,pre-matching", rtype, net, policy);
                    out.module_rules.push(ModuleRuleLine { line: rule, weight });
                }
            }
            _ => {}
        }
        return;
    }

    // Standard REJECT domain/IP rules without pre-matching route cleanly into Adblock.list
    insert_ruleset_entry(&rtype, val, out);
}

fn find_builtin_policy(parts: &[&str]) -> Option<&'static str> {
    for p in parts.iter().rev() {
        let up = p.trim().to_ascii_uppercase();
        if let Some(matched) = match up.as_str() {
            "DIRECT" => Some("DIRECT"),
            "REJECT" => Some("REJECT"),
            "REJECT-DROP" => Some("REJECT-DROP"),
            "REJECT-NO-DROP" => Some("REJECT-NO-DROP"),
            "REJECT-TINYGIF" => Some("REJECT-TINYGIF"),
            _ => None,
        } {
            return Some(matched);
        }
    }
    None
}

fn parse_url_rewrite_line(line: &str, weight: u16, out: &mut ParsedAdblockSource) {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 2 {
        return;
    }
    let Some(pattern) = normalize_surge_regex(tokens[0]) else {
        return;
    };
    let host_info = extract_hosts_from_regex(&pattern);

    // Handle 2-token legacy/header form (`^http://a ^https://a` -> header) or 3-token form
    let repl = tokens[1];
    let action = tokens.get(2).copied().unwrap_or("header");

    match action.to_ascii_lowercase().as_str() {
        "reject" => {
            out.register_host_info(host_info);
            out.url_rewrites.push(UrlRewriteRule {
                pattern,
                replacement: "_".to_string(),
                mode: UrlRewriteMode::Reject,
                weight,
            });
        }
        // Loon / Walvez shorthand `- reject-200`, `- reject-dict`, `- reject-array`, `- reject-img`
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
        "reject-img" | "reject-tinygif" => {
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
        "header" | "302" | "307" => {
            if repl == "-" || repl == "_" {
                return;
            }
            let mode = match action.to_ascii_lowercase().as_str() {
                "302" => UrlRewriteMode::Redirect302,
                "307" => UrlRewriteMode::Redirect307,
                _ => UrlRewriteMode::Header,
            };
            out.register_host_info(host_info);
            out.url_rewrites.push(UrlRewriteRule {
                pattern,
                replacement: repl.to_string(),
                mode,
                weight,
            });
        }
        _ => {}
    }
}

fn parse_header_rewrite_line(line: &str, weight: u16, out: &mut ParsedAdblockSource) {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 3 {
        return;
    }
    let (dir, offset) = match tokens[0] {
        "http-request" => (HeaderDirection::HttpRequest, 1usize),
        "http-response" => (HeaderDirection::HttpResponse, 1usize),
        _ => (HeaderDirection::HttpRequest, 0usize),
    };
    let Some(raw_pat) = tokens.get(offset) else {
        return;
    };
    let Some(pattern) = normalize_surge_regex(raw_pat) else {
        return;
    };
    let Some(action_str) = tokens.get(offset + 1) else {
        return;
    };
    let Some(field) = tokens.get(offset + 2) else {
        return;
    };
    if field.eq_ignore_ascii_case("content-length")
        || field.eq_ignore_ascii_case("transfer-encoding")
    {
        return;
    }

    let action = match *action_str {
        "header-del" => HeaderAction::HeaderDel,
        "header-add" => HeaderAction::HeaderAdd,
        "header-replace" => HeaderAction::HeaderReplace,
        "header-replace-regex" => HeaderAction::HeaderReplaceRegex,
        _ => return,
    };

    let host_info = extract_hosts_from_regex(&pattern);
    out.register_host_info(host_info);

    out.header_rewrites.push(HeaderRewriteRule {
        direction: dir,
        pattern,
        action,
        field: (*field).to_string(),
        value: tokens.get(offset + 3).map(|s| (*s).to_string()),
        replace_regex: tokens.get(offset + 4).map(|s| (*s).to_string()),
        weight,
    });
}

fn parse_body_rewrite_line(line: &str, weight: u16, out: &mut ParsedAdblockSource) {
    let tokens = split_space_preserving_quotes(line);
    if tokens.len() < 3 {
        return;
    }
    let kind = match tokens[0].as_str() {
        "http-request" => BodyRewriteKind::HttpRequest,
        "http-response" => BodyRewriteKind::HttpResponse,
        "http-request-jq" => BodyRewriteKind::HttpRequestJq,
        "http-response-jq" => BodyRewriteKind::HttpResponseJq,
        _ => return,
    };
    let Some(pattern) = normalize_surge_regex(&tokens[1]) else {
        return;
    };

    match kind {
        BodyRewriteKind::HttpRequestJq | BodyRewriteKind::HttpResponseJq => {
            if tokens.len() != 3 {
                return;
            }
            let expr = tokens[2].trim_matches('\'').trim();
            if expr.is_empty() || expr.contains('\'') {
                return;
            }
            out.register_host_info(extract_hosts_from_regex(&pattern));
            out.body_rewrites.push(BodyRewriteRule {
                kind,
                pattern,
                expression: expr.to_string(),
                replacement: None,
                weight,
            });
        }
        BodyRewriteKind::HttpRequest | BodyRewriteKind::HttpResponse => {
            if tokens.len() != 4 {
                return;
            }
            let expr = tokens[2].trim();
            let repl = tokens[3].trim();
            if expr.is_empty() || repl.contains(' ') {
                return;
            }
            out.register_host_info(extract_hosts_from_regex(&pattern));
            out.body_rewrites.push(BodyRewriteRule {
                kind,
                pattern,
                expression: expr.to_string(),
                replacement: Some(repl.to_string()),
                weight,
            });
        }
    }
}

fn parse_map_local_line(line: &str, weight: u16, out: &mut ParsedAdblockSource) {
    let tokens = split_space_preserving_quotes(line);
    if tokens.len() < 2 {
        return;
    }
    let Some(pattern) = normalize_surge_regex(&tokens[0]) else {
        return;
    };

    let mut data_type: Option<MapLocalDataType> = None;
    let mut data: Option<String> = None;
    let mut status_code: Option<u16> = None;
    let mut header: Option<String> = None;

    for tok in &tokens[1..] {
        if let Some((k, raw_v)) = split_kv(tok) {
            let v = unquote_surge_value(raw_v);
            match k {
                "data-type" => {
                    data_type = match v.as_str() {
                        "text" => Some(MapLocalDataType::Text),
                        "tiny-gif" => Some(MapLocalDataType::TinyGif),
                        "base64" => Some(MapLocalDataType::Base64),
                        "file" => Some(MapLocalDataType::File),
                        _ => None,
                    };
                }
                "data" => data = Some(v),
                "status-code" => {
                    if let Ok(code) = v.parse::<u16>()
                        && (200..=999).contains(&code)
                    {
                        status_code = Some(code);
                    }
                }
                "header" => header = Some(v),
                _ => {}
            }
        }
    }

    let dt = data_type.unwrap_or(MapLocalDataType::File);
    // Reject local relative `file` paths that do not resolve cleanly across devices
    if dt == MapLocalDataType::File
        && !data
            .as_deref()
            .is_some_and(|d| d.starts_with("https://") || d.starts_with("http://"))
    {
        return;
    }

    out.register_host_info(extract_hosts_from_regex(&pattern));
    out.map_locals.push(MapLocalRule {
        pattern,
        data_type: dt,
        data,
        status_code,
        header,
        weight,
    });
}

fn parse_script_line(line: &str, weight: u16, out: &mut ParsedAdblockSource) {
    let Some((raw_name, rhs)) = line.split_once('=') else {
        return;
    };
    let name = raw_name.trim();
    if name.is_empty() || name.contains(char::is_whitespace) {
        return;
    }

    let mut script_type: Option<ScriptType> = None;
    let mut pattern: Option<String> = None;
    let mut script_path: Option<String> = None;
    let mut requires_body = false;
    let mut binary_body_mode = false;
    let mut max_size: Option<i64> = None;
    let mut timeout: Option<u32> = None;
    let mut argument: Option<String> = None;
    let mut engine: Option<String> = None;

    for param in split_top_level_commas(rhs) {
        let Some((k, raw_v)) = split_kv(&param) else {
            continue;
        };
        let v = unquote_surge_value(raw_v);
        match k {
            "type" => {
                script_type = match v.as_str() {
                    "http-request" => Some(ScriptType::HttpRequest),
                    "http-response" => Some(ScriptType::HttpResponse),
                    _ => return,
                };
            }
            "pattern" => pattern = normalize_surge_regex(&v),
            "script-path" => {
                if v.starts_with("https://") {
                    script_path = Some(v);
                }
            }
            "requires-body" => requires_body = matches!(v.as_str(), "true" | "1"),
            "binary-body-mode" => binary_body_mode = matches!(v.as_str(), "true" | "1"),
            "max-size" => max_size = v.parse::<i64>().ok(),
            "timeout" => timeout = v.parse::<u32>().ok().filter(|t| *t >= 1 && *t <= 120),
            "argument" => argument = Some(v),
            "engine" => engine = Some(v),
            _ => {}
        }
    }

    let (Some(st), Some(pat), Some(path)) = (script_type, pattern, script_path) else {
        return;
    };

    out.register_host_info(extract_hosts_from_regex(&pat));
    out.scripts.push(ScriptRule {
        name: sanitize_script_name(name),
        script_type: st,
        pattern: pat,
        script_path: path,
        requires_body,
        binary_body_mode,
        max_size,
        timeout,
        argument,
        engine,
        weight,
    });
}

fn parse_mitm_line(line: &str, out: &mut ParsedAdblockSource) {
    let Some((k, v)) = split_kv(line) else {
        return;
    };
    if !k.eq_ignore_ascii_case("hostname") {
        return;
    }
    let body = v
        .strip_prefix("%APPEND%")
        .or_else(|| v.strip_prefix("%INSERT%"))
        .unwrap_or(v);
    for item in body.split(',').map(str::trim) {
        if item.is_empty() || item.starts_with('-') {
            continue;
        }
        if is_valid_mitm_host(item) {
            out.mitm_hosts.insert(item.to_ascii_lowercase());
        }
    }
}

pub fn sanitize_script_name(raw: &str) -> String {
    let clean: String = raw
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '_' | '-' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if clean.is_empty() {
        "adblock_script".to_string()
    } else {
        clean
    }
}

fn split_kv(s: &str) -> Option<(&str, &str)> {
    let idx = s.find('=')?;
    Some((s[..idx].trim(), s[idx + 1..].trim()))
}

pub fn unquote_surge_value(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        let inner = &t[1..t.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                match chars.next() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some(other) => {
                        out.push('\\');
                        out.push(other);
                    }
                    None => out.push('\\'),
                }
            } else {
                out.push(ch);
            }
        }
        out
    } else {
        t.to_string()
    }
}

/// Split a Surge `[Script]` RHS parameter string on commas strictly outside double quotes.
pub fn split_surge_script_params(input: &str) -> anyhow::Result<Vec<String>> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;

    for ch in input.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if in_quotes {
            match ch {
                '\\' => {
                    current.push(ch);
                    escaped = true;
                }
                '"' => {
                    current.push(ch);
                    in_quotes = false;
                }
                _ => current.push(ch),
            }
        } else {
            match ch {
                '"' => {
                    current.push(ch);
                    in_quotes = true;
                }
                ',' => {
                    let trimmed = current.trim();
                    if trimmed.is_empty() {
                        return Err(anyhow::anyhow!(
                            "empty parameter segment in Surge [Script] line"
                        ));
                    }
                    parts.push(trimmed.to_string());
                    current.clear();
                }
                _ => current.push(ch),
            }
        }
    }

    if in_quotes || escaped {
        return Err(anyhow::anyhow!(
            "unterminated quoted parameter in Surge [Script] line"
        ));
    }

    let trimmed = current.trim();
    if trimmed.is_empty() {
        return Err(anyhow::anyhow!(
            "empty trailing parameter segment in Surge [Script] line"
        ));
    }
    parts.push(trimmed.to_string());
    Ok(parts)
}

/// Splits key=value pairs in a Surge `[Script]` line on top-level commas,
/// respecting double quotes as well as `()`, `{}`, and `[]` delimiters inside regexes/JSON arguments.
pub fn split_top_level_commas(input: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut in_quotes = false;
    let mut paren = 0i32;
    let mut brace = 0i32;
    let mut bracket = 0i32;
    let mut escaped = false;

    for (idx, ch) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' && paren == 0 && brace == 0 && bracket == 0 {
            in_quotes = !in_quotes;
            continue;
        }
        if !in_quotes {
            match ch {
                '(' => paren += 1,
                ')' => paren = (paren - 1).max(0),
                '{' => brace += 1,
                '}' => brace = (brace - 1).max(0),
                '[' => bracket += 1,
                ']' => bracket = (bracket - 1).max(0),
                ',' if paren == 0 && brace == 0 && bracket == 0 => {
                    parts.push(input[start..idx].trim().to_string());
                    start = idx + 1;
                }
                _ => {}
            }
        }
    }
    let tail = input[start..].trim();
    if !tail.is_empty() {
        parts.push(tail.to_string());
    }
    parts
}

fn split_space_preserving_quotes(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for ch in input.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && quote == Some('"') {
            cur.push(ch);
            escaped = true;
            continue;
        }
        if let Some(q) = quote {
            cur.push(ch);
            if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => {
                quote = Some(ch);
                cur.push(ch);
            }
            c if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(ch),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}
