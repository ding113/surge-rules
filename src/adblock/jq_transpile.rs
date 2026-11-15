/// Converts an AdGuard/uBO `$jsonprune` argument string into a Surge native `http-response-jq` expression.
/// Supports common path forms like `\.ads`, `\$.data.ad_info`, `\$.items.[].ad`, and whitespace-separated multi-paths.
pub fn transpile_jsonprune_to_jq(raw: &str) -> Option<String> {
    let normalized = raw.replace("\\$", "$").replace("\\,", ",");
    let trimmed = normalized.trim();
    if trimmed.is_empty()
        || trimmed.contains('\'')
        || trimmed.contains('\n')
        || trimmed.contains('\r')
    {
        return None;
    }

    let mut jq_paths = Vec::new();
    for token in trimmed.split_whitespace() {
        let jq_path = convert_single_path(token)?;
        jq_paths.push(jq_path);
    }

    if jq_paths.is_empty() {
        return None;
    }

    Some(format!("del({})", jq_paths.join(", ")))
}

fn convert_single_path(raw: &str) -> Option<String> {
    let mut s = raw.trim();
    // Skip negation prefixes (`-`) or conditional object matchers we cannot statically turn into del()
    if s.is_empty()
        || s.starts_with('-')
        || s.contains("=~")
        || s.contains("==")
        || s.contains("!=")
        || s.contains("..[")
    {
        return None;
    }

    if let Some(rest) = s.strip_prefix("$.") {
        s = rest;
    } else if let Some(rest) = s.strip_prefix('$') {
        s = rest;
    } else if let Some(rest) = s.strip_prefix("\\.") {
        s = rest;
    } else if let Some(rest) = s.strip_prefix('.') {
        s = rest;
    }

    if s.is_empty() {
        return None;
    }

    let mut expr = String::new();
    let segments: Vec<&str> = s.split('.').collect();
    for seg in segments {
        if seg.is_empty() || seg == "$" {
            continue;
        }
        if seg == "[]" || seg == "[*]" {
            expr.push_str("[]?");
            continue;
        }
        if let Some(stripped) = seg.strip_suffix("[]") {
            push_field_segment(&mut expr, stripped)?;
            expr.push_str("[]?");
            continue;
        }
        if let Some(stripped) = seg.strip_suffix("[*]") {
            push_field_segment(&mut expr, stripped)?;
            expr.push_str("[]?");
            continue;
        }
        if seg.starts_with('[') && seg.ends_with(']') {
            let inner = seg[1..seg.len() - 1].trim();
            if inner.chars().all(|c| c.is_ascii_digit()) {
                expr.push('[');
                expr.push_str(inner);
                expr.push_str("]?");
                continue;
            }
            return None;
        }
        push_field_segment(&mut expr, seg)?;
    }

    if expr.is_empty() { None } else { Some(expr) }
}

fn push_field_segment(out: &mut String, field: &str) -> Option<()> {
    let clean = field.trim();
    if clean.is_empty() {
        return None;
    }
    if clean.contains('*')
        || clean.contains('(')
        || clean.contains(')')
        || clean.contains('\'')
        || clean.contains('"')
    {
        return None;
    }
    if clean.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !clean.starts_with(|c: char| c.is_ascii_digit())
    {
        out.push('.');
        out.push_str(clean);
        out.push('?');
    } else if clean
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ':' | '$'))
    {
        out.push_str(".[\"");
        out.push_str(clean);
        out.push_str("\"]?");
    } else {
        return None;
    }
    Some(())
}
