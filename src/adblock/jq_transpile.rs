/// Converts an AdGuard/uBO `$jsonprune` argument string into a Surge native `http-response-jq` expression.
/// Supports static non-recursive path forms including bracketed keys (`["a/b"]`, `['a/b']`),
/// array/object wildcards (`[]`, `[*]`, `.*`), numeric indices (`[0]`), and whitespace-separated multi-paths.
/// Complex recursive (`..`) or predicate (`[?(...)]`) JSONPrune expressions return `None` so the compiler
/// routes them to the `surge-adguard.js` runtime evaluator.
pub fn transpile_jsonprune_to_jq(raw: &str) -> Option<String> {
    let normalized = raw.replace("\\$", "$").replace("\\,", ",");
    let trimmed = normalized.trim();
    if trimmed.is_empty() || trimmed.contains('\n') || trimmed.contains('\r') {
        return None;
    }

    // Do not split on whitespace inside quoted bracket keys (`["foo bar"]`) or predicates (`[?(has ...)]`)
    if trimmed.contains("[?") || trimmed.contains("..") {
        return None;
    }

    let tokens = split_whitespace_outside_brackets(trimmed)?;
    let mut jq_paths = Vec::new();
    for token in tokens {
        let jq_path = convert_single_path(&token)?;
        if jq_path.contains('\'') {
            return None;
        }
        jq_paths.push(jq_path);
    }

    if jq_paths.is_empty() {
        return None;
    }

    Some(format!("del({})", jq_paths.join(", ")))
}

fn split_whitespace_outside_brackets(s: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut bracket = 0i32;
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for ch in s.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        if let Some(q) = quote {
            if ch == '\\' {
                cur.push(ch);
                escaped = true;
                continue;
            }
            cur.push(ch);
            if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' if bracket > 0 => {
                quote = Some(ch);
                cur.push(ch);
            }
            '[' => {
                bracket += 1;
                cur.push(ch);
            }
            ']' => {
                bracket -= 1;
                if bracket < 0 {
                    return None;
                }
                cur.push(ch);
            }
            c if c.is_whitespace() && bracket == 0 => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(ch),
        }
    }

    if bracket != 0 || quote.is_some() || escaped {
        return None;
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    Some(out)
}

fn convert_single_path(raw: &str) -> Option<String> {
    let mut s = raw.trim();
    if s.is_empty()
        || s.starts_with('-')
        || s.contains("=~")
        || s.contains("==")
        || s.contains("!=")
        || s.contains("..")
        || s.contains("[?")
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
    let bytes = s.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'.' {
            i += 1;
            if i >= bytes.len() {
                return None;
            }
        }

        if bytes[i] == b'*'
            && (i + 1 == bytes.len() || bytes[i + 1] == b'.' || bytes[i + 1] == b'[')
        {
            if expr.is_empty() {
                expr.push('.');
            }
            expr.push_str("[]?");
            i += 1;
            continue;
        }

        if bytes[i] == b'[' {
            let (inner, next_idx) = read_bracket_segment(s, i)?;
            i = next_idx;
            let trimmed_inner = inner.trim();
            if trimmed_inner.is_empty() || trimmed_inner == "*" {
                if expr.is_empty() {
                    expr.push('.');
                }
                expr.push_str("[]?");
            } else if trimmed_inner.chars().all(|c| c.is_ascii_digit()) {
                if expr.is_empty() {
                    expr.push('.');
                }
                expr.push('[');
                expr.push_str(trimmed_inner);
                expr.push_str("]?");
            } else {
                // Multi-key `[a, b]` or predicate returns `None` -> delegate to runtime script
                let str_key = unquote_bracket_string(trimmed_inner)?;
                push_quoted_jq_key(&mut expr, &str_key)?;
            }
            continue;
        }

        let start = i;
        while i < bytes.len() && bytes[i] != b'.' && bytes[i] != b'[' {
            i += 1;
        }
        let field = &s[start..i];
        if field == "$" {
            continue;
        }
        push_field_segment(&mut expr, field)?;
    }

    if expr.is_empty() { None } else { Some(expr) }
}

fn read_bracket_segment(s: &str, open_idx: usize) -> Option<(&str, usize)> {
    let rest = &s[open_idx + 1..];
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (offset, ch) in rest.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if let Some(q) = quote {
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '[' => return None,
            ']' => return Some((&rest[..offset], open_idx + 1 + offset + 1)),
            _ => {}
        }
    }
    None
}

fn unquote_bracket_string(inner: &str) -> Option<String> {
    if inner.len() < 2 {
        return None;
    }
    let first = inner.chars().next()?;
    let last = inner.chars().last()?;
    if !((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
        return None;
    }
    let body = &inner[1..inner.len() - 1];
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let next = chars.next()?;
            out.push(next);
        } else if c == first {
            return None;
        } else {
            out.push(c);
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

fn push_quoted_jq_key(out: &mut String, key: &str) -> Option<()> {
    if key.is_empty()
        || key.contains('\'')
        || key.chars().any(|c| c.is_control())
        || !key.is_ascii()
    {
        return None;
    }
    let escaped = key.replace('\\', "\\\\").replace('"', "\\\"");
    if out.is_empty() {
        out.push('.');
    }
    out.push_str("[\"");
    out.push_str(&escaped);
    out.push_str("\"]?");
    Some(())
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
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ':' | '$' | '/'))
    {
        out.push_str(".[\"");
        out.push_str(clean);
        out.push_str("\"]?");
    } else {
        return None;
    }
    Some(())
}
