//! Input validation shared by the contract methods. Everything stored onchain
//! is bounded so a caller cannot make reads (gateways, SDKs) expensive.
use crate::Rule;
use near_sdk::AccountId;

pub const MAX_RULES: usize = 32;
pub const MAX_PRINCIPALS: usize = 32;
pub const MAX_PREFIX_LEN: usize = 256;
pub const MAX_RULES_JSON_BYTES: usize = 16 * 1024;
pub const MAX_URL_LEN: usize = 256;
pub const MAX_TAGS: usize = 16;
pub const MAX_TAG_LEN: usize = 32;
pub const MAX_PRICE_HINT_LEN: usize = 256;
pub const MAX_ATTESTATION_LEN: usize = 16 * 1024;
pub const MAX_ROOT_LEN: usize = 128;
pub const MAX_TOKEN_ID_LEN: usize = 128;
/// Signing keys kept per account (the oldest is dropped beyond this).
pub const MAX_SIGN_KEYS: usize = 16;

pub const ACCOUNT_PLACEHOLDER: &str = "{account}";

pub fn is_account_id(s: &str) -> bool {
    s.parse::<AccountId>().is_ok()
}

/// Mirrors `near_drive_core::uri::validate_path` for prefixes, plus the
/// `{account}` placeholder rules of `near_drive_core::policy`.
pub fn validate_prefix(prefix: &str) -> Result<bool, String> {
    if prefix.len() > MAX_PREFIX_LEN {
        return Err(format!("prefix longer than {MAX_PREFIX_LEN} bytes"));
    }
    if prefix.starts_with('/') {
        return Err("prefix must not start with '/'".into());
    }
    if prefix.chars().any(|c| c.is_control() || c == '\\') {
        return Err("prefix contains control characters or backslash".into());
    }
    let n = prefix.matches(ACCOUNT_PLACEHOLDER).count();
    if n > 1 {
        return Err("at most one {account} per prefix".into());
    }
    let rest = prefix.replacen(ACCOUNT_PLACEHOLDER, "", 1);
    if rest.contains('{') || rest.contains('}') {
        return Err("only the {account} placeholder may use braces".into());
    }
    if n == 1 {
        let (pre, post) = prefix.split_once(ACCOUNT_PLACEHOLDER).unwrap();
        if !(pre.is_empty() || pre.ends_with('/')) || !(post.is_empty() || post.starts_with('/')) {
            return Err("{account} must be a whole path segment".into());
        }
    }
    // Non-final segments must be non-empty and not `.`/`..`.
    let body = prefix.strip_suffix('/').unwrap_or(prefix);
    if !body.is_empty() {
        for seg in body.split('/') {
            if seg.is_empty() || seg == "." || seg == ".." {
                return Err("empty, '.' or '..' segment in prefix".into());
            }
        }
    }
    Ok(n == 1)
}

fn validate_principal(p: &str, has_capture: bool, allow_star: bool) -> Result<(), String> {
    if p == "*" {
        return if allow_star {
            Ok(())
        } else {
            Err("'*' is not allowed as payer".into())
        };
    }
    if p == ACCOUNT_PLACEHOLDER {
        return if has_capture {
            Ok(())
        } else {
            Err("{account} used but the prefix has no {account}".into())
        };
    }
    if is_account_id(p) {
        Ok(())
    } else {
        Err(format!("invalid account id {p:?}"))
    }
}

pub fn validate_rules(rules: &[Rule]) -> Result<(), String> {
    if rules.len() > MAX_RULES {
        return Err(format!("at most {MAX_RULES} rules"));
    }
    for (i, r) in rules.iter().enumerate() {
        let ctx = |e: String| format!("rule {i}: {e}");
        if rules[..i].iter().any(|prev| prev.prefix == r.prefix) {
            return Err(ctx(format!("duplicate prefix {:?}", r.prefix)));
        }
        let cap = validate_prefix(&r.prefix).map_err(ctx)?;
        if r.read.len() > MAX_PRINCIPALS || r.write.len() > MAX_PRINCIPALS {
            return Err(ctx(format!("at most {MAX_PRINCIPALS} read/write entries")));
        }
        for p in r.read.iter().chain(&r.write) {
            validate_principal(p, cap, true).map_err(ctx)?;
        }
        if let Some(p) = &r.payer {
            validate_principal(p, cap, false).map_err(ctx)?;
        }
    }
    let size = near_sdk::serde_json::to_vec(rules)
        .map(|v| v.len())
        .unwrap_or(usize::MAX);
    if size > MAX_RULES_JSON_BYTES {
        return Err(format!("rules exceed {MAX_RULES_JSON_BYTES} bytes"));
    }
    Ok(())
}

/// `x25519:<base58 of 32 bytes>`
pub fn validate_enc_key(k: &str) -> Result<(), String> {
    let b58 = k
        .strip_prefix("x25519:")
        .ok_or("key must start with x25519:")?;
    match bs58::decode(b58).into_vec() {
        Ok(v) if v.len() == 32 && v.iter().any(|b| *b != 0) => Ok(()),
        Ok(v) if v.len() == 32 => Err("x25519 key must not be all zero".into()),
        _ => Err("x25519 key must be base58 of 32 bytes".into()),
    }
}

/// `ed25519:<base58 of 32 bytes>`
pub fn validate_sign_key(k: &str) -> Result<(), String> {
    let b58 = k
        .strip_prefix("ed25519:")
        .ok_or("key must start with ed25519:")?;
    match bs58::decode(b58).into_vec() {
        Ok(v) if v.len() == 32 => Ok(()),
        _ => Err("ed25519 key must be base58 of 32 bytes".into()),
    }
}

fn validate_tags(what: &str, tags: &[String]) -> Result<(), String> {
    if tags.len() > MAX_TAGS {
        return Err(format!("at most {MAX_TAGS} {what}"));
    }
    for t in tags {
        if t.is_empty()
            || t.len() > MAX_TAG_LEN
            || !t.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
            })
        {
            return Err(format!(
                "invalid {what} entry {t:?} (1..={MAX_TAG_LEN} of [a-z0-9-_.])"
            ));
        }
    }
    Ok(())
}

pub fn validate_gateway(g: &crate::gateway::GatewayInfo) -> Result<(), String> {
    if g.url.len() > MAX_URL_LEN || !(g.url.starts_with("https://") || g.url.starts_with("http://"))
    {
        return Err(format!(
            "url must be http(s):// and at most {MAX_URL_LEN} bytes"
        ));
    }
    if g.url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("url contains whitespace".into());
    }
    validate_tags("regions", &g.regions)?;
    validate_tags("backends", &g.backends)?;
    if g.price_hint.len() > MAX_PRICE_HINT_LEN {
        return Err(format!("price_hint longer than {MAX_PRICE_HINT_LEN} bytes"));
    }
    if g.attestation
        .as_ref()
        .is_some_and(|a| a.len() > MAX_ATTESTATION_LEN)
    {
        return Err(format!(
            "attestation longer than {MAX_ATTESTATION_LEN} bytes"
        ));
    }
    Ok(())
}

pub fn validate_root(root: &str) -> Result<(), String> {
    if root.is_empty() || root.len() > MAX_ROOT_LEN || !root.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!(
            "root must be 1..={MAX_ROOT_LEN} printable ASCII bytes"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(prefix: &str, read: &[&str], write: &[&str], payer: Option<&str>) -> Rule {
        Rule {
            prefix: prefix.into(),
            read: read.iter().map(|s| s.to_string()).collect(),
            write: write.iter().map(|s| s.to_string()).collect(),
            payer: payer.map(Into::into),
        }
    }

    #[test]
    fn prefixes() {
        assert_eq!(validate_prefix("users/{account}/"), Ok(true));
        assert_eq!(validate_prefix("{account}"), Ok(true));
        assert_eq!(validate_prefix("weights/"), Ok(false));
        assert_eq!(validate_prefix(""), Ok(false));
        assert_eq!(validate_prefix("a/b"), Ok(false));
        for bad in [
            "users/{account}/{account}/",
            "users/x{account}/",
            "users/{account}x/",
            "users/{acc}/",
            "/abs",
            "a//b",
            "a/../b",
            "a\nb",
            "a\\b",
        ] {
            assert!(validate_prefix(bad).is_err(), "{bad}");
        }
        assert!(validate_prefix(&"a".repeat(MAX_PREFIX_LEN + 1)).is_err());
    }

    #[test]
    fn rules() {
        validate_rules(&[
            rule(
                "users/{account}/",
                &["{account}"],
                &["{account}", "app.near"],
                Some("app.near"),
            ),
            rule("public/", &["*"], &[], None),
            rule("p/{account}/", &[], &[], Some("{account}")),
        ])
        .unwrap();
        assert!(validate_rules(&[rule("x/", &["{account}"], &[], None)]).is_err());
        assert!(validate_rules(&[rule("x/", &["Bad.near"], &[], None)]).is_err());
        assert!(validate_rules(&[rule("x/", &[], &[], Some("*"))]).is_err());
        assert!(validate_rules(&[rule("x/", &[], &[], Some("{account}"))]).is_err());
        let many: Vec<_> = (0..=MAX_RULES)
            .map(|_| rule("x/", &[], &[], None))
            .collect();
        assert!(validate_rules(&many).is_err());
        let wide: Vec<String> = (0..=MAX_PRINCIPALS).map(|i| format!("a{i}.near")).collect();
        let wide: Vec<&str> = wide.iter().map(String::as_str).collect();
        assert!(validate_rules(&[rule("x/", &wide, &[], None)]).is_err());
    }

    #[test]
    fn enc_keys() {
        let k = format!("x25519:{}", bs58::encode([7u8; 32]).into_string());
        validate_enc_key(&k).unwrap();
        assert!(validate_enc_key(&format!(
            "ed25519:{}",
            bs58::encode([7u8; 32]).into_string()
        ))
        .is_err());
        assert!(
            validate_enc_key(&format!("x25519:{}", bs58::encode([7u8; 31]).into_string())).is_err()
        );
        assert!(validate_enc_key("x25519:0OIl").is_err());
    }

    #[test]
    fn sign_keys() {
        let k = format!("ed25519:{}", bs58::encode([7u8; 32]).into_string());
        validate_sign_key(&k).unwrap();
        assert!(validate_sign_key(&format!(
            "x25519:{}",
            bs58::encode([7u8; 32]).into_string()
        ))
        .is_err());
        assert!(validate_sign_key(&format!(
            "ed25519:{}",
            bs58::encode([7u8; 33]).into_string()
        ))
        .is_err());
        assert!(validate_sign_key("ed25519:0OIl").is_err());
    }
}
