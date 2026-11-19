use std::fmt;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum UriError {
    #[error("uri must start with near://")]
    Scheme,
    #[error("invalid NEAR account id: {0}")]
    Account(String),
    #[error("invalid object path: {0}")]
    Path(String),
}

/// `near://<namespace>/<path>` where namespace is a NEAR account id.
/// `path` may be empty (namespace root / listing prefix).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NearUri {
    pub namespace: String,
    pub path: String,
}

impl NearUri {
    pub fn parse(s: &str) -> Result<Self, UriError> {
        let rest = s.strip_prefix("near://").ok_or(UriError::Scheme)?;
        let (ns, path) = rest.split_once('/').unwrap_or((rest, ""));
        validate_account_id(ns)?;
        if !path.is_empty() {
            validate_path(path, true)?;
        }
        Ok(Self { namespace: ns.to_string(), path: path.to_string() })
    }

    pub fn object(namespace: &str, path: &str) -> Result<Self, UriError> {
        validate_account_id(namespace)?;
        validate_path(path, false)?;
        Ok(Self { namespace: namespace.into(), path: path.into() })
    }
}

impl fmt::Display for NearUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "near://{}/{}", self.namespace, self.path)
    }
}

/// NEAR account id rules: 2..=64 chars of [a-z0-9], separated by single
/// `.`, `-` or `_`, not starting or ending with a separator.
pub fn validate_account_id(id: &str) -> Result<(), UriError> {
    let err = || UriError::Account(id.to_string());
    if id.len() < 2 || id.len() > 64 {
        return Err(err());
    }
    let mut prev_sep = true;
    for c in id.chars() {
        let sep = matches!(c, '.' | '-' | '_');
        if sep {
            if prev_sep {
                return Err(err());
            }
        } else if !(c.is_ascii_lowercase() || c.is_ascii_digit()) {
            return Err(err());
        }
        prev_sep = sep;
    }
    if prev_sep {
        return Err(err());
    }
    Ok(())
}

/// Object paths: 1..=1024 bytes, `/`-separated non-empty segments, no `.`/`..`
/// segments, no control characters. A trailing `/` is allowed only for
/// prefixes (`allow_trailing_slash`).
pub fn validate_path(p: &str, allow_trailing_slash: bool) -> Result<(), UriError> {
    let err = |m: &str| UriError::Path(format!("{p:?}: {m}"));
    if p.is_empty() || p.len() > 1024 {
        return Err(err("length must be 1..=1024"));
    }
    if p.chars().any(|c| c.is_control() || c == '\\') {
        return Err(err("control characters or backslash"));
    }
    let body = if allow_trailing_slash { p.strip_suffix('/').unwrap_or(p) } else { p };
    if body.is_empty() {
        return Err(err("empty"));
    }
    for seg in body.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(err("empty, '.' or '..' segment"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        let u = NearUri::parse("near://root.near/objects/etc/mystuff").unwrap();
        assert_eq!(u.namespace, "root.near");
        assert_eq!(u.path, "objects/etc/mystuff");
        assert_eq!(u.to_string(), "near://root.near/objects/etc/mystuff");
        assert_eq!(NearUri::parse("near://alice.near").unwrap().path, "");
        assert!(NearUri::parse("near://alice.near/dir/").is_ok());
    }

    #[test]
    fn rejects() {
        for bad in [
            "s3://a.near/x",
            "near://A.near/x",
            "near://a..near/x",
            "near://.a.near/x",
            "near://a/x",
            "near://alice.near/../x",
            "near://alice.near/a//b",
            "near://alice.near/a\nb",
        ] {
            assert!(NearUri::parse(bad).is_err(), "{bad}");
        }
        assert!(NearUri::object("alice.near", "dir/").is_err());
    }
}
