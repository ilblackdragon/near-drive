//! Namespace access policy. Mirrors what `drive.near` will hold onchain.
//!
//! Rules are evaluated in order; the first rule whose `prefix` pattern matches
//! the path applies. `{account}` in a prefix captures one path segment that
//! must be a valid account id; `{account}` in read/write/payer refers to that
//! captured value. The namespace owner always has full access and is the
//! default payer.
use crate::uri::validate_account_id;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Rule {
    pub prefix: String,
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
    #[serde(default)]
    pub payer: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Access {
    pub read: bool,
    pub write: bool,
    pub payer: String,
}

/// Returns the captured `{account}` (or `Some("")` when the pattern has none)
/// if `path` is under `pattern`.
fn match_prefix(pattern: &str, path: &str) -> Option<String> {
    match pattern.split_once("{account}") {
        None => path.starts_with(pattern).then(String::new),
        Some((pre, post)) => {
            let rest = path.strip_prefix(pre)?;
            let end = rest.find('/').unwrap_or(rest.len());
            let acct = &rest[..end];
            validate_account_id(acct).ok()?;
            rest[end..].starts_with(post).then(|| acct.to_string())
        }
    }
}

fn subst(s: &str, bound: &str) -> String {
    s.replace("{account}", bound)
}

pub fn resolve(namespace: &str, rules: &[Rule], path: &str, signer: &str) -> Access {
    let owner = signer == namespace;
    for r in rules {
        if let Some(bound) = match_prefix(&r.prefix, path) {
            let allowed = |list: &[String]| list.iter().any(|e| e == "*" || subst(e, &bound) == signer);
            return Access {
                read: owner || allowed(&r.read),
                write: owner || allowed(&r.write),
                payer: r.payer.as_deref().map(|p| subst(p, &bound)).unwrap_or_else(|| namespace.to_string()),
            };
        }
    }
    Access { read: owner, write: owner, payer: namespace.to_string() }
}

/// Whether `signer` may write anywhere in the namespace (gate for chunk uploads).
pub fn can_write_somewhere(namespace: &str, rules: &[Rule], signer: &str) -> bool {
    signer == namespace
        || rules.iter().any(|r| r.write.iter().any(|e| e == "*" || e == signer || (e == "{account}" && r.prefix.contains("{account}"))))
}

/// Whether `signer` may read at least some path under `prefix` according to
/// the rules (first match wins, as in [`resolve`]). Used to decide which
/// rolled-up common prefixes a directory listing may show; it does not check
/// that a readable object actually exists there.
pub fn subtree_readable(namespace: &str, rules: &[Rule], prefix: &str, signer: &str) -> bool {
    if signer == namespace {
        return true;
    }
    for r in rules {
        if let Some(bound) = match_prefix(&r.prefix, prefix) {
            // Every path under `prefix` not claimed by an earlier rule lands here.
            return r.read.iter().any(|e| e == "*" || subst(e, &bound) == signer);
        }
        let (lit, templated) = match r.prefix.split_once("{account}") {
            Some((pre, _)) => (pre, true),
            None => (r.prefix.as_str(), false),
        };
        // The rule applies to some paths under `prefix` only.
        let overlaps = lit.starts_with(prefix) || (templated && prefix.starts_with(lit));
        if overlaps && r.read.iter().any(|e| e == "*" || e == signer || (templated && e.contains("{account}"))) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subtree_visibility() {
        let rules = rules();
        assert!(subtree_readable("app.near", &rules, "", "app.near"), "owner sees all");
        assert!(subtree_readable("app.near", &rules, "", "bob.near"), "public/ and own folder are under the root");
        assert!(subtree_readable("app.near", &rules, "users/", "bob.near"));
        assert!(subtree_readable("app.near", &rules, "users/bob.near/", "bob.near"));
        assert!(!subtree_readable("app.near", &rules, "users/alice.near/", "bob.near"));
        assert!(subtree_readable("app.near", &rules, "public/x/", "bob.near"));
        assert!(!subtree_readable("app.near", &rules, "private/", "bob.near"));
        let shadow: Vec<Rule> = serde_json::from_str(r#"[{"prefix":"a/secret/","read":[]},{"prefix":"a/","read":["*"]}]"#).unwrap();
        assert!(!subtree_readable("app.near", &shadow, "a/secret/", "bob.near"), "an earlier rule shadows a later one");
        assert!(subtree_readable("app.near", &shadow, "a/other/", "bob.near"));
    }

    fn rules() -> Vec<Rule> {
        serde_json::from_str(
            r#"[
            {"prefix":"users/{account}/","read":["{account}"],"write":["{account}","app.near"],"payer":"app.near"},
            {"prefix":"public/","read":["*"],"write":[]}
        ]"#,
        )
        .unwrap()
    }

    #[test]
    fn per_user_pattern() {
        let r = rules();
        let a = resolve("app.near", &r, "users/bob.near/chat/1", "bob.near");
        assert_eq!(a, Access { read: true, write: true, payer: "app.near".into() });
        // app can write but not read user data
        let a = resolve("app.near", &r, "users/bob.near/chat/1", "app.near");
        assert!(a.read && a.write, "owner has full access");
        let a = resolve("app.near", &r, "users/bob.near/chat/1", "eve.near");
        assert!(!a.read && !a.write);
        // capture must be a full segment
        let a = resolve("app.near", &r, "users/bob.near.evil/x", "bob.near");
        assert!(!a.read);
        assert!(!resolve("app.near", &r, "users/bob.near", "bob.near").read);
    }

    #[test]
    fn public_and_default() {
        let r = rules();
        let a = resolve("app.near", &r, "public/x", "anyone.near");
        assert!(a.read && !a.write);
        let a = resolve("app.near", &r, "private/x", "anyone.near");
        assert!(!a.read && !a.write);
        assert_eq!(a.payer, "app.near");
    }

    #[test]
    fn app_writer_not_reader() {
        let r: Vec<Rule> = serde_json::from_str(
            r#"[{"prefix":"inbox/","read":[],"write":["app.near"],"payer":"app.near"}]"#,
        )
        .unwrap();
        let a = resolve("alice.near", &r, "inbox/1", "app.near");
        assert!(a.write && !a.read);
    }
}
