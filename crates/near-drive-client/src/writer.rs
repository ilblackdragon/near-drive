//! Reader-side writer authorization: a record is accepted only if its
//! `writer_pk` is a signing key its `writer` published in `drive.near` (and
//! was in force at the record's timestamp), and the namespace policy lets
//! `writer` write the path. Without this a gateway could sign records with
//! its own key and claim any writer.
use anyhow::{anyhow, Result};
use near_drive_chain::{NoContract, StorageContract};
use near_drive_core::{
    policy::{self, Rule},
    record::{PointerRecord, SignKeyEntry},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// How long sign keys and rules read from the chain are reused.
pub const WRITER_CACHE_TTL: Duration = Duration::from_secs(60);
/// Most accounts / namespaces kept in each cache.
pub const WRITER_CACHE_MAX: usize = 1024;
/// A rejection based on cached state older than this re-reads the chain once
/// (the writer may have just published a key or a rule).
const RECHECK_AFTER: Duration = Duration::from_secs(2);

/// How a client decides whether a record's writer was allowed to write it.
#[derive(Clone)]
pub enum WriterCheck {
    /// `get_sign_keys(writer)` and `get_rules(namespace)` from `drive.near`
    /// (cached [`WRITER_CACHE_TTL`]). The default once a chain is configured
    /// ([`crate::Client::with_chain`]).
    Chain(StorageContract),
    /// Fixed keys and rules, for tests and dev setups without a chain.
    Trusted(TrustedWriters),
    /// No writer check at all: a gateway can forge records. Tests only; set
    /// with [`crate::Client::insecure_skip_writer_check`].
    InsecureSkip,
}

/// Writers and policy for [`WriterCheck::Trusted`].
#[derive(Clone, Debug, Default)]
pub struct TrustedWriters {
    /// account -> its record-signing keys (`ed25519:<base58>`), valid at any time.
    pub sign_keys: HashMap<String, Vec<String>>,
    /// namespace -> rules; a namespace not listed is owner-only.
    pub rules: HashMap<String, Vec<Rule>>,
}

impl TrustedWriters {
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust `key` as a signing key of `account`.
    pub fn key(mut self, account: impl Into<String>, key: impl Into<String>) -> Self {
        self.sign_keys.entry(account.into()).or_default().push(key.into());
        self
    }

    /// Use `rules` as the policy of `namespace`.
    pub fn rules(mut self, namespace: impl Into<String>, rules: Vec<Rule>) -> Self {
        self.rules.insert(namespace.into(), rules);
        self
    }

    fn verify(&self, r: &PointerRecord) -> Result<()> {
        let known = self.sign_keys.get(&r.writer).is_some_and(|ks| ks.contains(&r.writer_pk));
        anyhow::ensure!(known, "{}/{} is signed with {}, which is not a trusted signing key of {}", r.namespace, r.path, r.writer_pk, r.writer);
        let rules = self.rules.get(&r.namespace).map(Vec::as_slice).unwrap_or_default();
        anyhow::ensure!(policy::resolve(&r.namespace, rules, &r.path, &r.writer).write, "{} is not allowed to write {}/{}", r.writer, r.namespace, r.path);
        Ok(())
    }
}

pub(crate) const NO_CHECK: &str = "no writer check configured, so records read from the gateway cannot be trusted: \
use Client::with_chain (check writers against drive.near), Client::with_writer_check(WriterCheck::Trusted(..)) \
for fixed keys, or Client::insecure_skip_writer_check() in tests";

/// TTL + size-bounded cache; serves a stale value when a refresh fails.
struct Cache<T> {
    map: Mutex<HashMap<String, (Arc<T>, Instant)>>,
}

impl<T> Default for Cache<T> {
    fn default() -> Self {
        Self { map: Mutex::new(HashMap::new()) }
    }
}

impl<T> Cache<T> {
    fn get(&self, k: &str) -> Option<(Arc<T>, Duration)> {
        self.map.lock().unwrap().get(k).map(|(v, at)| (v.clone(), at.elapsed()))
    }

    fn put(&self, k: &str, v: Arc<T>) {
        let mut m = self.map.lock().unwrap();
        if m.len() >= WRITER_CACHE_MAX && !m.contains_key(k) {
            m.retain(|_, (_, at)| at.elapsed() < WRITER_CACHE_TTL);
            if m.len() >= WRITER_CACHE_MAX {
                // Drop the oldest entry.
                if let Some(old) = m.iter().min_by_key(|(_, (_, at))| *at).map(|(k, _)| k.clone()) {
                    m.remove(&old);
                }
            }
        }
        m.insert(k.to_string(), (v, Instant::now()));
    }

    /// Cached value if fresh (and `!force`), else `fetch`; on a fetch error
    /// the stale value if any. Returns the value and its age.
    async fn load<F, Fut>(&self, k: &str, force: bool, fetch: F) -> Result<(Arc<T>, Duration)>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let cached = self.get(k);
        if let Some((v, age)) = &cached {
            if !force && *age < WRITER_CACHE_TTL {
                return Ok((v.clone(), *age));
            }
        }
        match fetch().await {
            Ok(v) => {
                let v = Arc::new(v);
                self.put(k, v.clone());
                Ok((v, Duration::ZERO))
            }
            Err(e) => match cached {
                Some((v, age)) => {
                    crate::debug(&format!("refreshing {k} failed, using cached state: {e:#}"));
                    Ok((v, age))
                }
                None => Err(e),
            },
        }
    }
}

#[derive(Default)]
pub(crate) struct WriterVerifier {
    pub(crate) check: Option<WriterCheck>,
    sign_keys: Cache<Vec<SignKeyEntry>>,
    rules: Cache<Vec<Rule>>,
}

/// No contract deployed yet: nobody has published anything.
fn or_empty<T: Default>(r: Result<T>) -> Result<T> {
    match r {
        Err(e) if e.downcast_ref::<NoContract>().is_some() => Ok(T::default()),
        r => r,
    }
}

impl WriterVerifier {
    pub(crate) fn set(&mut self, check: WriterCheck) {
        *self = Self { check: Some(check), ..Default::default() };
    }

    /// The reader rule for a record whose signature already checked out.
    pub(crate) async fn verify(&self, r: &PointerRecord) -> Result<()> {
        match self.check.as_ref().ok_or_else(|| anyhow!(NO_CHECK))? {
            WriterCheck::InsecureSkip => Ok(()),
            WriterCheck::Trusted(t) => t.verify(r),
            WriterCheck::Chain(c) => match self.verify_chain(c, r, false).await? {
                (Ok(()), _) => Ok(()),
                (Err(_), age) if age >= RECHECK_AFTER => self.verify_chain(c, r, true).await?.0,
                (Err(e), _) => Err(e),
            },
        }
    }

    /// Outer error: NEAR state unavailable. Inner: the record was rejected;
    /// with the age of the oldest cached state used.
    async fn verify_chain(&self, c: &StorageContract, r: &PointerRecord, force: bool) -> Result<(Result<()>, Duration)> {
        let (keys, kage) = self
            .sign_keys
            .load(&r.writer, force, || async { or_empty(c.get_sign_keys(&r.writer).await) })
            .await
            .map_err(|e| e.context(format!("reading the signing keys of {}", r.writer)))?;
        // The namespace owner may always write; no rules needed.
        let (rules, rage) = if r.writer == r.namespace {
            (Arc::default(), Duration::ZERO)
        } else {
            self.rules
                .load(&r.namespace, force, || async { or_empty(c.get_rules(&r.namespace).await) })
                .await
                .map_err(|e| e.context(format!("reading the policy of {}", r.namespace)))?
        };
        let res = if keys.is_empty() {
            Err(anyhow!("{} has not published a record-signing key (near drive publish-key), so {}/{} cannot be verified", r.writer, r.namespace, r.path))
        } else {
            r.verify_writer(&keys, &rules)
        };
        Ok((res, kage.max(rage)))
    }
}
