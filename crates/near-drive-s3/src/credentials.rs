//! Local S3 credentials for the sidecar, persisted as JSON (mode 0600).
use crate::sigv4::Credentials;
use anyhow::{Context, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize)]
struct File {
    access_key: String,
    secret_key: String,
}

fn random(alphabet: &[u8], n: usize) -> String {
    let mut r = rand::rngs::OsRng;
    (0..n).map(|_| alphabet[r.gen_range(0..alphabet.len())] as char).collect()
}

pub fn generate() -> Credentials {
    Credentials {
        access_key: format!("NST{}", random(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 17)),
        secret_key: random(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 40),
    }
}

/// Load credentials from `path`, or create and persist new ones.
/// Returns `(credentials, newly_created)`.
pub fn load_or_create(path: &Path) -> Result<(Credentials, bool)> {
    match std::fs::read(path) {
        Ok(b) => {
            let f: File = serde_json::from_slice(&b).with_context(|| format!("parsing {}", path.display()))?;
            Ok((Credentials { access_key: f.access_key, secret_key: f.secret_key }, false))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let c = generate();
            if let Some(d) = path.parent() {
                std::fs::create_dir_all(d)?;
            }
            let json = serde_json::to_vec_pretty(&File { access_key: c.access_key.clone(), secret_key: c.secret_key.clone() })?;
            write_private(path, &json)?;
            Ok((c, true))
        }
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path).with_context(|| format!("creating {}", path.display()))?;
    f.write_all(data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn persist() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sub/s3.json");
        let (a, new) = super::load_or_create(&p).unwrap();
        assert!(new && a.access_key.len() == 20 && a.secret_key.len() == 40);
        let (b, new) = super::load_or_create(&p).unwrap();
        assert!(!new);
        assert_eq!(a, b);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}
