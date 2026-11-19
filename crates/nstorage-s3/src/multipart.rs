//! Multipart upload staging on local disk (`<nstorage home>/s3-staging/<upload-id>/`).
//! Parts are plaintext on the user's own machine (same trust domain as the
//! files being uploaded); they are encrypted when the assembled object is
//! uploaded at CompleteMultipartUpload.
use crate::error::{S3Error, S3Result};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadMeta {
    pub bucket: String,
    pub key: String,
    pub content_type: Option<String>,
    pub user_meta: BTreeMap<String, String>,
    pub initiated_ms: u64,
}

#[derive(Debug, Clone)]
pub struct PartInfo {
    pub number: u32,
    pub etag: String,
    pub size: u64,
    pub modified_ms: u64,
}

pub struct Staging {
    dir: PathBuf,
}

fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn mtime_ms(m: &std::fs::Metadata) -> u64 {
    m.modified().ok().and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok()).map(|d| d.as_millis() as u64).unwrap_or(0)
}

impl Staging {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn upload_dir(&self, id: &str) -> S3Result<PathBuf> {
        if !valid_id(id) {
            return Err(S3Error::no_such_upload());
        }
        Ok(self.dir.join(id))
    }

    pub async fn create(&self, meta: &UploadMeta) -> S3Result<String> {
        let id = hex::encode(rand::random::<[u8; 16]>());
        let d = self.dir.join(&id);
        tokio::fs::create_dir_all(&d).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700));
        }
        tokio::fs::write(d.join("upload.json"), serde_json::to_vec(meta).expect("serializable")).await?;
        Ok(id)
    }

    /// Load an upload and check it belongs to `bucket`/`key`.
    pub async fn load(&self, id: &str, bucket: &str, key: &str) -> S3Result<UploadMeta> {
        let d = self.upload_dir(id)?;
        let b = tokio::fs::read(d.join("upload.json")).await.map_err(|_| S3Error::no_such_upload())?;
        let m: UploadMeta = serde_json::from_slice(&b).map_err(|_| S3Error::no_such_upload())?;
        if m.bucket != bucket || m.key != key {
            return Err(S3Error::no_such_upload());
        }
        Ok(m)
    }

    pub async fn put_part(&self, id: &str, n: u32, data: &[u8]) -> S3Result<String> {
        use md5::Digest;
        let d = self.upload_dir(id)?;
        let etag = hex::encode(md5::Md5::digest(data));
        let tmp = d.join(format!("{n:05}.tmp-{}", hex::encode(rand::random::<[u8; 6]>())));
        let mut f = tokio::fs::File::create(&tmp).await?;
        f.write_all(data).await?;
        f.flush().await?;
        drop(f);
        tokio::fs::write(d.join(format!("{n:05}.etag")), &etag).await?;
        tokio::fs::rename(&tmp, d.join(format!("{n:05}.part"))).await?;
        Ok(etag)
    }

    pub async fn parts(&self, id: &str) -> S3Result<Vec<PartInfo>> {
        let d = self.upload_dir(id)?;
        let mut out = vec![];
        let mut rd = tokio::fs::read_dir(&d).await.map_err(|_| S3Error::no_such_upload())?;
        while let Some(e) = rd.next_entry().await? {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(n) = name.strip_suffix(".part").and_then(|s| s.parse::<u32>().ok()) else { continue };
            let md = e.metadata().await?;
            let etag = tokio::fs::read_to_string(d.join(format!("{n:05}.etag"))).await.unwrap_or_default();
            out.push(PartInfo { number: n, etag, size: md.len(), modified_ms: mtime_ms(&md) });
        }
        out.sort_by_key(|p| p.number);
        Ok(out)
    }

    /// Concatenate the listed parts (ascending, ETags must match) into one
    /// file inside the upload dir and return its path.
    pub async fn assemble(&self, id: &str, wanted: &[(u32, String)]) -> S3Result<PathBuf> {
        let d = self.upload_dir(id)?;
        if wanted.is_empty() {
            return Err(S3Error::malformed_xml());
        }
        let have: BTreeMap<u32, PartInfo> = self.parts(id).await?.into_iter().map(|p| (p.number, p)).collect();
        let mut prev = 0;
        for (n, etag) in wanted {
            if *n <= prev {
                return Err(S3Error::new(StatusCode::BAD_REQUEST, "InvalidPartOrder", "The list of parts was not in ascending order."));
            }
            prev = *n;
            match have.get(n) {
                Some(p) if p.etag == *etag => {}
                _ => {
                    return Err(S3Error::new(
                        StatusCode::BAD_REQUEST,
                        "InvalidPart",
                        format!("Part {n} could not be found or its ETag does not match."),
                    ))
                }
            }
        }
        let out_path = d.join("assembled");
        let mut out = tokio::fs::File::create(&out_path).await?;
        for (n, _) in wanted {
            let mut f = tokio::fs::File::open(d.join(format!("{n:05}.part"))).await?;
            tokio::io::copy(&mut f, &mut out).await?;
        }
        out.flush().await?;
        Ok(out_path)
    }

    pub async fn abort(&self, id: &str) -> S3Result<()> {
        let d = self.upload_dir(id)?;
        if tokio::fs::metadata(d.join("upload.json")).await.is_err() {
            return Err(S3Error::no_such_upload());
        }
        tokio::fs::remove_dir_all(&d).await?;
        Ok(())
    }

    pub async fn list(&self, bucket: &str) -> S3Result<Vec<(String, UploadMeta)>> {
        let mut out = vec![];
        let Ok(mut rd) = tokio::fs::read_dir(&self.dir).await else { return Ok(out) };
        while let Some(e) = rd.next_entry().await? {
            let id = e.file_name().to_string_lossy().into_owned();
            if !valid_id(&id) {
                continue;
            }
            if let Ok(b) = tokio::fs::read(e.path().join("upload.json")).await {
                if let Ok(m) = serde_json::from_slice::<UploadMeta>(&b) {
                    if m.bucket == bucket {
                        out.push((id, m));
                    }
                }
            }
        }
        out.sort_by(|a, b| (&a.1.key, a.1.initiated_ms).cmp(&(&b.1.key, b.1.initiated_ms)));
        Ok(out)
    }

    /// Remove uploads untouched for longer than `max_age`.
    pub fn cleanup(dir: &Path, max_age: Duration) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let id = e.file_name().to_string_lossy().into_owned();
            if !valid_id(&id) {
                continue;
            }
            let old = e.metadata().ok().and_then(|m| m.modified().ok()).and_then(|t| t.elapsed().ok()).is_some_and(|age| age > max_age);
            if old {
                tracing::info!("removing stale multipart upload {id}");
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
}
