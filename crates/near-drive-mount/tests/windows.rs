//! Windows Cloud Files provider against an in-process gateway. Files are
//! touched from separate PowerShell processes, as an app would.
#![cfg(windows)]
use ed25519_dalek::SigningKey;
use near_drive_client::{
    near_drive_core::{crypto::RootKey, keys, NearUri},
    Client, PutOptions,
};
use near_drive_gateway::{router, AppState, Config};
use near_drive_mount::{mount, unregister, MountOptions};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

fn u(s: &str) -> NearUri {
    NearUri::parse(s).unwrap()
}

fn ps(root: &Path, script: &str) -> String {
    let out = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(out.status.success(), "powershell failed: {script}\n{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

async fn eventually<F, Fut>(what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..60 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("timed out waiting for: {what}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cloud_files_placeholders() {
    if !cloud_filter_supported() {
        eprintln!("skipping: no Cloud Files API here");
        return;
    }
    let _ = tracing_subscriber::fmt().with_env_filter("near_drive_mount=debug").with_test_writer().try_init();
    let tmp = tempfile::tempdir().unwrap();
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let dev = HashMap::from([("alice.near".to_string(), vec![keys::format_public_key(&sk.verifying_key())])]);
    let cfg = Config { listen: "127.0.0.1:0".into(), data_dir: tmp.path().join("gw"), dev_keys: dev, ..Default::default() };
    let state = AppState::new(cfg).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
    let root_key = *RootKey::generate().as_bytes();
    let mk = || Client::new(&url, "alice.near", sk.clone(), Some(RootKey::from_bytes(root_key)));
    let c = mk();
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    c.put(&u("near://alice.near/Drive/docs/a.txt"), b"hello", &PutOptions::default()).await.unwrap();
    c.put(&u("near://alice.near/Drive/b.bin"), &big, &PutOptions::default()).await.unwrap();

    // Like cloud-filter's own tests: a sync root on the build volume (NTFS).
    let root = std::env::current_dir().unwrap().join("target").join(format!("nd-cf-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let remote = u("near://alice.near/Drive/");
    let m = mount(Arc::new(mk()), remote.clone(), &root, MountOptions::new(tmp.path().join("cache")), tokio::runtime::Handle::current()).unwrap();

    let r = root.clone();
    let names = tokio::task::spawn_blocking(move || ps(&r, "(Get-ChildItem -Name | Sort-Object) -join ','")).await.unwrap();
    assert_eq!(names, "b.bin,docs");
    let r = root.clone();
    let text = tokio::task::spawn_blocking(move || ps(&r, "Get-Content -Raw docs\\a.txt")).await.unwrap();
    assert_eq!(text, "hello");
    let r = root.clone();
    let len = tokio::task::spawn_blocking(move || ps(&r, "(Get-FileHash -Algorithm SHA256 b.bin).Hash; (Get-Item b.bin).Length")).await.unwrap();
    assert!(len.ends_with("300000"), "{len}");

    // New file -> uploaded.
    let r = root.clone();
    tokio::task::spawn_blocking(move || ps(&r, "Set-Content -NoNewline -Path new.txt -Value 'made on windows'")).await.unwrap();
    eventually("new.txt uploaded", || async { c.head(&u("near://alice.near/Drive/new.txt")).await.unwrap().is_some() }).await;
    assert_eq!(c.get(&u("near://alice.near/Drive/new.txt")).await.unwrap().1, b"made on windows");

    // Delete -> deleted remotely.
    let r = root.clone();
    tokio::task::spawn_blocking(move || ps(&r, "Remove-Item b.bin")).await.unwrap();
    assert!(c.head(&u("near://alice.near/Drive/b.bin")).await.unwrap().is_none());

    // Remote change -> placeholder updated; new content on next read.
    c.put(&u("near://alice.near/Drive/docs/a.txt"), b"changed remotely", &PutOptions::default()).await.unwrap();
    let r = root.clone();
    eventually("remote change visible", || {
        let r = r.clone();
        async move { tokio::task::spawn_blocking(move || ps(&r, "Get-Content -Raw docs\\a.txt")).await.unwrap() == "changed remotely" }
    })
    .await;

    m.unmount().unwrap();
    unregister(&remote).unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

fn cloud_filter_supported() -> bool {
    // Windows Server images may lack the Cloud Files filter driver.
    std::process::Command::new("fltmc.exe").arg("filters").output().map(|o| String::from_utf8_lossy(&o.stdout).contains("CldFlt")).unwrap_or(true)
}
