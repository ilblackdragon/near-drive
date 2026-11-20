//! End-to-end: real gateway + real S3 proxy on random 127.0.0.1 ports,
//! driven by the official AWS Rust SDK (and raw reqwest for edge cases).
use aws_sdk_s3::{
    config::{BehaviorVersion, Credentials as AwsCreds, Region},
    error::{ProvideErrorMetadata, SdkError},
    presigning::PresigningConfig,
    primitives::ByteStream,
    types::{ChecksumAlgorithm, CompletedMultipartUpload, CompletedPart, Delete, ObjectIdentifier},
    Client as S3,
};
use ed25519_dalek::SigningKey;
use near_drive_client::{
    near_drive_core::{crypto::RootKey, keys},
    Client,
};
use near_drive_gateway::{router as gw_router, AppState, Config};
use near_drive_s3::{backend::ClientBackend, sigv4, Proxy, ProxyConfig};
use std::{collections::HashMap, time::Duration};

const AK: &str = "NSTTESTACCESSKEY0001";
const SK: &str = "testsecretkey0123456789abcdefghijklmnopq";

struct Env {
    url: String,
    gw_url: String,
    alice: SigningKey,
    gw_dir: tempfile::TempDir,
    _home: tempfile::TempDir,
    s3: S3,
}

async fn start() -> Env {
    start_cfg(|_| {}).await
}

const SHARED_RULES: &str = r#"[{"prefix":"inbox/","read":["*"],"write":["*"]}]"#;

async fn start_cfg(f: impl FnOnce(&mut ProxyConfig)) -> Env {
    let gw_dir = tempfile::tempdir().unwrap();
    let alice = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut dev_keys = HashMap::new();
    dev_keys.insert("alice.near".to_string(), vec![keys::format_public_key(&alice.verifying_key())]);
    let policies = HashMap::from([("shared.near".to_string(), serde_json::from_str(SHARED_RULES).unwrap())]);
    let cfg = Config {
        listen: "127.0.0.1:0".into(),
        data_dir: gw_dir.path().to_path_buf(),
        rpc_url: None,
        storage_contract: "drive.near".into(),
        dev_keys,
        policies,
        ..Default::default()
    };
    let state = AppState::new(cfg).await.unwrap();
    let gl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gw_url = format!("http://{}", gl.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(gl, gw_router(state)).await.unwrap() });

    let home = tempfile::tempdir().unwrap();
    // Trusts alice's two signing keys (the test also writes with a second root).
    let mut client = Client::new(&gw_url, "alice.near", alice.clone(), Some(RootKey::from_bytes([9; 32]))).with_writer_check(near_drive_client::WriterCheck::Trusted(near_drive_client::TrustedWriters::new().key("alice.near", RootKey::from_bytes([9; 32]).sign_public_key()).key("alice.near", RootKey::from_bytes([1; 32]).sign_public_key()).rules("shared.near", serde_json::from_str(SHARED_RULES).unwrap())));
    client.chunk_size = 64 * 1024; // multi-chunk objects in tests
    let mut pcfg = ProxyConfig::new(sigv4::Credentials { access_key: AK.into(), secret_key: SK.into() }, home.path().join("s3-staging"));
    pcfg.public_prefixes = vec!["public/".into()];
    pcfg.extra_buckets = vec!["shared.near".into()];
    f(&mut pcfg);
    let proxy = Proxy::new(pcfg, ClientBackend::new(client));
    let pl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", pl.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(pl, near_drive_s3::router(proxy)).await.unwrap() });
    let s3 = s3_client(&url, AK, SK);
    Env { url, gw_url, alice, gw_dir, _home: home, s3 }
}

fn s3_client(url: &str, ak: &str, sk: &str) -> S3 {
    let conf = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .endpoint_url(url)
        .credentials_provider(AwsCreds::new(ak, sk, None, None, "test"))
        .force_path_style(true)
        .build();
    S3::from_conf(conf)
}

fn code<E: ProvideErrorMetadata, R>(e: &SdkError<E, R>) -> String {
    match e {
        SdkError::ServiceError(s) => s.err().code().unwrap_or("<none>").to_string(),
        _ => "<not a service error>".into(),
    }
}

fn status<E>(e: &SdkError<E, aws_sdk_s3::config::http::HttpResponse>) -> u16 {
    e.raw_response().map(|r| r.status().as_u16()).unwrap_or(0)
}

fn data(n: usize, seed: u32) -> Vec<u8> {
    (0..n as u32).map(|i| (i.wrapping_add(seed.wrapping_mul(0x9E37_79B9)).wrapping_mul(2_654_435_761) >> 13) as u8).collect()
}

async fn body(o: aws_sdk_s3::operation::get_object::GetObjectOutput) -> Vec<u8> {
    o.body.collect().await.unwrap().into_bytes().to_vec()
}

const B: &str = "alice.near";

#[tokio::test]
async fn put_get_head_range_meta_and_encryption_at_rest() {
    let env = start().await;
    let s3 = &env.s3;
    let payload = data(200_000, 1);
    let put = s3
        .put_object()
        .bucket(B)
        .key("dir/obj one.bin")
        .content_type("application/x-test")
        .metadata("color", "blue")
        .metadata("run-id", "42")
        .body(ByteStream::from(payload.clone()))
        .send()
        .await
        .unwrap();
    let et = put.e_tag().unwrap().to_string();
    assert!(et.starts_with('"') && et.len() == 34, "{et}");

    let got = s3.get_object().bucket(B).key("dir/obj one.bin").send().await.unwrap();
    assert_eq!(got.e_tag(), Some(et.as_str()));
    assert_eq!(got.content_type(), Some("application/x-test"));
    assert_eq!(got.content_length(), Some(200_000));
    assert_eq!(got.metadata().unwrap().get("color").map(String::as_str), Some("blue"));
    assert_eq!(got.metadata().unwrap().get("run-id").map(String::as_str), Some("42"));
    assert!(got.last_modified().is_some());
    assert_eq!(body(got).await, payload);

    let head = s3.head_object().bucket(B).key("dir/obj one.bin").send().await.unwrap();
    assert_eq!(head.content_length(), Some(200_000));
    assert_eq!(head.e_tag(), Some(et.as_str()));
    assert_eq!(head.metadata().unwrap().get("color").map(String::as_str), Some("blue"));

    let r = s3.get_object().bucket(B).key("dir/obj one.bin").range("bytes=100000-100009").send().await.unwrap();
    assert_eq!(r.content_range(), Some("bytes 100000-100009/200000"));
    assert_eq!(r.content_length(), Some(10));
    assert_eq!(body(r).await, &payload[100_000..100_010]);
    let r = s3.get_object().bucket(B).key("dir/obj one.bin").range("bytes=-5").send().await.unwrap();
    assert_eq!(body(r).await, &payload[199_995..]);
    let e = s3.get_object().bucket(B).key("dir/obj one.bin").range("bytes=300000-").send().await.unwrap_err();
    assert_eq!(code(&e), "InvalidRange");

    // conditional GET
    let e = s3.get_object().bucket(B).key("dir/obj one.bin").if_none_match(&et).send().await.unwrap_err();
    assert_eq!(status(&e), 304);
    let e = s3.get_object().bucket(B).key("dir/obj one.bin").if_match("\"nope\"").send().await.unwrap_err();
    assert_eq!(status(&e), 412);

    // missing objects
    let e = s3.get_object().bucket(B).key("nope").send().await.unwrap_err();
    assert_eq!(code(&e), "NoSuchKey");
    let e = s3.head_object().bucket(B).key("nope").send().await.unwrap_err();
    assert_eq!(status(&e), 404);

    // empty object
    s3.put_object().bucket(B).key("empty").body(ByteStream::from_static(b"")).send().await.unwrap();
    let g = s3.get_object().bucket(B).key("empty").send().await.unwrap();
    assert_eq!(g.content_length(), Some(0));
    assert!(body(g).await.is_empty());

    // overwrite without metadata drops the old metadata
    s3.put_object().bucket(B).key("dir/obj one.bin").body(ByteStream::from_static(b"v2")).send().await.unwrap();
    let h = s3.head_object().bucket(B).key("dir/obj one.bin").send().await.unwrap();
    assert!(h.metadata().map(|m| m.is_empty()).unwrap_or(true));
    assert_eq!(h.content_length(), Some(2));

    // public prefix stored in plaintext, private data never
    let secret = data(5000, 7);
    let public = data(5000, 8);
    s3.put_object().bucket(B).key("private/x").body(ByteStream::from(secret.clone())).send().await.unwrap();
    s3.put_object().bucket(B).key("public/weights.bin").body(ByteStream::from(public.clone())).send().await.unwrap();
    let (mut saw_secret, mut saw_public) = (false, false);
    for f in walk(env.gw_dir.path().join("chunks")) {
        let b = std::fs::read(f).unwrap();
        saw_secret |= b.windows(64).any(|w| w == &secret[..64]);
        saw_public |= b.windows(64).any(|w| w == &public[..64]);
    }
    assert!(!saw_secret, "private plaintext reached the backend");
    assert!(saw_public, "public prefix should be stored unencrypted");
    let g = s3.get_object().bucket(B).key("public/weights.bin").send().await.unwrap();
    assert_eq!(body(g).await, public);

    // reserved / invalid keys
    let e = s3.put_object().bucket(B).key("x.drive-s3meta").body(ByteStream::from_static(b"x")).send().await.unwrap_err();
    assert_eq!(code(&e), "InvalidArgument");
    let e = s3.put_object().bucket(B).key("a//b").body(ByteStream::from_static(b"x")).send().await.unwrap_err();
    assert_eq!(code(&e), "InvalidArgument");
}

#[tokio::test]
async fn list_v2_v1_delimiter_pagination_and_delete() {
    let env = start().await;
    let s3 = &env.s3;
    let keys = ["a/1", "a/2", "a/sub/3", "b/x", "c", "d+e f", "z.txt"];
    for k in keys {
        s3.put_object().bucket(B).key(k).metadata("k", k.replace(['+', ' '], "_")).body(ByteStream::from(k.as_bytes().to_vec())).send().await.unwrap();
    }
    let all = s3.list_objects_v2().bucket(B).send().await.unwrap();
    let got: Vec<_> = all.contents().iter().map(|o| o.key().unwrap().to_string()).collect();
    assert_eq!(got, keys); // sidecars hidden, sorted
    assert_eq!(all.key_count(), Some(7));
    let o = &all.contents()[4];
    assert_eq!(o.size(), Some(1));
    let head = s3.head_object().bucket(B).key("c").send().await.unwrap();
    assert_eq!(o.e_tag(), head.e_tag());

    let d = s3.list_objects_v2().bucket(B).delimiter("/").send().await.unwrap();
    let files: Vec<_> = d.contents().iter().map(|o| o.key().unwrap()).collect();
    let dirs: Vec<_> = d.common_prefixes().iter().map(|p| p.prefix().unwrap()).collect();
    assert_eq!(files, ["c", "d+e f", "z.txt"]);
    assert_eq!(dirs, ["a/", "b/"]);

    let d = s3.list_objects_v2().bucket(B).prefix("a/").delimiter("/").send().await.unwrap();
    assert_eq!(d.contents().iter().map(|o| o.key().unwrap()).collect::<Vec<_>>(), ["a/1", "a/2"]);
    assert_eq!(d.common_prefixes().iter().map(|p| p.prefix().unwrap()).collect::<Vec<_>>(), ["a/sub/"]);

    // pagination: max-keys=2 with delimiter, via the SDK paginator
    let mut seen = vec![];
    let mut pages = s3.list_objects_v2().bucket(B).delimiter("/").max_keys(2).into_paginator().send();
    let mut n = 0;
    while let Some(p) = pages.next().await {
        let p = p.unwrap();
        n += 1;
        seen.extend(p.contents().iter().map(|o| o.key().unwrap().to_string()));
        seen.extend(p.common_prefixes().iter().map(|o| o.prefix().unwrap().to_string()));
    }
    seen.sort();
    assert_eq!(n, 3);
    assert_eq!(seen, ["a/", "b/", "c", "d+e f", "z.txt"]);

    let sa = s3.list_objects_v2().bucket(B).start_after("b/x").send().await.unwrap();
    assert_eq!(sa.contents().iter().map(|o| o.key().unwrap()).collect::<Vec<_>>(), ["c", "d+e f", "z.txt"]);

    // v1
    let v1 = s3.list_objects().bucket(B).max_keys(3).send().await.unwrap();
    assert_eq!(v1.contents().len(), 3);
    assert_eq!(v1.is_truncated(), Some(true));
    let v1b = s3.list_objects().bucket(B).marker(v1.contents()[2].key().unwrap()).send().await.unwrap();
    assert_eq!(v1b.contents().len(), 4);

    // delete one, then batch
    s3.delete_object().bucket(B).key("c").send().await.unwrap();
    s3.delete_object().bucket(B).key("never-existed").send().await.unwrap();
    let del = Delete::builder()
        .set_objects(Some(["a/1", "a/2", "a/sub/3", "b/x", "d+e f", "missing"].iter().map(|k| ObjectIdentifier::builder().key(*k).build().unwrap()).collect()))
        .build()
        .unwrap();
    let r = s3.delete_objects().bucket(B).delete(del).send().await.unwrap();
    assert_eq!(r.deleted().len(), 6);
    assert!(r.errors().is_empty());
    let left = s3.list_objects_v2().bucket(B).send().await.unwrap();
    assert_eq!(left.contents().iter().map(|o| o.key().unwrap()).collect::<Vec<_>>(), ["z.txt"]);
    // sidecars of deleted objects are gone too
    let bk = s3.list_objects_v2().bucket(B).prefix("a/").send().await.unwrap();
    assert_eq!(bk.key_count(), Some(0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn list_pages_2500_keys() {
    use futures_util::StreamExt;
    let env = start().await;
    let s3 = &env.s3;
    // 2000 top-level keys + 500 under 10 folders; every 7th has metadata (a hidden sidecar)
    let keys: Vec<String> = (0..2500).map(|i| if i < 2000 { format!("f{i:04}") } else { format!("d{}/x{i}", i % 10) }).collect();
    futures_util::stream::iter(keys.iter().enumerate())
        .for_each_concurrent(32, |(i, k)| async move {
            let mut put = s3.put_object().bucket(B).key(k).body(ByteStream::from(k.as_bytes().to_vec()));
            if i % 7 == 0 {
                put = put.metadata("n", i.to_string());
            }
            put.send().await.unwrap();
        })
        .await;
    let mut sorted = keys.clone();
    sorted.sort();

    // v2, no delimiter: 1000 + 1000 + 500
    let mut pages = s3.list_objects_v2().bucket(B).max_keys(1000).into_paginator().send();
    let (mut seen, mut sizes) = (vec![], vec![]);
    while let Some(p) = pages.next().await {
        let p = p.unwrap();
        sizes.push(p.contents().len());
        seen.extend(p.contents().iter().map(|o| o.key().unwrap().to_string()));
    }
    assert_eq!(sizes, [1000, 1000, 500]);
    assert_eq!(seen, sorted);

    // v2 with delimiter: 2000 files + 10 folders
    let mut pages = s3.list_objects_v2().bucket(B).delimiter("/").max_keys(1000).into_paginator().send();
    let (mut files, mut dirs, mut sizes) = (vec![], vec![], vec![]);
    while let Some(p) = pages.next().await {
        let p = p.unwrap();
        sizes.push(p.contents().len() + p.common_prefixes().len());
        files.extend(p.contents().iter().map(|o| o.key().unwrap().to_string()));
        dirs.extend(p.common_prefixes().iter().map(|o| o.prefix().unwrap().to_string()));
    }
    assert_eq!(sizes, [1000, 1000, 10]);
    assert_eq!(files, keys[..2000]);
    assert_eq!(dirs, (0..10).map(|d| format!("d{d}/")).collect::<Vec<_>>());

    // continuation from the middle of a folder, and start-after a common prefix
    let p = s3.list_objects_v2().bucket(B).prefix("d3/").max_keys(20).send().await.unwrap();
    assert_eq!((p.contents().len(), p.is_truncated()), (20, Some(true)));
    let p2 = s3.list_objects_v2().bucket(B).prefix("d3/").continuation_token(p.next_continuation_token().unwrap()).send().await.unwrap();
    assert_eq!((p2.contents().len(), p2.is_truncated()), (30, Some(false)));
    let p = s3.list_objects_v2().bucket(B).delimiter("/").start_after("d4/").send().await.unwrap();
    assert_eq!(p.common_prefixes().iter().map(|o| o.prefix().unwrap()).collect::<Vec<_>>(), ["d5/", "d6/", "d7/", "d8/", "d9/"]);
    assert_eq!(p.contents().len(), 995, "max-keys defaults to 1000");

    // v1 with marker / NextMarker and a delimiter
    let (mut marker, mut n, mut total) = (None::<String>, 0, 0);
    loop {
        let r = s3.list_objects().bucket(B).delimiter("/").max_keys(700).set_marker(marker.clone()).send().await.unwrap();
        n += 1;
        total += r.contents().len() + r.common_prefixes().len();
        if r.is_truncated() != Some(true) {
            break;
        }
        marker = Some(r.next_marker().unwrap().to_string());
    }
    assert_eq!((n, total), (3, 2010));
}

#[tokio::test]
async fn multipart_copy_and_buckets() {
    let env = start().await;
    let s3 = &env.s3;
    let key = "ckpt/model.safetensors";
    let up = s3.create_multipart_upload().bucket(B).key(key).content_type("application/octet-stream").metadata("step", "100").send().await.unwrap();
    let id = up.upload_id().unwrap().to_string();
    let p1 = data(300_000, 11);
    let p2 = data(123_457, 12);
    let mut parts = vec![];
    for (i, p) in [&p1, &p2].iter().enumerate() {
        let r = s3
            .upload_part()
            .bucket(B)
            .key(key)
            .upload_id(&id)
            .part_number(i as i32 + 1)
            .body(ByteStream::from((*p).clone()))
            .send()
            .await
            .unwrap();
        parts.push(CompletedPart::builder().part_number(i as i32 + 1).e_tag(r.e_tag().unwrap()).build());
    }
    let lp = s3.list_parts().bucket(B).key(key).upload_id(&id).send().await.unwrap();
    assert_eq!(lp.parts().len(), 2);
    assert_eq!(lp.parts()[1].size(), Some(123_457));
    let lu = s3.list_multipart_uploads().bucket(B).send().await.unwrap();
    assert_eq!(lu.uploads().len(), 1);

    // wrong etag -> InvalidPart
    let bad = CompletedMultipartUpload::builder()
        .parts(CompletedPart::builder().part_number(1).e_tag("\"0000\"").build())
        .build();
    let e = s3.complete_multipart_upload().bucket(B).key(key).upload_id(&id).multipart_upload(bad).send().await.unwrap_err();
    assert_eq!(code(&e), "InvalidPart");

    let done = s3
        .complete_multipart_upload()
        .bucket(B)
        .key(key)
        .upload_id(&id)
        .multipart_upload(CompletedMultipartUpload::builder().set_parts(Some(parts)).build())
        .send()
        .await
        .unwrap();
    let g = s3.get_object().bucket(B).key(key).send().await.unwrap();
    assert_eq!(g.e_tag(), done.e_tag());
    assert_eq!(g.metadata().unwrap().get("step").map(String::as_str), Some("100"));
    assert_eq!(body(g).await, [p1.clone(), p2.clone()].concat());
    let e = s3.list_parts().bucket(B).key(key).upload_id(&id).send().await.unwrap_err();
    assert_eq!(code(&e), "NoSuchUpload");

    // abort
    let up2 = s3.create_multipart_upload().bucket(B).key("tmp").send().await.unwrap();
    let id2 = up2.upload_id().unwrap();
    s3.upload_part().bucket(B).key("tmp").upload_id(id2).part_number(1).body(ByteStream::from_static(b"zz")).send().await.unwrap();
    s3.abort_multipart_upload().bucket(B).key("tmp").upload_id(id2).send().await.unwrap();
    let e = s3.upload_part().bucket(B).key("tmp").upload_id(id2).part_number(2).body(ByteStream::from_static(b"zz")).send().await.unwrap_err();
    assert_eq!(code(&e), "NoSuchUpload");
    assert!(s3.list_multipart_uploads().bucket(B).send().await.unwrap().uploads().is_empty());

    // copy (metadata COPY then REPLACE)
    let c = s3.copy_object().bucket(B).key("copy/of-model").copy_source(format!("{B}/{key}")).send().await.unwrap();
    let ce = c.copy_object_result().unwrap().e_tag().unwrap().to_string();
    let g = s3.get_object().bucket(B).key("copy/of-model").send().await.unwrap();
    assert_eq!(g.e_tag(), Some(ce.as_str()));
    assert_eq!(g.metadata().unwrap().get("step").map(String::as_str), Some("100"));
    assert_eq!(body(g).await.len(), p1.len() + p2.len());
    s3.copy_object()
        .bucket(B)
        .key("copy/of-model")
        .copy_source(format!("{B}/copy/of-model"))
        .metadata_directive(aws_sdk_s3::types::MetadataDirective::Replace)
        .metadata("step", "200")
        .content_type("text/plain")
        .send()
        .await
        .unwrap();
    let h = s3.head_object().bucket(B).key("copy/of-model").send().await.unwrap();
    assert_eq!(h.metadata().unwrap().get("step").map(String::as_str), Some("200"));
    assert_eq!(h.content_type(), Some("text/plain"));
    let e = s3.copy_object().bucket(B).key("x").copy_source(format!("{B}/missing")).send().await.unwrap_err();
    assert_eq!(code(&e), "NoSuchKey");

    // buckets
    let lb = s3.list_buckets().send().await.unwrap();
    assert_eq!(lb.buckets().iter().map(|b| b.name().unwrap()).collect::<Vec<_>>(), ["alice.near", "shared.near"]);
    s3.create_bucket().bucket(B).send().await.unwrap();
    s3.head_bucket().bucket(B).send().await.unwrap();
    let e = s3.create_bucket().bucket("someone-else.near").send().await.unwrap_err();
    assert_eq!(code(&e), "BucketAlreadyExists");
    let e = s3.create_bucket().bucket("Bad_Name").send().await.unwrap_err();
    assert_eq!(code(&e), "InvalidBucketName");
    let loc = s3.get_bucket_location().bucket(B).send().await.unwrap();
    assert!(loc.location_constraint().is_none() || loc.location_constraint().unwrap().as_str().is_empty());
    let e = s3.delete_bucket().bucket(B).send().await.unwrap_err();
    assert_eq!(code(&e), "BucketNotEmpty");

    // other namespaces: gateway policy decides (shared.near/inbox/ is world-writable)
    s3.put_object().bucket("shared.near").key("inbox/hi").body(ByteStream::from_static(b"hi")).send().await.unwrap();
    let g = s3.get_object().bucket("shared.near").key("inbox/hi").send().await.unwrap();
    assert_eq!(body(g).await, b"hi");
    let e = s3.put_object().bucket("shared.near").key("private/x").body(ByteStream::from_static(b"x")).send().await.unwrap_err();
    assert_eq!(code(&e), "AccessDenied");
}

#[tokio::test]
async fn checksums_from_sdk() {
    let env = start().await;
    let s3 = &env.s3;
    for alg in [ChecksumAlgorithm::Crc32, ChecksumAlgorithm::Crc32C, ChecksumAlgorithm::Crc64Nvme, ChecksumAlgorithm::Sha1, ChecksumAlgorithm::Sha256] {
        let key = format!("ck/{}", alg.as_str());
        let d = data(70_000, 3);
        let r = s3.put_object().bucket(B).key(&key).checksum_algorithm(alg.clone()).body(ByteStream::from(d.clone())).send().await.unwrap();
        assert!(r.e_tag().is_some());
        // the verified checksum is echoed back
        let echoed = r.checksum_crc32().or(r.checksum_crc32_c()).or(r.checksum_crc64_nvme()).or(r.checksum_sha1()).or(r.checksum_sha256());
        assert_eq!(echoed, near_drive_s3::sigv4::compute_checksum(&alg.as_str().to_ascii_lowercase(), &d).as_deref(), "{alg:?}");
        let g = s3.get_object().bucket(B).key(&key).send().await.unwrap();
        assert_eq!(body(g).await, d, "{alg:?}");
    }
}

#[tokio::test]
async fn auth_presigned_bad_signatures_and_streaming() {
    let env = start().await;
    let s3 = &env.s3;
    s3.put_object().bucket(B).key("p/file.txt").body(ByteStream::from_static(b"presigned body")).send().await.unwrap();
    let http = reqwest::Client::new();

    // presigned GET
    let ps = s3.get_object().bucket(B).key("p/file.txt").presigned(PresigningConfig::expires_in(Duration::from_secs(300)).unwrap()).await.unwrap();
    let r = http.get(ps.uri()).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.bytes().await.unwrap().as_ref(), b"presigned body");
    // tampered presigned URL
    let tampered = ps.uri().replace("p/file.txt", "p/other.txt");
    let r = http.get(&tampered).send().await.unwrap();
    assert_eq!(r.status(), 403);
    assert!(r.text().await.unwrap().contains("<Code>SignatureDoesNotMatch</Code>"));

    // presigned PUT
    let ps = s3.put_object().bucket(B).key("p/up.txt").presigned(PresigningConfig::expires_in(Duration::from_secs(300)).unwrap()).await.unwrap();
    let mut req = http.put(ps.uri()).body("via presigned put");
    for (k, v) in ps.headers() {
        req = req.header(k, v);
    }
    assert_eq!(req.send().await.unwrap().status(), 200);
    let g = s3.get_object().bucket(B).key("p/up.txt").send().await.unwrap();
    assert_eq!(body(g).await, b"via presigned put");

    // wrong secret / wrong access key / anonymous
    let bad = s3_client(&env.url, AK, "wrong-secret");
    let e = bad.get_object().bucket(B).key("p/file.txt").send().await.unwrap_err();
    assert_eq!(code(&e), "SignatureDoesNotMatch");
    let e = bad.put_object().bucket(B).key("p/evil").body(ByteStream::from_static(b"x")).send().await.unwrap_err();
    assert_eq!(code(&e), "SignatureDoesNotMatch");
    let bad = s3_client(&env.url, "NSTWRONGACCESSKEY000", SK);
    let e = bad.list_objects_v2().bucket(B).send().await.unwrap_err();
    assert_eq!(code(&e), "InvalidAccessKeyId");
    let r = http.get(format!("{}/{B}/p/file.txt", env.url)).send().await.unwrap();
    assert_eq!(r.status(), 403);
    assert!(r.text().await.unwrap().contains("<Code>AccessDenied</Code>"));

    let creds = sigv4::Credentials { access_key: AK.into(), secret_key: SK.into() };
    let host = env.url.trim_start_matches("http://").to_string();
    let amz = |secs_ago: u64| {
        let t = std::time::SystemTime::now() - Duration::from_secs(secs_ago);
        let iso = near_drive_s3::xml::iso8601(t.duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64);
        format!("{}{}{}T{}{}{}Z", &iso[0..4], &iso[5..7], &iso[8..10], &iso[11..13], &iso[14..16], &iso[17..19])
    };
    let empty_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    // clock skew > 15 min
    let d = amz(20 * 60);
    let (authz, _) = sigv4::client::authorization(&creds, "GET", "/alice.near/p/file.txt", "", &[("host", &host), ("x-amz-content-sha256", empty_sha), ("x-amz-date", &d)], empty_sha, &d, "us-east-1");
    let r = http
        .get(format!("{}/alice.near/p/file.txt", env.url))
        .header("authorization", authz)
        .header("x-amz-content-sha256", empty_sha)
        .header("x-amz-date", &d)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    assert!(r.text().await.unwrap().contains("RequestTimeTooSkewed"));

    // signed payload hash that does not match the body
    let d = amz(0);
    let claimed = "0000000000000000000000000000000000000000000000000000000000000000";
    let (authz, _) = sigv4::client::authorization(&creds, "PUT", "/alice.near/p/x", "", &[("host", &host), ("x-amz-content-sha256", claimed), ("x-amz-date", &d)], claimed, &d, "us-east-1");
    let r = http
        .put(format!("{}/alice.near/p/x", env.url))
        .header("authorization", authz)
        .header("x-amz-content-sha256", claimed)
        .header("x-amz-date", &d)
        .body("hello")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    assert!(r.text().await.unwrap().contains("XAmzContentSHA256Mismatch"));

    // STREAMING-AWS4-HMAC-SHA256-PAYLOAD with chunk signatures (what older
    // boto3 / aws-cli / Java SDK v1 send over plain http)
    let payload = data(150_000, 5);
    let mode = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
    let send_streaming = |tamper: bool| {
        let d = amz(0);
        let enc_len = sigv4::client::chunked_signed(&creds, &d, "us-east-1", "0", &payload, 65536).len().to_string();
        let dlen = payload.len().to_string();
        let headers = [
            ("content-encoding", "aws-chunked"),
            ("content-length", enc_len.as_str()),
            ("host", host.as_str()),
            ("x-amz-content-sha256", mode),
            ("x-amz-date", d.as_str()),
            ("x-amz-decoded-content-length", dlen.as_str()),
        ];
        let (authz, seed) = sigv4::client::authorization(&creds, "PUT", "/alice.near/stream/obj", "", &headers, mode, &d, "us-east-1");
        let mut body = sigv4::client::chunked_signed(&creds, &d, "us-east-1", &seed, &payload, 65536);
        if tamper {
            body[70_000] ^= 1;
        }
        let mut req = http.put(format!("{}/alice.near/stream/obj", env.url)).header("authorization", authz);
        for (k, v) in headers {
            if k != "host" && k != "content-length" {
                req = req.header(k, v);
            }
        }
        req.body(body).send()
    };
    let r = send_streaming(true).await.unwrap();
    assert_eq!(r.status(), 403);
    assert!(r.text().await.unwrap().contains("SignatureDoesNotMatch"));
    let r = send_streaming(false).await.unwrap();
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    let g = s3.get_object().bucket(B).key("stream/obj").send().await.unwrap();
    assert_eq!(body(g).await, payload);

    // STREAMING-UNSIGNED-PAYLOAD-TRAILER with a CRC64NVME trailer (botocore >= 1.36 default shape)
    let mode = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";
    let send_trailer = |crc: String| {
        let d = amz(0);
        let body = format!("{:x}\r\n{}\r\n0\r\nx-amz-checksum-crc64nvme:{crc}\r\n\r\n", 11, "hello world");
        let headers = [
            ("content-encoding", "aws-chunked"),
            ("host", host.as_str()),
            ("x-amz-content-sha256", mode),
            ("x-amz-date", d.as_str()),
            ("x-amz-decoded-content-length", "11"),
            ("x-amz-trailer", "x-amz-checksum-crc64nvme"),
        ];
        let (authz, _) = sigv4::client::authorization(&creds, "PUT", "/alice.near/trailer/obj", "", &headers, mode, &d, "us-east-1");
        let mut req = http.put(format!("{}/alice.near/trailer/obj", env.url)).header("authorization", authz);
        for (k, v) in headers {
            if k != "host" {
                req = req.header(k, v);
            }
        }
        req.body(body).send()
    };
    let r = send_trailer("AAAAAAAAAAA=".into()).await.unwrap();
    assert_eq!(r.status(), 400);
    assert!(r.text().await.unwrap().contains("BadDigest"));
    let good = sigv4::compute_checksum("crc64nvme", b"hello world").unwrap();
    let r = send_trailer(good.clone()).await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["x-amz-checksum-crc64nvme"].to_str().unwrap(), good);
    let g = s3.get_object().bucket(B).key("trailer/obj").send().await.unwrap();
    assert_eq!(body(g).await, b"hello world");

    // virtual-host style: <bucket>.localhost
    let port = env.url.rsplit(':').next().unwrap();
    let vh = s3_client_vhost(port);
    vh.put_object().bucket(B).key("vh/key").body(ByteStream::from_static(b"vhost")).send().await.unwrap_or_else(|e| panic!("{e:?}"));
    let g = s3.get_object().bucket(B).key("vh/key").send().await.unwrap();
    assert_eq!(body(g).await, b"vhost");
}

#[tokio::test]
async fn large_objects_stream_and_foreign_keys() {
    let env = start().await;
    let s3 = &env.s3;
    // > STREAM_THRESHOLD: GET is streamed to the client
    let big = data(9 * 1024 * 1024 + 4321, 21);
    s3.put_object().bucket(B).key("big/blob").metadata("m", "1").body(ByteStream::from(big.clone())).send().await.unwrap();
    let g = s3.get_object().bucket(B).key("big/blob").send().await.unwrap();
    assert_eq!(g.content_length(), Some(big.len() as i64));
    assert_eq!(body(g).await, big);
    // large range (streamed) and small range (buffered) not chunk-aligned
    let r = s3.get_object().bucket(B).key("big/blob").range("bytes=1000-9000999").send().await.unwrap();
    assert_eq!(body(r).await, &big[1000..9_001_000]);
    let r = s3.get_object().bucket(B).key("big/blob").range("bytes=65530-65545").send().await.unwrap();
    assert_eq!(body(r).await, &big[65530..65546]);
    // large copy goes through a spooled temp file
    s3.copy_object().bucket(B).key("big/copy").copy_source(format!("{B}/big/blob")).send().await.unwrap();
    let g = s3.get_object().bucket(B).key("big/copy").send().await.unwrap();
    assert_eq!(g.metadata().unwrap().get("m").map(String::as_str), Some("1"));
    assert_eq!(body(g).await, big);

    // objects encrypted to a different root key -> AccessDenied (small and streamed paths)
    let mut other = Client::new(&env.gw_url, "alice.near", env.alice.clone(), Some(RootKey::from_bytes([1; 32]))).with_writer_check(near_drive_client::WriterCheck::Trusted(near_drive_client::TrustedWriters::new().key("alice.near", RootKey::from_bytes([9; 32]).sign_public_key()).key("alice.near", RootKey::from_bytes([1; 32]).sign_public_key()).rules("shared.near", serde_json::from_str(SHARED_RULES).unwrap())));
    other.chunk_size = 64 * 1024;
    let opts = near_drive_client::PutOptions::default();
    other.put(&near_drive_client::near_drive_core::NearUri::parse("near://alice.near/foreign/small").unwrap(), b"x", &opts).await.unwrap();
    other.put(&near_drive_client::near_drive_core::NearUri::parse("near://alice.near/foreign/big").unwrap(), &big, &opts).await.unwrap();
    for k in ["foreign/small", "foreign/big"] {
        let e = s3.get_object().bucket(B).key(k).send().await.unwrap_err();
        assert_eq!(code(&e), "AccessDenied", "{k}");
    }
}

/// Virtual-host addressing: the SDK sends `Host: alice.near.localhost:<port>`
/// (`*.localhost` resolves to loopback).
fn s3_client_vhost(port: &str) -> S3 {
    let conf = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .endpoint_url(format!("http://localhost:{port}"))
        .credentials_provider(AwsCreds::new(AK, SK, None, None, "test"))
        .force_path_style(false)
        .build();
    S3::from_conf(conf)
}

fn walk(p: std::path::PathBuf) -> Vec<std::path::PathBuf> {
    let mut out = vec![];
    if let Ok(rd) = std::fs::read_dir(&p) {
        for e in rd.flatten() {
            let path = e.path();
            if path.is_dir() {
                out.extend(walk(path))
            } else {
                out.push(path)
            }
        }
    }
    out
}

/// Multipart parts stream into the object: in-order parts never touch the
/// staging disk, out-of-order parts are staged only until their turn, and
/// the result is byte-exact with odd part sizes.
#[tokio::test]
async fn multipart_streams_out_of_order_and_retries() {
    let env = start().await;
    let s3 = &env.s3;
    let staging = env._home.path().join("s3-staging");
    let key = "ckpt/streamed.bin";
    // 5 parts of 150_001 bytes (not a multiple of the 64 KiB chunk size) + a short last part.
    let sizes = [150_001usize, 150_001, 150_001, 150_001, 150_001, 7];
    let parts: Vec<Vec<u8>> = sizes.iter().enumerate().map(|(i, n)| data(*n, 100 + i as u32)).collect();
    let up = s3.create_multipart_upload().bucket(B).key(key).metadata("run", "7").send().await.unwrap();
    let id = up.upload_id().unwrap().to_string();
    let put = |n: i32| {
        let (s3, id, body) = (s3.clone(), id.clone(), parts[(n - 1) as usize].clone());
        async move { s3.upload_part().bucket(B).key(key).upload_id(id).part_number(n).body(ByteStream::from(body)).send().await.unwrap().e_tag().unwrap().to_string() }
    };
    // Part 1 in order: streamed, nothing staged.
    let e1 = put(1).await;
    let staged = |d: &std::path::Path| walk(d.to_path_buf()).into_iter().filter(|p| p.extension().is_some_and(|e| e == "part")).count();
    assert_eq!(staged(&staging), 0, "an in-order part is streamed, not staged");
    // Parts 4 and 3 arrive early: staged until 2 comes, then drained.
    let e4 = put(4).await;
    let e3 = put(3).await;
    assert_eq!(staged(&staging), 2);
    let e2 = put(2).await;
    assert_eq!(staged(&staging), 0, "staged parts drained once their turn came");
    // Identical retry of a streamed part: accepted. Different bytes: refused.
    assert_eq!(put(2).await, e2);
    let e = s3.upload_part().bucket(B).key(key).upload_id(&id).part_number(2).body(ByteStream::from(vec![1u8; 10])).send().await.unwrap_err();
    assert_eq!(code(&e), "InvalidPart");
    // The rest concurrently.
    let (e5, e6) = tokio::join!(put(5), put(6));
    let lp = s3.list_parts().bucket(B).key(key).upload_id(&id).send().await.unwrap();
    assert_eq!(lp.parts().iter().map(|p| p.part_number().unwrap()).collect::<Vec<_>>(), vec![1, 2, 3, 4, 5, 6]);
    // Leaving out a part that was already streamed is refused.
    let mk = |v: &[(i32, &String)]| CompletedMultipartUpload::builder().set_parts(Some(v.iter().map(|(n, e)| CompletedPart::builder().part_number(*n).e_tag(e.as_str()).build()).collect())).build();
    let e = s3.complete_multipart_upload().bucket(B).key(key).upload_id(&id).multipart_upload(mk(&[(1, &e1), (3, &e3)])).send().await.unwrap_err();
    assert_eq!(code(&e), "InvalidPart");
    s3.complete_multipart_upload()
        .bucket(B)
        .key(key)
        .upload_id(&id)
        .multipart_upload(mk(&[(1, &e1), (2, &e2), (3, &e3), (4, &e4), (5, &e5), (6, &e6)]))
        .send()
        .await
        .unwrap();
    let got = s3.get_object().bucket(B).key(key).send().await.unwrap();
    assert_eq!(got.metadata().unwrap().get("run").map(String::as_str), Some("7"));
    assert_eq!(body(got).await, parts.concat());
    let r = s3.get_object().bucket(B).key(key).range("bytes=150000-300003").send().await.unwrap();
    assert_eq!(body(r).await, parts.concat()[150_000..=300_003]);
    assert!(s3.list_multipart_uploads().bucket(B).send().await.unwrap().uploads().is_empty());
    assert_eq!(walk(staging.clone()).len(), 0, "nothing left in staging");

    // Parts sent with gaps in numbering (1, 3) complete from staging at the end.
    let up = s3.create_multipart_upload().bucket(B).key("gaps").send().await.unwrap();
    let id = up.upload_id().unwrap().to_string();
    let a = s3.upload_part().bucket(B).key("gaps").upload_id(&id).part_number(1).body(ByteStream::from(data(70_000, 1))).send().await.unwrap().e_tag().unwrap().to_string();
    let b = s3.upload_part().bucket(B).key("gaps").upload_id(&id).part_number(3).body(ByteStream::from(data(9, 2))).send().await.unwrap().e_tag().unwrap().to_string();
    s3.complete_multipart_upload().bucket(B).key("gaps").upload_id(&id).multipart_upload(mk(&[(1, &a), (3, &b)])).send().await.unwrap();
    let got = body(s3.get_object().bucket(B).key("gaps").send().await.unwrap()).await;
    assert_eq!(got, [data(70_000, 1), data(9, 2)].concat());
}

/// deltaleague's setup: existing bucket names served from NEAR Drive folders,
/// presigned GET / PUT URLs used by plain HTTP clients (GPU workers, browsers),
/// CORS for the browser upload, and virtual-host addressing on a real domain.
#[tokio::test]
async fn bucket_aliases_presigned_urls_cors_and_vhost() {
    use near_drive_s3::backend::Alias;
    let env = start_cfg(|c| {
        c.aliases.insert("delta-artifacts".into(), Alias::parse("near://alice.near/artifacts/").unwrap());
        c.aliases.insert("delta-private".into(), Alias::parse("near://alice.near/private/").unwrap());
        c.cors_origins = vec!["https://portal.example".into()];
        c.vhost_domains.push("s3.test".into());
    })
    .await;
    let s3 = &env.s3;
    let http = reqwest::Client::new();

    // Existing bucket names work, and land in the NEAR Drive folders.
    s3.put_object().bucket("delta-artifacts").key("verified/abc").body(ByteStream::from_static(b"model bytes")).send().await.unwrap();
    s3.put_object().bucket("delta-private").key("jobs/1/input.jsonl").body(ByteStream::from_static(b"prompts")).send().await.unwrap();
    let mut c = Client::new(&env.gw_url, "alice.near", env.alice.clone(), Some(RootKey::from_bytes([9; 32]))).with_writer_check(near_drive_client::WriterCheck::Trusted(near_drive_client::TrustedWriters::new().key("alice.near", RootKey::from_bytes([9; 32]).sign_public_key()).key("alice.near", RootKey::from_bytes([1; 32]).sign_public_key()).rules("shared.near", serde_json::from_str(SHARED_RULES).unwrap())));
    c.chunk_size = 64 * 1024;
    let u = |s: &str| near_drive_client::near_drive_core::NearUri::parse(s).unwrap();
    assert_eq!(c.get(&u("near://alice.near/artifacts/verified/abc")).await.unwrap().1, b"model bytes");
    assert_eq!(c.get(&u("near://alice.near/private/jobs/1/input.jsonl")).await.unwrap().1, b"prompts");
    let keys: Vec<String> = s3.list_objects_v2().bucket("delta-artifacts").send().await.unwrap().contents().iter().map(|o| o.key().unwrap().to_string()).collect();
    assert_eq!(keys, vec!["verified/abc"], "listing shows keys relative to the alias");
    let names: Vec<String> = s3.list_buckets().send().await.unwrap().buckets().iter().map(|b| b.name().unwrap().to_string()).collect();
    assert!(names.contains(&"delta-artifacts".to_string()) && names.contains(&"delta-private".to_string()), "{names:?}");

    // A worker downloads with a presigned GET (plain HTTP, no redirects) ...
    let pc = || PresigningConfig::expires_in(Duration::from_secs(7 * 24 * 3600)).unwrap();
    let get = s3.get_object().bucket("delta-artifacts").key("verified/abc").presigned(pc()).await.unwrap();
    let no_redirect = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    let r = no_redirect.get(get.uri()).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.bytes().await.unwrap().as_ref(), b"model bytes");
    let r = no_redirect.get(get.uri()).header("range", "bytes=6-10").send().await.unwrap();
    assert_eq!((r.status().as_u16(), r.bytes().await.unwrap().to_vec()), (206, b"bytes".to_vec()));
    // ... and uploads its result with a presigned PUT.
    let put = s3.put_object().bucket("delta-private").key("jobs/1/output.jsonl").presigned(pc()).await.unwrap();
    let mut req = http.put(put.uri()).body("answers");
    for (k, v) in put.headers() {
        req = req.header(k, v);
    }
    assert_eq!(req.send().await.unwrap().status(), 200);
    assert_eq!(c.get(&u("near://alice.near/private/jobs/1/output.jsonl")).await.unwrap().1, b"answers");
    // A presigned URL only works for what it was signed for.
    let tampered = put.uri().replace("output.jsonl", "other.jsonl");
    assert_eq!(http.put(tampered).body("x").send().await.unwrap().status(), 403);

    // Browser upload from the portal: preflight, then the presigned PUT with CORS headers.
    let pre = http
        .request(reqwest::Method::OPTIONS, format!("{}/delta-artifacts/staging/up.bin", env.url))
        .header("origin", "https://portal.example")
        .header("access-control-request-method", "PUT")
        .header("access-control-request-headers", "content-type")
        .send()
        .await
        .unwrap();
    assert_eq!(pre.status(), 200);
    assert_eq!(pre.headers()["access-control-allow-origin"], "https://portal.example");
    assert!(pre.headers()["access-control-allow-methods"].to_str().unwrap().contains("PUT"));
    let other = http
        .request(reqwest::Method::OPTIONS, format!("{}/delta-artifacts/staging/up.bin", env.url))
        .header("origin", "https://evil.example")
        .header("access-control-request-method", "PUT")
        .send()
        .await
        .unwrap();
    assert_eq!(other.status(), 403);
    let up = s3.put_object().bucket("delta-artifacts").key("staging/up.bin").presigned(pc()).await.unwrap();
    let mut req = http.put(up.uri()).header("origin", "https://portal.example").body(vec![7u8; 200_000]);
    for (k, v) in up.headers() {
        req = req.header(k, v);
    }
    let r = req.send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["access-control-allow-origin"], "https://portal.example");
    assert!(r.headers()["access-control-expose-headers"].to_str().unwrap().contains("ETag"));

    // Virtual-host addressing on a configured domain: <bucket>.s3.test
    let port = env.url.rsplit(':').next().unwrap().to_string();
    let vconf = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .endpoint_url(format!("http://s3.test:{port}"))
        .credentials_provider(AwsCreds::new(AK, SK, None, None, "test"))
        .force_path_style(false)
        .build();
    let vs3 = S3::from_conf(vconf);
    let vget = vs3.get_object().bucket("delta-artifacts").key("verified/abc").presigned(pc()).await.unwrap();
    assert!(vget.uri().starts_with(&format!("http://delta-artifacts.s3.test:{port}/verified/abc")), "{}", vget.uri());
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let resolving = reqwest::Client::builder().resolve("delta-artifacts.s3.test", addr).build().unwrap();
    let r = resolving.get(vget.uri()).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.bytes().await.unwrap().as_ref(), b"model bytes");
}
