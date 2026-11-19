//! AWS Signature Version 4 verification (server side) for S3:
//! `Authorization` header and presigned-URL (query) auth, plus request body
//! decoding for every payload mode SDKs use:
//! - hex sha256 of the body (signed payload),
//! - `UNSIGNED-PAYLOAD`,
//! - `STREAMING-AWS4-HMAC-SHA256-PAYLOAD[-TRAILER]` (aws-chunked, every chunk
//!   signature and the trailer signature are verified),
//! - `STREAMING-UNSIGNED-PAYLOAD-TRAILER` (aws-chunked with an
//!   `x-amz-checksum-*` trailer; botocore >= 1.36 and recent AWS SDKs).
//!
//! `x-amz-checksum-{crc32,crc32c,crc64nvme,sha1,sha256}` (header or trailer)
//! and `Content-MD5` are verified against the decoded body.
//!
//! Legacy SigV2 (header and presigned query) is accepted too, see [`v2`].
use crate::error::{S3Error, S3Result};
use crate::xml::{parse_amz_date, percent_decode, uri_encode};
use axum::http::{HeaderMap, StatusCode};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

type HmacSha256 = Hmac<Sha256>;
type Trailers = Vec<(String, String)>;

pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";
/// Max clock difference between client and proxy.
pub const MAX_SKEW_SECS: i64 = 15 * 60;
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub access_key: String,
    pub secret_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    Unsigned,
    /// Hex sha256 the client committed to in the signature.
    Sha256(String),
    StreamingSigned { trailer: bool },
    StreamingUnsignedTrailer,
}

/// Result of a successful signature check; needed to verify streaming chunks.
#[derive(Debug, Clone)]
pub struct Auth {
    pub payload: Payload,
    pub presigned: bool,
    signing_key: [u8; 32],
    amz_date: String,
    scope: String,
    seed_signature: String,
}

pub struct Request<'a> {
    pub method: &'a str,
    pub raw_path: &'a str,
    pub raw_query: &'a str,
    pub headers: &'a HeaderMap,
}

fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().into()
}

pub fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
    let k = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k = hmac(&k, region.as_bytes());
    let k = hmac(&k, service.as_bytes());
    hmac(&k, b"aws4_request")
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// Constant-time compare of a computed MAC against a hex signature.
fn sig_matches(key: &[u8; 32], string_to_sign: &str, provided_hex: &str) -> bool {
    let Ok(provided) = hex::decode(provided_hex) else { return false };
    let mut m = HmacSha256::new_from_slice(key).expect("hmac key");
    m.update(string_to_sign.as_bytes());
    m.verify_slice(&provided).is_ok()
}

fn sign_hex(key: &[u8; 32], string_to_sign: &str) -> String {
    hex::encode(hmac(key, string_to_sign.as_bytes()))
}

fn header_str<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// Raw query → decoded `(key, value)` pairs in request order.
pub fn parse_query(raw: &str) -> Vec<(String, String)> {
    raw.split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (String::from_utf8_lossy(&percent_decode(k)).into_owned(), String::from_utf8_lossy(&percent_decode(v)).into_owned())
        })
        .collect()
}

fn canonical_query(raw: &str, skip_signature: bool) -> String {
    let mut pairs: Vec<(String, String)> = raw
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            let enc = |s: &str| {
                let d = percent_decode(s);
                let mut out = String::new();
                for b in d {
                    if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                        out.push(b as char);
                    } else {
                        out.push_str(&format!("%{b:02X}"));
                    }
                }
                out
            };
            (enc(k), enc(v))
        })
        .filter(|(k, _)| !(skip_signature && k == "X-Amz-Signature"))
        .collect();
    pairs.sort();
    pairs.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&")
}

/// Canonical URI candidates: S3 does not normalize paths, it re-encodes the
/// decoded path once. Fall back to the raw path for clients that encode
/// differently (e.g. leave `!` unescaped and sign that).
fn canonical_uris(raw_path: &str) -> Vec<String> {
    let decoded = percent_decode(raw_path);
    let mut out = String::new();
    for b in decoded {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    let path = if out.is_empty() { "/".to_string() } else { out };
    if path == raw_path {
        vec![path]
    } else {
        vec![path, raw_path.to_string()]
    }
}

fn canonical_headers(h: &HeaderMap, signed: &[&str]) -> S3Result<String> {
    let mut out = String::new();
    for name in signed {
        let vals: Vec<String> = h
            .get_all(*name)
            .iter()
            .map(|v| {
                let s = String::from_utf8_lossy(v.as_bytes());
                s.split_whitespace().collect::<Vec<_>>().join(" ")
            })
            .collect();
        if vals.is_empty() {
            return Err(S3Error::access_denied(format!("signed header {name} is missing from the request")));
        }
        out.push_str(name);
        out.push(':');
        out.push_str(&vals.join(","));
        out.push('\n');
    }
    Ok(out)
}

struct Scope<'a> {
    access_key: &'a str,
    date: &'a str,
    region: &'a str,
    service: &'a str,
}

fn parse_credential(c: &str) -> S3Result<Scope<'_>> {
    let parts: Vec<&str> = c.split('/').collect();
    if parts.len() != 5 || parts[4] != "aws4_request" {
        return Err(S3Error::new(StatusCode::BAD_REQUEST, "AuthorizationHeaderMalformed", "malformed credential scope"));
    }
    Ok(Scope { access_key: parts[0], date: parts[1], region: parts[2], service: parts[3] })
}

fn payload_mode(v: &str) -> S3Result<Payload> {
    Ok(match v {
        "UNSIGNED-PAYLOAD" => Payload::Unsigned,
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" => Payload::StreamingSigned { trailer: false },
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER" => Payload::StreamingSigned { trailer: true },
        "STREAMING-UNSIGNED-PAYLOAD-TRAILER" => Payload::StreamingUnsignedTrailer,
        v if v.starts_with("STREAMING-AWS4-ECDSA") => return Err(S3Error::not_implemented("SigV4a streaming payloads are not supported")),
        v if v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()) => Payload::Sha256(v.to_ascii_lowercase()),
        _ => return Err(S3Error::invalid_argument("x-amz-content-sha256 must be UNSIGNED-PAYLOAD, a STREAMING-* mode or a hex sha256")),
    })
}

#[allow(clippy::too_many_arguments)]
fn check_signature(
    req: &Request,
    creds: &Credentials,
    scope: &Scope,
    amz_date: &str,
    signed_headers: &str,
    payload_hash: &str,
    provided: &str,
    presigned: bool,
) -> S3Result<([u8; 32], String)> {
    if scope.access_key != creds.access_key {
        return Err(S3Error::invalid_access_key());
    }
    if scope.service != "s3" || amz_date.get(..8) != Some(scope.date) {
        return Err(S3Error::new(StatusCode::BAD_REQUEST, "AuthorizationHeaderMalformed", "credential scope does not match request date or service"));
    }
    let signed: Vec<&str> = signed_headers.split(';').filter(|s| !s.is_empty()).collect();
    if !signed.contains(&"host") {
        return Err(S3Error::access_denied("host must be a signed header"));
    }
    let headers = canonical_headers(req.headers, &signed)?;
    let query = canonical_query(req.raw_query, presigned);
    let scope_str = format!("{}/{}/{}/aws4_request", scope.date, scope.region, scope.service);
    let key = signing_key(&creds.secret_key, scope.date, scope.region, scope.service);
    for uri in canonical_uris(req.raw_path) {
        let creq = format!("{}\n{}\n{}\n{}\n{}\n{}", req.method, uri, query, headers, signed_headers, payload_hash);
        let sts = format!("{ALGORITHM}\n{amz_date}\n{scope_str}\n{}", sha256_hex(creq.as_bytes()));
        if sig_matches(&key, &sts, provided) {
            return Ok((key, scope_str));
        }
        tracing::debug!("signature mismatch; canonical request:\n{creq}");
    }
    Err(S3Error::signature_mismatch())
}

/// Verify a request's SigV4 signature. `now` is unix seconds.
pub fn authenticate(req: &Request, creds: &Credentials, now: i64) -> S3Result<Auth> {
    let query = parse_query(req.raw_query);
    let qget = |k: &str| query.iter().find(|(qk, _)| qk == k).map(|(_, v)| v.as_str());

    if let Some(authz) = header_str(req.headers, "authorization") {
        let Some(rest) = authz.strip_prefix(ALGORITHM) else {
            if let Some(v2) = authz.strip_prefix("AWS ") {
                return v2::header_auth(req, creds, v2, now);
            }
            return Err(S3Error::not_implemented("unsupported authorization algorithm (only AWS4-HMAC-SHA256)"));
        };
        let (mut cred, mut signed, mut sig) = (None, None, None);
        for part in rest.split(',') {
            let part = part.trim();
            if let Some(v) = part.strip_prefix("Credential=") {
                cred = Some(v);
            } else if let Some(v) = part.strip_prefix("SignedHeaders=") {
                signed = Some(v);
            } else if let Some(v) = part.strip_prefix("Signature=") {
                sig = Some(v);
            }
        }
        let malformed = || S3Error::new(StatusCode::BAD_REQUEST, "AuthorizationHeaderMalformed", "the authorization header is malformed");
        let (cred, signed, sig) = (cred.ok_or_else(malformed)?, signed.ok_or_else(malformed)?, sig.ok_or_else(malformed)?);
        let scope = parse_credential(cred)?;
        let amz_date = header_str(req.headers, "x-amz-date")
            .map(str::to_string)
            .or_else(|| {
                let d = header_str(req.headers, "date")?;
                let t = httpdate::parse_http_date(d).ok()?;
                let secs = t.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
                let iso = crate::xml::iso8601(secs * 1000);
                Some(format!("{}{}{}T{}{}{}Z", &iso[0..4], &iso[5..7], &iso[8..10], &iso[11..13], &iso[14..16], &iso[17..19]))
            })
            .ok_or_else(|| S3Error::access_denied("missing x-amz-date"))?;
        let t = parse_amz_date(&amz_date).ok_or_else(|| S3Error::access_denied("malformed x-amz-date"))?;
        if (now - t).abs() > MAX_SKEW_SECS {
            return Err(S3Error::skewed());
        }
        let payload_hash = header_str(req.headers, "x-amz-content-sha256")
            .ok_or_else(|| S3Error::invalid_request("missing required header x-amz-content-sha256"))?;
        let payload = payload_mode(payload_hash)?;
        let (key, scope_str) = check_signature(req, creds, &scope, &amz_date, signed, payload_hash, sig, false)?;
        return Ok(Auth { payload, presigned: false, signing_key: key, amz_date, scope: scope_str, seed_signature: sig.to_ascii_lowercase() });
    }

    if let Some(alg) = qget("X-Amz-Algorithm") {
        if alg != ALGORITHM {
            return Err(S3Error::not_implemented("unsupported X-Amz-Algorithm"));
        }
        let need = |k: &str| qget(k).ok_or_else(|| S3Error::access_denied(format!("presigned URL is missing {k}")));
        let (cred, amz_date, expires, signed, sig) =
            (need("X-Amz-Credential")?, need("X-Amz-Date")?, need("X-Amz-Expires")?, need("X-Amz-SignedHeaders")?, need("X-Amz-Signature")?);
        let scope = parse_credential(cred)?;
        let t = parse_amz_date(amz_date).ok_or_else(|| S3Error::access_denied("malformed X-Amz-Date"))?;
        let expires: i64 = expires.parse().map_err(|_| S3Error::access_denied("malformed X-Amz-Expires"))?;
        if !(1..=604_800).contains(&expires) {
            return Err(S3Error::access_denied("X-Amz-Expires must be between 1 and 604800 seconds"));
        }
        if now + MAX_SKEW_SECS < t {
            return Err(S3Error::skewed());
        }
        if now > t + expires {
            return Err(S3Error::access_denied("Request has expired"));
        }
        let payload_hash = qget("X-Amz-Content-Sha256").unwrap_or("UNSIGNED-PAYLOAD");
        let payload = payload_mode(payload_hash)?;
        if !matches!(payload, Payload::Unsigned | Payload::Sha256(_)) {
            return Err(S3Error::invalid_request("streaming payloads are not allowed with presigned URLs"));
        }
        let (key, scope_str) = check_signature(req, creds, &scope, amz_date, signed, payload_hash, sig, true)?;
        return Ok(Auth {
            payload,
            presigned: true,
            signing_key: key,
            amz_date: amz_date.to_string(),
            scope: scope_str,
            seed_signature: sig.to_ascii_lowercase(),
        });
    }

    if let Some(ak) = qget("AWSAccessKeyId") {
        return v2::query_auth(req, creds, ak, qget("Expires"), qget("Signature"), now);
    }
    Err(S3Error::access_denied("anonymous requests are not allowed; sign with the proxy's access key"))
}

/// Decoded request body plus the checksums that were verified against it
/// (`(header-name, base64)`; echoed back on PutObject/UploadPart).
#[derive(Debug, Default)]
pub struct Decoded {
    pub data: Vec<u8>,
    pub checksums: Vec<(String, String)>,
}

pub const CHECKSUM_ALGS: [&str; 5] = ["crc32", "crc32c", "crc64nvme", "sha1", "sha256"];

pub fn compute_checksum(alg: &str, data: &[u8]) -> Option<String> {
    use crc::{Crc, CRC_32_ISCSI, CRC_32_ISO_HDLC, CRC_64_NVME};
    Some(match alg {
        "crc32" => B64.encode(Crc::<u32>::new(&CRC_32_ISO_HDLC).checksum(data).to_be_bytes()),
        "crc32c" => B64.encode(Crc::<u32>::new(&CRC_32_ISCSI).checksum(data).to_be_bytes()),
        "crc64nvme" => B64.encode(Crc::<u64>::new(&CRC_64_NVME).checksum(data).to_be_bytes()),
        "sha1" => {
            use sha1::Digest as _;
            B64.encode(sha1::Sha1::digest(data))
        }
        "sha256" => B64.encode(Sha256::digest(data)),
        _ => return None,
    })
}

fn verify_checksum(name: &str, value: &str, data: &[u8], out: &mut Vec<(String, String)>) -> S3Result<()> {
    let alg = name.strip_prefix("x-amz-checksum-").unwrap_or(name);
    let Some(expected) = compute_checksum(alg, data) else {
        return Err(S3Error::invalid_request(format!("unsupported checksum algorithm {alg}")));
    };
    if expected != value.trim() {
        return Err(S3Error::bad_digest(format!("The {} you specified did not match the calculated checksum.", alg.to_uppercase())));
    }
    out.push((format!("x-amz-checksum-{alg}"), expected));
    Ok(())
}

impl Auth {
    fn chunk_sts(&self, prev: &str, data: &[u8]) -> String {
        format!("AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{EMPTY_SHA256}\n{}", self.amz_date, self.scope, prev, sha256_hex(data))
    }

    /// Decode and verify a request body. `header_checksums`: whether
    /// `x-amz-checksum-*` request headers describe this body (false for
    /// CompleteMultipartUpload, where they describe the whole object).
    pub fn decode_body(&self, headers: &HeaderMap, body: &[u8], header_checksums: bool) -> S3Result<Decoded> {
        let mut out = Decoded::default();
        let mut trailers: Vec<(String, String)> = vec![];
        match &self.payload {
            Payload::Unsigned => out.data = body.to_vec(),
            Payload::Sha256(h) => {
                if sha256_hex(body) != *h {
                    return Err(S3Error::new(
                        StatusCode::BAD_REQUEST,
                        "XAmzContentSHA256Mismatch",
                        "The provided 'x-amz-content-sha256' header does not match what was computed.",
                    ));
                }
                out.data = body.to_vec();
            }
            Payload::StreamingSigned { trailer } => {
                let (data, tr) = self.decode_chunked(body, true, *trailer)?;
                out.data = data;
                trailers = tr;
            }
            Payload::StreamingUnsignedTrailer => {
                let (data, tr) = self.decode_chunked(body, false, true)?;
                out.data = data;
                trailers = tr;
            }
        }
        if !matches!(self.payload, Payload::Unsigned | Payload::Sha256(_)) {
            if let Some(dl) = header_str(headers, "x-amz-decoded-content-length") {
                if dl.trim().parse::<usize>().ok() != Some(out.data.len()) {
                    return Err(S3Error::new(StatusCode::BAD_REQUEST, "IncompleteBody", "x-amz-decoded-content-length does not match the decoded body"));
                }
            }
        }
        if let Some(md5) = header_str(headers, "content-md5") {
            use md5::Digest as _;
            let got = B64.encode(md5::Md5::digest(&out.data));
            if got != md5.trim() {
                return Err(S3Error::bad_digest("The Content-MD5 you specified did not match what we received."));
            }
        }
        if header_checksums {
            for (name, v) in headers.iter() {
                let n = name.as_str();
                if n.starts_with("x-amz-checksum-") && !matches!(n, "x-amz-checksum-algorithm" | "x-amz-checksum-type" | "x-amz-checksum-mode") {
                    verify_checksum(n, v.to_str().unwrap_or(""), &out.data, &mut out.checksums)?;
                }
            }
        }
        for (n, v) in &trailers {
            if n.starts_with("x-amz-checksum-") {
                verify_checksum(n, v, &out.data, &mut out.checksums)?;
            }
        }
        if let Some(t) = header_str(headers, "x-amz-trailer") {
            for name in t.split(',').map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()) {
                if !trailers.iter().any(|(n, _)| *n == name) {
                    return Err(S3Error::new(StatusCode::BAD_REQUEST, "IncompleteBody", format!("declared trailer {name} is missing")));
                }
            }
        }
        Ok(out)
    }

    /// aws-chunked: `hex-size[;chunk-signature=sig]\r\n<data>\r\n` … `0[;…]\r\n`
    /// then optional trailer lines `name:value\r\n` and a final `\r\n`.
    fn decode_chunked(&self, body: &[u8], signed: bool, with_trailer: bool) -> S3Result<(Vec<u8>, Trailers)> {
        let bad = |m: &str| S3Error::new(StatusCode::BAD_REQUEST, "IncompleteBody", format!("malformed aws-chunked body: {m}"));
        let mut pos = 0usize;
        let mut data = Vec::with_capacity(body.len());
        let mut prev = self.seed_signature.clone();
        let read_line = |pos: &mut usize| -> Option<&[u8]> {
            let rest = &body[*pos..];
            let i = rest.windows(2).position(|w| w == b"\r\n")?;
            *pos += i + 2;
            Some(&rest[..i])
        };
        loop {
            let line = read_line(&mut pos).ok_or_else(|| bad("missing chunk header"))?;
            let line = std::str::from_utf8(line).map_err(|_| bad("chunk header is not utf-8"))?;
            let (size_hex, ext) = line.split_once(';').unwrap_or((line, ""));
            let size = usize::from_str_radix(size_hex.trim(), 16).map_err(|_| bad("bad chunk size"))?;
            if body.len() - pos < size {
                return Err(bad("truncated chunk"));
            }
            let chunk = &body[pos..pos + size];
            pos += size;
            if signed {
                let sig = ext.trim().strip_prefix("chunk-signature=").ok_or_else(|| bad("missing chunk-signature"))?;
                if !sig_matches(&self.signing_key, &self.chunk_sts(&prev, chunk), sig) {
                    return Err(S3Error::signature_mismatch());
                }
                prev = sig.to_ascii_lowercase();
            }
            data.extend_from_slice(chunk);
            if size == 0 {
                break;
            }
            if body.get(pos..pos + 2) != Some(b"\r\n") {
                return Err(bad("chunk not terminated by CRLF"));
            }
            pos += 2;
        }
        let mut trailers = vec![];
        let mut trailer_sig = None;
        while pos < body.len() {
            let line = read_line(&mut pos).ok_or_else(|| bad("unterminated trailer"))?;
            if line.is_empty() {
                break;
            }
            let line = std::str::from_utf8(line).map_err(|_| bad("trailer is not utf-8"))?;
            let (n, v) = line.split_once(':').ok_or_else(|| bad("malformed trailer"))?;
            let n = n.trim().to_ascii_lowercase();
            if n == "x-amz-trailer-signature" {
                trailer_sig = Some(v.trim().to_string());
            } else {
                trailers.push((n, v.trim().to_string()));
            }
        }
        if !with_trailer && !trailers.is_empty() {
            return Err(bad("unexpected trailer"));
        }
        if signed && with_trailer {
            let sig = trailer_sig.ok_or_else(|| bad("missing x-amz-trailer-signature"))?;
            let canon: String = trailers.iter().map(|(n, v)| format!("{n}:{v}\n")).collect();
            let sts = format!("AWS4-HMAC-SHA256-TRAILER\n{}\n{}\n{}\n{}", self.amz_date, self.scope, prev, sha256_hex(canon.as_bytes()));
            if !sig_matches(&self.signing_key, &sts, &sig) {
                return Err(S3Error::signature_mismatch());
            }
        }
        Ok((data, trailers))
    }
}

/// Legacy Signature Version 2 (HMAC-SHA1). botocore < 1.36 still uses it by
/// default for `generate_presigned_url`, so existing presigned-URL code keeps
/// working. Payloads are unsigned in SigV2 (Content-MD5 is still checked).
mod v2 {
    use super::*;
    use sha1::Sha1;

    /// Query parameters that are part of the SigV2 canonical resource.
    const SUBRESOURCES: &[&str] = &[
        "acl", "cors", "delete", "lifecycle", "location", "logging", "notification", "partNumber", "policy", "requestPayment",
        "restore", "tagging", "torrent", "uploadId", "uploads", "versionId", "versioning", "versions", "website",
        "response-cache-control", "response-content-disposition", "response-content-encoding", "response-content-language",
        "response-content-type", "response-expires",
    ];

    fn string_to_sign(req: &Request, date_or_expires: &str, resource: &str) -> String {
        let h = |n: &str| header_str(req.headers, n).unwrap_or("").trim().to_string();
        let mut amz: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (n, v) in req.headers.iter() {
            if n.as_str().starts_with("x-amz-") {
                amz.entry(n.as_str().to_string()).or_default().push(String::from_utf8_lossy(v.as_bytes()).trim().to_string());
            }
        }
        let amz: String = amz.iter().map(|(n, v)| format!("{n}:{}\n", v.join(","))).collect();
        format!("{}\n{}\n{}\n{}\n{amz}{resource}", req.method, h("content-md5"), h("content-type"), date_or_expires)
    }

    /// Canonical resources to try: the path as sent, and `/<bucket><path>`
    /// for virtual-host requests.
    fn resources(req: &Request) -> Vec<String> {
        let mut sub: Vec<(String, String)> =
            parse_query(req.raw_query).into_iter().filter(|(k, _)| SUBRESOURCES.contains(&k.as_str())).collect();
        sub.sort_by(|a, b| a.0.cmp(&b.0));
        let qs = sub.iter().map(|(k, v)| if v.is_empty() { k.clone() } else { format!("{k}={v}") }).collect::<Vec<_>>().join("&");
        let suffix = if qs.is_empty() { String::new() } else { format!("?{qs}") };
        let mut out = vec![format!("{}{suffix}", req.raw_path)];
        let host = header_str(req.headers, "host").unwrap_or("");
        let host = host.rsplit_once(':').map(|(n, _)| n).unwrap_or(host);
        if let Some(b) = host.strip_suffix(".localhost").filter(|b| !b.is_empty()) {
            out.push(format!("/{b}{}{suffix}", req.raw_path));
        }
        out
    }

    fn check(req: &Request, creds: &Credentials, date_or_expires: &str, provided_b64: &str) -> S3Result<()> {
        let Ok(provided) = B64.decode(provided_b64.trim()) else { return Err(S3Error::signature_mismatch()) };
        for r in resources(req) {
            let mut m = Hmac::<Sha1>::new_from_slice(creds.secret_key.as_bytes()).expect("hmac key");
            m.update(string_to_sign(req, date_or_expires, &r).as_bytes());
            if m.verify_slice(&provided).is_ok() {
                return Ok(());
            }
        }
        Err(S3Error::signature_mismatch())
    }

    fn unsigned_auth() -> Auth {
        Auth { payload: Payload::Unsigned, presigned: true, signing_key: [0; 32], amz_date: String::new(), scope: String::new(), seed_signature: String::new() }
    }

    pub fn query_auth(req: &Request, creds: &Credentials, ak: &str, expires: Option<&str>, sig: Option<&str>, now: i64) -> S3Result<Auth> {
        if ak != creds.access_key {
            return Err(S3Error::invalid_access_key());
        }
        let (Some(expires), Some(sig)) = (expires, sig) else {
            return Err(S3Error::access_denied("presigned URL is missing Expires or Signature"));
        };
        let exp: i64 = expires.parse().map_err(|_| S3Error::access_denied("malformed Expires"))?;
        if now > exp {
            return Err(S3Error::access_denied("Request has expired"));
        }
        check(req, creds, expires, sig)?;
        Ok(Auth { presigned: true, ..unsigned_auth() })
    }

    pub fn header_auth(req: &Request, creds: &Credentials, v: &str, now: i64) -> S3Result<Auth> {
        let (ak, sig) = v.trim().split_once(':').ok_or_else(|| S3Error::new(StatusCode::BAD_REQUEST, "InvalidArgument", "malformed AWS authorization header"))?;
        if ak != creds.access_key {
            return Err(S3Error::invalid_access_key());
        }
        // With x-amz-date present it is part of the amz headers and Date is signed as "".
        let date = if req.headers.contains_key("x-amz-date") { "" } else { header_str(req.headers, "date").unwrap_or("") };
        let t = header_str(req.headers, "x-amz-date")
            .or(header_str(req.headers, "date"))
            .and_then(|d| httpdate::parse_http_date(d).ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .ok_or_else(|| S3Error::access_denied("missing or malformed Date"))?;
        if (now - t.as_secs() as i64).abs() > MAX_SKEW_SECS {
            return Err(S3Error::skewed());
        }
        check(req, creds, date, sig)?;
        Ok(Auth { presigned: false, ..unsigned_auth() })
    }
}

/// Client-side helpers (tests, tools): sign a request with header auth.
pub mod client {
    use super::*;

    /// Returns the `Authorization` header value for the given canonical inputs.
    /// `headers` must be lowercase `(name, value)` pairs, including `host`.
    #[allow(clippy::too_many_arguments)]
    pub fn authorization(
        creds: &Credentials,
        method: &str,
        path: &str,
        query: &str,
        headers: &[(&str, &str)],
        payload_hash: &str,
        amz_date: &str,
        region: &str,
    ) -> (String, String) {
        let mut hs: Vec<(&str, &str)> = headers.to_vec();
        hs.sort();
        let signed = hs.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(";");
        let canon_h: String = hs.iter().map(|(n, v)| format!("{n}:{}\n", v.trim())).collect();
        let creq = format!("{method}\n{}\n{}\n{canon_h}\n{signed}\n{payload_hash}", uri_encode(path, true), canonical_query(query, false));
        let date = &amz_date[..8];
        let scope = format!("{date}/{region}/s3/aws4_request");
        let sts = format!("{ALGORITHM}\n{amz_date}\n{scope}\n{}", sha256_hex(creq.as_bytes()));
        let key = signing_key(&creds.secret_key, date, region, "s3");
        let sig = sign_hex(&key, &sts);
        (format!("{ALGORITHM} Credential={}/{scope}, SignedHeaders={signed}, Signature={sig}", creds.access_key), sig)
    }

    /// Encode `data` as aws-chunked with chunk signatures, starting from `seed`.
    pub fn chunked_signed(creds: &Credentials, amz_date: &str, region: &str, seed: &str, data: &[u8], chunk: usize) -> Vec<u8> {
        let date = &amz_date[..8];
        let auth = Auth {
            payload: Payload::StreamingSigned { trailer: false },
            presigned: false,
            signing_key: signing_key(&creds.secret_key, date, region, "s3"),
            amz_date: amz_date.into(),
            scope: format!("{date}/{region}/s3/aws4_request"),
            seed_signature: seed.into(),
        };
        let mut out = vec![];
        let mut prev = seed.to_string();
        let mut chunks: Vec<&[u8]> = data.chunks(chunk).collect();
        chunks.push(&[]);
        for c in chunks {
            let sig = sign_hex(&auth.signing_key, &auth.chunk_sts(&prev, c));
            out.extend_from_slice(format!("{:x};chunk-signature={sig}\r\n", c.len()).as_bytes());
            out.extend_from_slice(c);
            out.extend_from_slice(b"\r\n");
            prev = sig;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn creds() -> Credentials {
        Credentials { access_key: "AKIAIOSFODNN7EXAMPLE".into(), secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into() }
    }
    const T: i64 = 1_369_353_600; // 20130524T000000Z

    fn hm(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    /// AWS documentation example "GET Object".
    #[test]
    fn aws_example_get_object() {
        let h = hm(&[
            ("host", "examplebucket.s3.amazonaws.com"),
            ("range", "bytes=0-9"),
            ("x-amz-content-sha256", EMPTY_SHA256),
            ("x-amz-date", "20130524T000000Z"),
            ("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"),
        ]);
        let req = Request { method: "GET", raw_path: "/test.txt", raw_query: "", headers: &h };
        let a = authenticate(&req, &creds(), T).unwrap();
        assert_eq!(a.payload, Payload::Sha256(EMPTY_SHA256.into()));
        // wrong secret
        let bad = Credentials { secret_key: "x".into(), ..creds() };
        assert_eq!(authenticate(&req, &bad, T).unwrap_err().code, "SignatureDoesNotMatch");
        // wrong access key
        let bad = Credentials { access_key: "OTHER".into(), ..creds() };
        assert_eq!(authenticate(&req, &bad, T).unwrap_err().code, "InvalidAccessKeyId");
        // clock skew
        assert_eq!(authenticate(&req, &creds(), T + 16 * 60).unwrap_err().code, "RequestTimeTooSkewed");
        assert!(authenticate(&req, &creds(), T + 14 * 60).is_ok());
        // tampered path
        let req = Request { method: "GET", raw_path: "/test2.txt", raw_query: "", headers: &h };
        assert_eq!(authenticate(&req, &creds(), T).unwrap_err().code, "SignatureDoesNotMatch");
    }

    /// AWS documentation example "presigned URL".
    #[test]
    fn aws_example_presigned() {
        let h = hm(&[("host", "examplebucket.s3.amazonaws.com")]);
        let q = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404";
        let req = Request { method: "GET", raw_path: "/test.txt", raw_query: q, headers: &h };
        let a = authenticate(&req, &creds(), T + 100).unwrap();
        assert!(a.presigned);
        assert_eq!(authenticate(&req, &creds(), T + 86_401).unwrap_err().message, "Request has expired");
    }

    /// AWS documentation example "signed chunked upload" (64 KiB + 1 KiB of 'a').
    #[test]
    fn aws_example_streaming_chunks() {
        let seed = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";
        let h = hm(&[
            ("host", "s3.amazonaws.com"),
            ("x-amz-date", "20130524T000000Z"),
            ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
            ("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"),
            ("content-encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", "66560"),
            ("content-length", "66824"),
            ("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class,Signature=4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9"),
        ]);
        let req = Request { method: "PUT", raw_path: "/examplebucket/chunkObject.txt", raw_query: "", headers: &h };
        let a = authenticate(&req, &creds(), T).unwrap();
        let data = vec![b'a'; 66560];
        let body = client::chunked_signed(&creds(), "20130524T000000Z", "us-east-1", seed, &data, 65536);
        assert_eq!(body.len(), 66824);
        let s = String::from_utf8_lossy(&body);
        assert!(s.starts_with("10000;chunk-signature=ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648\r\n"));
        assert!(s.contains("400;chunk-signature=0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497\r\n"));
        assert!(s.ends_with("0;chunk-signature=b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9\r\n\r\n"));
        assert_eq!(a.decode_body(&h, &body, true).unwrap().data, data);
        // flip a data byte → chunk signature fails
        let mut bad = body.clone();
        bad[200] = b'b';
        assert_eq!(a.decode_body(&h, &bad, true).unwrap_err().code, "SignatureDoesNotMatch");
    }

    /// Legacy SigV2 presigned URL, from the AWS S3 SigV2 documentation example
    /// (`GET\n\n\n1175139620\n/johnsmith/photos/puppy.jpg`).
    #[test]
    fn sigv2_presigned() {
        let h = hm(&[("host", "s3.amazonaws.com")]);
        let q = "AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Expires=1175139620&Signature=NpgCjnDzrM%2BWFzoENXmpNDUsSn8%3D";
        let req = Request { method: "GET", raw_path: "/johnsmith/photos/puppy.jpg", raw_query: q, headers: &h };
        assert!(authenticate(&req, &creds(), 1_175_139_000).is_ok());
        assert_eq!(authenticate(&req, &creds(), 1_175_139_621).unwrap_err().message, "Request has expired");
        let req = Request { method: "GET", raw_path: "/johnsmith/photos/kitten.jpg", raw_query: q, headers: &h };
        assert_eq!(authenticate(&req, &creds(), 1_175_139_000).unwrap_err().code, "SignatureDoesNotMatch");
    }

    #[test]
    fn unsigned_trailer_crc32() {
        let h = hm(&[("x-amz-trailer", "x-amz-checksum-crc32"), ("x-amz-decoded-content-length", "11")]);
        let a = Auth {
            payload: Payload::StreamingUnsignedTrailer,
            presigned: false,
            signing_key: [0; 32],
            amz_date: String::new(),
            scope: String::new(),
            seed_signature: String::new(),
        };
        let crc = compute_checksum("crc32", b"hello world").unwrap();
        assert_eq!(crc, "DUoRhQ==");
        let body = format!("b\r\nhello world\r\n0\r\nx-amz-checksum-crc32:{crc}\r\n\r\n");
        let d = a.decode_body(&h, body.as_bytes(), true).unwrap();
        assert_eq!(d.data, b"hello world");
        assert_eq!(d.checksums, vec![("x-amz-checksum-crc32".to_string(), crc)]);
        let body = "b\r\nhello world\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n";
        assert_eq!(a.decode_body(&h, body.as_bytes(), true).unwrap_err().code, "BadDigest");
        // missing declared trailer
        assert!(a.decode_body(&h, b"b\r\nhello world\r\n0\r\n\r\n", true).is_err());
        // crc64nvme of "123456789" (check value from the CRC catalogue) = 0xAE8B14860A799888
        assert_eq!(compute_checksum("crc64nvme", b"123456789").unwrap(), B64.encode(0xAE8B_1486_0A79_9888u64.to_be_bytes()));
    }
}
