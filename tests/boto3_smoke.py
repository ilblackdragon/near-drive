#!/usr/bin/env python3
"""boto3 smoke test against a running `nst s3-proxy`.

Env: S3_ENDPOINT, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, S3_BUCKET
(the proxy's NEAR account). Run via tests/boto3_smoke.sh, which starts a
dev gateway and the proxy on 127.0.0.1.
"""
import hashlib
import io
import os
import sys
import tempfile
import urllib.request

import boto3
import botocore
from boto3.s3.transfer import TransferConfig
from botocore.config import Config
from botocore.exceptions import ClientError

EP = os.environ["S3_ENDPOINT"]
AK = os.environ["AWS_ACCESS_KEY_ID"]
SK = os.environ["AWS_SECRET_ACCESS_KEY"]
B = os.environ["S3_BUCKET"]

print(f"boto3 {boto3.__version__} / botocore {botocore.__version__} -> {EP} bucket={B}")


def client(**cfg):
    return boto3.client(
        "s3",
        endpoint_url=EP,
        aws_access_key_id=cfg.pop("ak", AK),
        aws_secret_access_key=cfg.pop("sk", SK),
        region_name="us-east-1",
        config=Config(**cfg) if cfg else None,
    )


s3 = client()
checks = 0


def ok(cond, what):
    global checks
    if not cond:
        print(f"FAIL: {what}")
        sys.exit(1)
    checks += 1
    print(f"  ok  {what}")


def err_code(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except ClientError as e:
        return e.response["Error"]["Code"]
    return None


# --- buckets
names = [b["Name"] for b in s3.list_buckets()["Buckets"]]
ok(B in names, f"list_buckets contains {B}")
s3.head_bucket(Bucket=B)
s3.create_bucket(Bucket=B)
ok(True, "head_bucket / create_bucket(own) succeed")

# --- put/get/head with metadata
s3.put_object(Bucket=B, Key="smoke/hello.txt", Body=b"hello nstorage", ContentType="text/plain", Metadata={"owner": "smoke"})
g = s3.get_object(Bucket=B, Key="smoke/hello.txt")
ok(g["Body"].read() == b"hello nstorage", "get_object body round-trips")
ok(g["ContentType"] == "text/plain", "content-type round-trips")
ok(g["Metadata"] == {"owner": "smoke"}, "x-amz-meta round-trips")
h = s3.head_object(Bucket=B, Key="smoke/hello.txt")
ok(h["ContentLength"] == 14 and h["ETag"] == g["ETag"], "head_object length + etag")
r = s3.get_object(Bucket=B, Key="smoke/hello.txt", Range="bytes=6-13")
ok(r["Body"].read() == b"nstorage" and r["ResponseMetadata"]["HTTPStatusCode"] == 206, "range GET -> 206")
ok(err_code(s3.get_object, Bucket=B, Key="smoke/missing") == "NoSuchKey", "missing key -> NoSuchKey")

# --- explicit checksum algorithms (header or trailer depending on botocore version)
for alg in ["CRC32", "SHA1", "SHA256", "CRC32C", "CRC64NVME"]:
    try:
        resp = s3.put_object(Bucket=B, Key=f"smoke/ck-{alg}", Body=b"x" * 1000, ChecksumAlgorithm=alg)
    except (botocore.exceptions.MissingDependencyException, botocore.exceptions.FlexibleChecksumError, botocore.exceptions.ParamValidationError) as e:
        # CRC32C/CRC64NVME need awscrt; old botocore does not know CRC64NVME
        print(f"  --  {alg} not available in this botocore: {type(e).__name__}")
        continue
    ok(resp["ResponseMetadata"]["HTTPStatusCode"] == 200, f"put_object ChecksumAlgorithm={alg}")

# --- botocore >= 1.36 sends aws-chunked bodies with an x-amz-checksum-* trailer
# (STREAMING-UNSIGNED-PAYLOAD-TRAILER), but only over https. The proxy is
# plain http on loopback, so make botocore believe the URL is https to drive
# that code path for real.
import botocore.httpchecksum as _hc

if hasattr(_hc, "_apply_request_trailer_checksum") and hasattr(_hc, "urlparse"):
    from types import SimpleNamespace

    _orig = _hc.urlparse
    _hc.urlparse = lambda u: SimpleNamespace(scheme="https")
    try:
        algs = ["CRC32", "CRC32C", "CRC64NVME", "SHA256"]
        for alg in algs:
            try:
                body = os.urandom(300_000)
                s3.put_object(Bucket=B, Key=f"smoke/trailer-{alg}", Body=body, ChecksumAlgorithm=alg)
            except (botocore.exceptions.MissingDependencyException, botocore.exceptions.FlexibleChecksumError):
                continue
            ok(s3.get_object(Bucket=B, Key=f"smoke/trailer-{alg}")["Body"].read() == body, f"aws-chunked + {alg} trailer PUT")
        tdata = os.urandom(11 * 1024 * 1024)
        s3.upload_fileobj(io.BytesIO(tdata), B, "smoke/trailer-mp.bin",
                          Config=TransferConfig(multipart_threshold=5 * 1024 * 1024, multipart_chunksize=5 * 1024 * 1024))
        ok(s3.get_object(Bucket=B, Key="smoke/trailer-mp.bin")["Body"].read() == tdata, "multipart upload with trailer checksums (default CRC32)")
    finally:
        _hc.urlparse = _orig
else:
    print("  --  this botocore has no trailer checksums (pre-1.36)")

# --- multipart upload_file + parallel ranged download_file
data = os.urandom(13 * 1024 * 1024 + 12345)
sha = hashlib.sha256(data).hexdigest()
tc = TransferConfig(multipart_threshold=5 * 1024 * 1024, multipart_chunksize=5 * 1024 * 1024, max_concurrency=4)
with tempfile.TemporaryDirectory() as d:
    src = os.path.join(d, "src.bin")
    dst = os.path.join(d, "dst.bin")
    with open(src, "wb") as f:
        f.write(data)
    s3.upload_file(src, B, "smoke/big/model.bin", Config=tc, ExtraArgs={"Metadata": {"step": "7"}})
    h = s3.head_object(Bucket=B, Key="smoke/big/model.bin")
    ok(h["ContentLength"] == len(data), "multipart upload_file: size")
    ok(h["Metadata"] == {"step": "7"}, "multipart upload_file: metadata")
    s3.download_file(B, "smoke/big/model.bin", dst, Config=tc)
    with open(dst, "rb") as f:
        ok(hashlib.sha256(f.read()).hexdigest() == sha, "download_file (parallel ranged GETs) matches")
buf = io.BytesIO()
s3.download_fileobj(B, "smoke/hello.txt", buf)
ok(buf.getvalue() == b"hello nstorage", "download_fileobj")
s3.upload_fileobj(io.BytesIO(b"fileobj"), B, "smoke/fileobj.txt")
ok(s3.get_object(Bucket=B, Key="smoke/fileobj.txt")["Body"].read() == b"fileobj", "upload_fileobj")

# --- manual multipart incl. list_parts / abort
mp = s3.create_multipart_upload(Bucket=B, Key="smoke/manual.bin")
uid = mp["UploadId"]
p1 = s3.upload_part(Bucket=B, Key="smoke/manual.bin", UploadId=uid, PartNumber=1, Body=b"a" * 100)
p2 = s3.upload_part(Bucket=B, Key="smoke/manual.bin", UploadId=uid, PartNumber=2, Body=b"b" * 50)
lp = s3.list_parts(Bucket=B, Key="smoke/manual.bin", UploadId=uid)
ok([p["PartNumber"] for p in lp["Parts"]] == [1, 2], "list_parts")
s3.complete_multipart_upload(
    Bucket=B, Key="smoke/manual.bin", UploadId=uid,
    MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": p1["ETag"]}, {"PartNumber": 2, "ETag": p2["ETag"]}]},
)
ok(s3.get_object(Bucket=B, Key="smoke/manual.bin")["Body"].read() == b"a" * 100 + b"b" * 50, "complete_multipart_upload")
mp = s3.create_multipart_upload(Bucket=B, Key="smoke/aborted.bin")
s3.abort_multipart_upload(Bucket=B, Key="smoke/aborted.bin", UploadId=mp["UploadId"])
ok(err_code(s3.list_parts, Bucket=B, Key="smoke/aborted.bin", UploadId=mp["UploadId"]) == "NoSuchUpload", "abort_multipart_upload")

# --- copy
s3.copy_object(Bucket=B, Key="smoke/copy.txt", CopySource={"Bucket": B, "Key": "smoke/hello.txt"})
c = s3.get_object(Bucket=B, Key="smoke/copy.txt")
ok(c["Body"].read() == b"hello nstorage" and c["Metadata"] == {"owner": "smoke"}, "copy_object keeps body + metadata")

# --- listing with paginator + delimiter
for k in ["smoke/list/a/1", "smoke/list/a/2", "smoke/list/b/1", "smoke/list/c", "smoke/list/d e+f"]:
    s3.put_object(Bucket=B, Key=k, Body=k.encode())
pag = s3.get_paginator("list_objects_v2")
keys, prefixes, pages = [], [], 0
for page in pag.paginate(Bucket=B, Prefix="smoke/list/", Delimiter="/", PaginationConfig={"PageSize": 2}):
    pages += 1
    keys += [o["Key"] for o in page.get("Contents", [])]
    prefixes += [p["Prefix"] for p in page.get("CommonPrefixes", [])]
ok(sorted(keys) == ["smoke/list/c", "smoke/list/d e+f"], f"paginator keys {keys}")
ok(sorted(prefixes) == ["smoke/list/a/", "smoke/list/b/"], f"paginator common prefixes {prefixes}")
ok(pages == 2, f"paginated in {pages} pages of 2")
allkeys = [o["Key"] for p in pag.paginate(Bucket=B, Prefix="smoke/") for o in p.get("Contents", [])]
ok(not any(k.endswith(".nst-s3meta") for k in allkeys), "metadata sidecars hidden from listings")
v1 = s3.list_objects(Bucket=B, Prefix="smoke/list/")
ok(len(v1["Contents"]) == 5, "list_objects (v1)")

# --- presigned URLs
url = s3.generate_presigned_url("get_object", Params={"Bucket": B, "Key": "smoke/hello.txt"}, ExpiresIn=300)
with urllib.request.urlopen(url) as resp:
    ok(resp.read() == b"hello nstorage", f"presigned GET via urllib ({'SigV2' if 'AWSAccessKeyId=' in url else 'SigV4'} URL)")
v4 = client(signature_version="s3v4")
url4 = v4.generate_presigned_url("get_object", Params={"Bucket": B, "Key": "smoke/hello.txt"}, ExpiresIn=300)
with urllib.request.urlopen(url4) as resp:
    ok(resp.read() == b"hello nstorage" and "X-Amz-Signature=" in url4, "presigned GET (explicit s3v4)")
bad_url = url.replace("hello.txt", "copy.txt")
try:
    urllib.request.urlopen(bad_url)
    ok(False, "tampered presigned URL must fail")
except urllib.error.HTTPError as e:
    ok(e.code == 403 and b"SignatureDoesNotMatch" in e.read(), "tampered presigned URL -> 403 SignatureDoesNotMatch")
put_url = s3.generate_presigned_url("put_object", Params={"Bucket": B, "Key": "smoke/presigned-put"}, ExpiresIn=300)
# SigV2 presigned URLs (botocore < 1.36 default) sign Content-Type; send none.
req = urllib.request.Request(put_url, data=b"pp", method="PUT", headers={"Content-Type": ""})
with urllib.request.urlopen(req) as resp:
    ok(resp.status == 200, "presigned PUT")
ok(s3.get_object(Bucket=B, Key="smoke/presigned-put")["Body"].read() == b"pp", "presigned PUT stored body")

# --- auth failures
ok(err_code(client(sk="wrong").get_object, Bucket=B, Key="smoke/hello.txt") == "SignatureDoesNotMatch", "wrong secret -> SignatureDoesNotMatch")
ok(err_code(client(ak="NSTNOPE").list_objects_v2, Bucket=B) == "InvalidAccessKeyId", "wrong access key -> InvalidAccessKeyId")

# --- virtual-host addressing (<bucket>.localhost)
vh = boto3.client(
    "s3", endpoint_url=EP.replace("127.0.0.1", "localhost"), aws_access_key_id=AK, aws_secret_access_key=SK,
    region_name="us-east-1", config=Config(s3={"addressing_style": "virtual"}),
)
try:
    vh.put_object(Bucket=B, Key="smoke/vhost", Body=b"vh")
    ok(s3.get_object(Bucket=B, Key="smoke/vhost")["Body"].read() == b"vh", "virtual-host style PUT")
except Exception as e:
    print(f"  --  virtual-host style unavailable here ({type(e).__name__}: {e})")

# --- delete_objects
allkeys = [o["Key"] for p in pag.paginate(Bucket=B, Prefix="smoke/") for o in p.get("Contents", [])]
for i in range(0, len(allkeys), 1000):
    r = s3.delete_objects(Bucket=B, Delete={"Objects": [{"Key": k} for k in allkeys[i:i + 1000]]})
    ok(len(r.get("Deleted", [])) == len(allkeys[i:i + 1000]) and not r.get("Errors"), f"delete_objects ({len(allkeys)} keys)")
ok(s3.list_objects_v2(Bucket=B, Prefix="smoke/")["KeyCount"] == 0, "everything deleted")
s3.delete_object(Bucket=B, Key="smoke/never-existed")
ok(True, "delete_object of a missing key succeeds")

print(f"ALL {checks} CHECKS PASSED (boto3 {boto3.__version__})")
