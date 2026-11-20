"""deltaleague's storage patterns against the NEAR Drive S3 endpoint.

Mirrors league/storage.py (BlobStore: upload_file, get_object streaming,
generate_presigned_url GET/PUT, delete), league/streaming_register.py
(upload_fileobj from a non-seekable pipe, TransferConfig 8 MiB parts x4,
head_object size check) and worker/main.py (httpx.stream GET of a presigned
URL with follow_redirects=False, sha256 check; presigned PUT of results).
"""
import hashlib
import io
import os
import pathlib
import tempfile
import threading

import boto3
import httpx
from boto3.s3.transfer import TransferConfig
from botocore.config import Config

passed = 0


def ok(msg):
    global passed
    passed += 1
    print(f"  ok   {msg}")


s3 = boto3.client("s3", endpoint_url=os.environ["R2_ENDPOINT"], aws_access_key_id=os.environ["R2_ACCESS_KEY_ID"],
                  aws_secret_access_key=os.environ["R2_SECRET_ACCESS_KEY"], region_name="auto",
                  config=Config(signature_version="s3v4"))
tmp = pathlib.Path(tempfile.mkdtemp())

# BlobStore.put -> upload_file (boto3 multipart above 8 MiB, 10 threads).
src = tmp / "model.safetensors"
src.write_bytes(os.urandom(45 * 1024 * 1024 + 123))
sha = hashlib.sha256(src.read_bytes()).hexdigest()
key = f"verified/{sha}"
s3.upload_file(str(src), "delta-artifacts", key)
assert s3.head_object(Bucket="delta-artifacts", Key=key)["ContentLength"] == src.stat().st_size
ok("upload_file (multipart, 10 concurrent parts) into delta-artifacts")

# BlobStore.download -> get_object streamed in 1 MiB reads.
body = s3.get_object(Bucket="delta-artifacts", Key=key)["Body"]
h = hashlib.sha256()
while chunk := body.read(1024 * 1024):
    h.update(chunk)
assert h.hexdigest() == sha
ok("get_object streamed, sha256 matches")

# worker/main.py: presigned GET (7 days), httpx.stream, no redirects.
url = s3.generate_presigned_url("get_object", Params={"Bucket": "delta-artifacts", "Key": key}, ExpiresIn=604800)
h, total = hashlib.sha256(), 0
with httpx.stream("GET", url, timeout=120, follow_redirects=False) as r:
    r.raise_for_status()
    for chunk in r.iter_bytes():
        total += len(chunk)
        h.update(chunk)
assert h.hexdigest() == sha and total == src.stat().st_size
ok("worker download: presigned GET via httpx.stream (no redirects), sha256 matches")

# Worker uploads results with a presigned PUT into the private bucket.
put = s3.generate_presigned_url("put_object", Params={"Bucket": "delta-private", "Key": "jobs/1/1/responses.jsonl"}, ExpiresIn=604800)
answers = b'{"id": 1, "answer": "42"}\n' * 1000
httpx.put(put, content=answers, timeout=60).raise_for_status()
got = s3.get_object(Bucket="delta-private", Key="jobs/1/1/responses.jsonl")["Body"].read()
assert got == answers
ok("worker upload: presigned PUT into delta-private")

# streaming_register.py: upload_fileobj from a non-seekable pipe.
class Pipe(io.RawIOBase):
    def __init__(self, n):
        self.left, self.h = n, hashlib.sha256()

    def readable(self):
        return True

    def readinto(self, b):
        if not self.left:
            return 0
        n = min(len(b), self.left, 1 << 20)
        data = os.urandom(n)
        b[:n] = data
        self.h.update(data)
        self.left -= n
        return n


n = 37 * 1024 * 1024 + 5
pipe = Pipe(n)
peak = {"bytes": 0}
stop = threading.Event()


def watch_staging():
    d = pathlib.Path(os.environ["STAGING_DIR"])
    while not stop.is_set():
        size = sum(p.stat().st_size for p in d.rglob("*") if p.is_file()) if d.exists() else 0
        peak["bytes"] = max(peak["bytes"], size)
        stop.wait(0.02)


w = threading.Thread(target=watch_staging)
w.start()
cfg = TransferConfig(multipart_chunksize=8 * 1024**2, max_concurrency=4)
s3.upload_fileobj(io.BufferedReader(pipe, buffer_size=1 << 20), "delta-artifacts", "verified/streamed", Config=cfg)
stop.set()
w.join()
assert s3.head_object(Bucket="delta-artifacts", Key="verified/streamed")["ContentLength"] == n
body = s3.get_object(Bucket="delta-artifacts", Key="verified/streamed")["Body"]
h = hashlib.sha256()
while chunk := body.read(1 << 20):
    h.update(chunk)
assert h.hexdigest() == pipe.h.hexdigest()
assert peak["bytes"] < n // 2, f"staging peaked at {peak['bytes']} bytes for a {n}-byte object"
ok(f"streaming_register: upload_fileobj from a pipe (8 MiB x4), staging peak {peak['bytes'] // 2**20} MiB for {n // 2**20} MiB")

# Presigned PUT from the browser portal (CORS) and a ranged read.
pre = httpx.options(put, headers={"Origin": "https://portal.example", "Access-Control-Request-Method": "PUT"})
assert pre.status_code == 200 and pre.headers["access-control-allow-origin"] == "https://portal.example"
ok("browser upload: CORS preflight allowed for the portal origin")
r = httpx.get(url, headers={"Range": "bytes=1000-1999"})
assert r.status_code == 206 and r.content == src.read_bytes()[1000:2000]
ok("ranged read through a presigned URL")

# Listing and delete use the existing bucket names; the gateway only stores ciphertext.
keys = [o["Key"] for o in s3.list_objects_v2(Bucket="delta-artifacts", Prefix="verified/")["Contents"]]
assert sorted(keys) == sorted([key, "verified/streamed"]), keys
s3.delete_object(Bucket="delta-artifacts", Key="verified/streamed")
assert [o["Key"] for o in s3.list_objects_v2(Bucket="delta-artifacts", Prefix="verified/")["Contents"]] == [key]
needle = answers[:40]
leaked = [p for p in pathlib.Path(os.environ["GW_DATA"]).rglob("*") if p.is_file() and needle in p.read_bytes()]
assert not leaked, leaked
ok("list / delete by bucket alias; gateway storage holds no plaintext")
print(f"\n{passed} passed")
