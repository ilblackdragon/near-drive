#!/usr/bin/env bash
# Start a dev gateway + `nst s3-proxy` on 127.0.0.1 and run tests/boto3_smoke.py.
#   PYTHON=/path/to/venv/bin/python tests/boto3_smoke.sh
# Needs `cargo build` first (BIN defaults to target/debug).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${BIN:-$ROOT/target/debug}
PY=${PYTHON:-python3}
T=$(mktemp -d)
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$T"; }
trap cleanup EXIT

port() { "$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
wait_port() { for _ in $(seq 100); do (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null && return 0; sleep 0.1; done; echo "port $1 not up" >&2; return 1; }

GWP=$(port); PXP=$(port)
PK=$("$BIN/nst" --account alice.near dev-key --out "$T/alice.json")
cat > "$T/gw.json" <<JSON
{"listen":"127.0.0.1:$GWP","data_dir":"$T/gw","dev_keys":{"alice.near":["$PK"]}}
JSON
"$BIN/nstorage-gateway" --config "$T/gw.json" > "$T/gw.log" 2>&1 & PIDS+=($!)
wait_port "$GWP"

export NSTORAGE_ACCOUNT=alice.near NSTORAGE_CREDENTIALS="$T/alice.json" NSTORAGE_HOME="$T/home" NSTORAGE_GATEWAY="http://127.0.0.1:$GWP"
"$BIN/nst" keygen 2>/dev/null
NO_COLOR=1 RUST_LOG=warn,nstorage_s3=debug "$BIN/nst" s3-proxy --listen "127.0.0.1:$PXP" --public-prefix public/ > "$T/proxy.log" 2>&1 & PIDS+=($!)
wait_port "$PXP"
head -3 "$T/proxy.log"

export S3_ENDPOINT="http://127.0.0.1:$PXP" S3_BUCKET=alice.near
AWS_ACCESS_KEY_ID=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["access_key"])' "$T/home/s3-proxy.json")
AWS_SECRET_ACCESS_KEY=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["secret_key"])' "$T/home/s3-proxy.json")
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
unset AWS_PROFILE AWS_DEFAULT_PROFILE AWS_SESSION_TOKEN || true
export AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null

rc=0
"$PY" "$ROOT/tests/boto3_smoke.py" || rc=$?

if [ -n "${AWS_CLI:-}" ]; then
  echo "--- aws cli: $("$AWS_CLI" --version 2>&1)"
  head -c 7000000 /dev/urandom > "$T/cli.bin"
  "$AWS_CLI" --endpoint-url "$S3_ENDPOINT" --region us-east-1 s3 cp "$T/cli.bin" "s3://alice.near/cli/cli.bin" --only-show-errors || rc=$?
  "$AWS_CLI" --endpoint-url "$S3_ENDPOINT" --region us-east-1 s3 ls "s3://alice.near/cli/" || rc=$?
  "$AWS_CLI" --endpoint-url "$S3_ENDPOINT" --region us-east-1 s3 cp "s3://alice.near/cli/cli.bin" "$T/cli.out" --only-show-errors || rc=$?
  cmp "$T/cli.bin" "$T/cli.out" && echo "  ok  aws s3 cp round-trip (multipart, 7 MB)" || rc=1
  "$AWS_CLI" --endpoint-url "$S3_ENDPOINT" --region us-east-1 s3 rm --recursive "s3://alice.near/cli/" --only-show-errors || rc=$?
fi

echo "--- payload modes seen by the proxy:"
grep -o 'payload=[A-Za-z]*' "$T/proxy.log" | sort | uniq -c || true
grep -E ' -> [0-9]{3} ' "$T/proxy.log" | sed 's/^.*nstorage_s3: //' | sort | uniq -c | head -20 || true
exit $rc
