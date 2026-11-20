#!/usr/bin/env bash
# deltaleague-style usage end to end: a dev gateway and the S3 endpoint
# configured the way a service would run it (keys from env vars, bucket
# aliases for its existing bucket names, CORS), then tests/deltaleague_compat.py
# drives it with deltaleague's own patterns (league/storage.py BlobStore,
# streaming_register.py, worker/main.py downloads).
#   cargo build && tests/deltaleague_compat.sh
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
PK=$("$BIN/near-drive" --account league.near dev-key --out "$T/league.json")
cat > "$T/gw.json" <<JSON
{"listen":"127.0.0.1:$GWP","data_dir":"$T/gw","dev_keys":{"league.near":["$PK"]}}
JSON
"$BIN/near-drive-gateway" --config "$T/gw.json" > "$T/gw.log" 2>&1 & PIDS+=($!)
wait_port "$GWP"

# Service configuration: everything from environment variables (no files, no near-cli).
export NEAR_DRIVE_ACCOUNT=league.near NEAR_DRIVE_GATEWAY="http://127.0.0.1:$GWP" NEAR_DRIVE_HOME="$T/home"
NEAR_DRIVE_SECRET_KEY=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["private_key"])' "$T/league.json")
NEAR_DRIVE_ROOT_KEY=$("$PY" -c 'import secrets; print(secrets.token_hex(32))')
export NEAR_DRIVE_SECRET_KEY NEAR_DRIVE_ROOT_KEY
export NEAR_DRIVE_INSECURE_SKIP_WRITER_CHECK=1 # dev gateway, no chain to check signing keys against
export NEAR_DRIVE_S3_ACCESS_KEY=LEAGUEACCESSKEY00001 NEAR_DRIVE_S3_SECRET_KEY=league-secret-key-0123456789abcdefghijkl
NO_COLOR=1 RUST_LOG=warn "$BIN/near-drive" --no-interactive s3-proxy --listen "127.0.0.1:$PXP" \
  --bucket-alias delta-artifacts=near://league.near/artifacts/ \
  --bucket-alias delta-private=near://league.near/private/ \
  --cors-origin https://portal.example > "$T/proxy.log" 2>&1 & PIDS+=($!)
wait_port "$PXP"

export R2_ENDPOINT="http://127.0.0.1:$PXP" R2_ACCESS_KEY_ID=$NEAR_DRIVE_S3_ACCESS_KEY R2_SECRET_ACCESS_KEY=$NEAR_DRIVE_S3_SECRET_KEY
export AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null
export STAGING_DIR="$T/home/s3-staging" GW_DATA="$T/gw"
"$PY" "$ROOT/tests/deltaleague_compat.py"
