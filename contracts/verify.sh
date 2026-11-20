#!/bin/sh
# Check that a deployed drive contract is exactly what its source says.
#
#   contracts/verify.sh <account> [mainnet|testnet|<rpc-url>]
#
# 1. reads the contract's NEP-330 `contract_source_metadata` (source commit,
#    build image, command) and its on-chain code hash;
# 2. rebuilds that commit with contracts/build-reproducible.sh;
# 3. compares the hashes.
set -eu
ACCOUNT="${1:?usage: verify.sh <account> [mainnet|testnet|<rpc-url>]}"
case "${2:-mainnet}" in
  mainnet) RPC=https://rpc.mainnet.near.org ;;
  testnet) RPC=https://rpc.testnet.near.org ;;
  *) RPC="$2" ;;
esac
here=$(cd "$(dirname "$0")" && pwd)

rpc() {
  curl -fsS "$RPC" -H 'content-type: application/json' -d "$1"
}

meta=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"call_function\",\"finality\":\"final\",\"account_id\":\"$ACCOUNT\",\"method_name\":\"contract_source_metadata\",\"args_base64\":\"e30=\"}}" |
  python3 -c "import sys,json; r=json.load(sys.stdin)['result']['result']; print(bytes(r).decode())")
code_hash=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$ACCOUNT\"}}" |
  python3 -c "import sys,json; print(json.load(sys.stdin)['result']['code_hash'])")
if ! printf '%s' "$meta" | python3 -c "import sys,json; sys.exit(0 if json.load(sys.stdin).get('build_info') else 1)"; then
  echo "NOT VERIFIABLE: $ACCOUNT has no NEP-330 build_info (not deployed from a reproducible build)" >&2
  exit 1
fi
rev=$(printf '%s' "$meta" | python3 -c "import sys,json; s=json.load(sys.stdin)['build_info']['source_code_snapshot']; print(s.split('rev=')[1])")
repo=$(printf '%s' "$meta" | python3 -c "import sys,json; s=json.load(sys.stdin)['build_info']['source_code_snapshot']; print(s.split('?')[0].removeprefix('git+'))")
echo "deployed:  $ACCOUNT  code hash $code_hash"
echo "source:    $repo @ $rev"

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT INT TERM
built=$(NEAR_DRIVE_REPO="$repo.git" sh "$here/build-reproducible.sh" "$rev" "$out" | sed -n 's/^code hash: *\([^ ]*\).*/\1/p')
echo "rebuilt:   code hash $built"
if [ "$built" = "$code_hash" ]; then
  echo "OK: $ACCOUNT runs exactly the code built from $repo @ $rev"
else
  echo "MISMATCH: the deployed code is not the reproducible build of $rev" >&2
  exit 1
fi
