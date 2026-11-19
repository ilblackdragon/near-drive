#!/usr/bin/env bash
# near-cli integration on a local NEAR sandbox: `near drive` as a near-cli
# extension, keys read from near-cli's keychain, transactions signed by `near`.
#
#   1. sandbox node (127.0.0.1 only) + drive contract + alice with a
#      full-access key in near-cli's legacy keychain
#   2. gateway that authenticates keys and reads rules from the sandbox
#   3. whoami (full-access key) -> login (session key via `near account add-key`)
#      -> put/get/ls signed by the session key -> grant/rules -> publish-key
#      -> `near drive ...` through near-cli -> logout
#
# Needs: near (near-cli-rs), near-sandbox (NEAR_SANDBOX_BIN, or the one
# near-workspaces downloaded under contracts/target), contracts built
# (contracts/build.sh), `cargo build`.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/debug"
NEAR="${NEAR_BIN:-near}"
SANDBOX="${NEAR_SANDBOX_BIN:-$(find "$ROOT/contracts/target" -name near-sandbox -type f -perm -u+x 2>/dev/null | head -1)}"
WASM="$ROOT/contracts/target/near/near_drive_contract/near_drive_contract.wasm"
[ -x "$SANDBOX" ] || { echo "near-sandbox not found; set NEAR_SANDBOX_BIN"; exit 1; }
[ -f "$WASM" ] || { echo "build the contract first: contracts/build.sh"; exit 1; }
command -v "$NEAR" >/dev/null || { echo "near-cli-rs not found"; exit 1; }

T="$(mktemp -d -t drive-nearcli.XXXXXX)"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$T"; }
trap cleanup EXIT
pass=0
ok() { echo "  ok   $1"; pass=$((pass + 1)); }
die() { echo "  FAIL $1"; exit 1; }

port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
RPC_PORT=$(port); NET_PORT=$(port); GW_PORT=$(port)
RPC="http://127.0.0.1:$RPC_PORT"

# near-cli and near-drive both read $XDG_CONFIG_HOME/near-cli/config.toml.
export XDG_CONFIG_HOME="$T/config"
CREDS="$T/creds"
mkdir -p "$XDG_CONFIG_HOME/near-cli" "$CREDS/sandbox"
cat >"$XDG_CONFIG_HOME/near-cli/config.toml" <<EOF
version = "4"
credentials_home_dir = "$CREDS"

[network_connection.sandbox]
network_name = "sandbox"
rpc_url = "$RPC/"
wallet_url = "http://127.0.0.1/"
explorer_transaction_url = "http://127.0.0.1/"
EOF

echo "== sandbox"
"$SANDBOX" --home "$T/sb" init >/dev/null 2>&1
"$SANDBOX" --home "$T/sb" run --rpc-addr "127.0.0.1:$RPC_PORT" --network-addr "127.0.0.1:$NET_PORT" >"$T/sandbox.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 60); do curl -sf "$RPC/status" >/dev/null && break; sleep 0.5; done
curl -sf "$RPC/status" >/dev/null || die "sandbox did not start"
ROOT_SK=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["secret_key"])' "$T/sb/validator_key.json")
ROOT_PK=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["public_key"])' "$T/sb/validator_key.json")
nearq() { "$NEAR" "$@" </dev/null >"$T/near.log" 2>&1 || { cat "$T/near.log"; die "near $*"; }; }

ALICE=alice.test.near
DRIVE=drive.test.near
ALICE_JSON="$CREDS/sandbox/$ALICE.json"
ALICE_PK=$(NEAR_DRIVE_ACCOUNT=$ALICE "$BIN/near-drive" --no-interactive dev-key --out "$T/alice-key.json")
cp "$T/alice-key.json" "$ALICE_JSON"   # what `near account import-account ... save-to-legacy-keychain` writes
nearq account create-account fund-myself "$ALICE" '50 NEAR' use-manually-provided-public-key "$ALICE_PK" sign-as test.near network-config sandbox sign-with-plaintext-private-key "$ROOT_SK" send
nearq account create-account fund-myself "$DRIVE" '20 NEAR' use-manually-provided-public-key "$ROOT_PK" sign-as test.near network-config sandbox sign-with-plaintext-private-key "$ROOT_SK" send
nearq contract deploy "$DRIVE" use-file "$WASM" with-init-call new json-args "{\"owner_id\":\"$DRIVE\"}" prepaid-gas '100 Tgas' attached-deposit '0 NEAR' network-config sandbox sign-with-plaintext-private-key "$ROOT_SK" send
ok "sandbox: $ALICE and $DRIVE deployed"

cat >"$T/gw.json" <<EOF
{"listen":"127.0.0.1:$GW_PORT","data_dir":"$T/gw","rpc_url":"$RPC","storage_contract":"$DRIVE","contract_policies":true}
EOF
RUST_LOG=warn "$BIN/near-drive-gateway" --config "$T/gw.json" >"$T/gw.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 40); do curl -sf "http://127.0.0.1:$GW_PORT/healthz" >/dev/null && break; sleep 0.25; done

export NEAR_DRIVE_GATEWAY="http://127.0.0.1:$GW_PORT" NEAR_DRIVE_CONTRACT="$DRIVE" NEAR_DRIVE_NETWORK=sandbox NEAR_DRIVE_HOME="$T/home" NEAR_DRIVE_NEAR_BIN="$NEAR"
# Non-interactive runs sign with near-cli's legacy keychain (headless: no OS keychain).
export NEAR_DRIVE_NEAR_SIGN="sign-with-legacy-keychain send"
nd() { "$BIN/near-drive" --no-interactive --account "$ALICE" "$@" </dev/null; }

echo "== keys from near-cli"
out=$(nd whoami)
grep -q "signing:  $ALICE_PK (full-access key" <<<"$out" || { echo "$out"; die "whoami should find alice's full-access key"; }
ok "whoami finds the full-access key in near-cli's legacy keychain"

nd login >"$T/login.log" 2>&1 || { cat "$T/login.log"; die "login"; }
out=$(nd whoami)
SESSION_PK=$(sed -n 's/^signing:  \(ed25519:[^ ]*\) (NEAR Drive session key.*/\1/p' <<<"$out")
[ -n "$SESSION_PK" ] || { echo "$out"; die "whoami should use the session key after login"; }
ls "$CREDS/sandbox/$ALICE/" | grep -q "${SESSION_PK/:/_}.json" || die "session key not in near-cli's keychain dir"
perm=$(curl -s "$RPC" -H 'content-type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_access_key\",\"finality\":\"final\",\"account_id\":\"$ALICE\",\"public_key\":\"$SESSION_PK\"}}")
grep -q "\"receiver_id\":\"$DRIVE\"" <<<"$perm" || { echo "$perm"; die "session key should be a function-call key for $DRIVE"; }
ok "login: near-cli added a function-call key for $DRIVE and stored it ($SESSION_PK)"

echo "== storage with the session key"
nd keygen --random 2>/dev/null
head -c 300000 /dev/urandom >"$T/blob"
nd put "$T/blob" "near://$ALICE/docs/blob.bin" 2>/dev/null
nd get "near://$ALICE/docs/blob.bin" "$T/blob.out"
cmp -s "$T/blob" "$T/blob.out" || die "roundtrip mismatch"
nd ls | grep -q "docs/blob.bin" || die "ls"
ok "put/get/ls signed by the session key (gateway checked it onchain)"

echo "== transactions through near-cli"
nd grant "near://$ALICE/shared/" --read bob.test.near >"$T/grant.log" 2>&1 || { cat "$T/grant.log"; die "grant"; }
nd rules "$ALICE" | grep -q '"bob.test.near"' || die "rules should show bob"
ok "grant: set_rules sent by near-cli; rules read back"
key=$(nd publish-key 2>"$T/pk.log") || { cat "$T/pk.log"; die "publish-key"; }
onchain=$("$NEAR" contract call-function as-read-only "$DRIVE" get_enc_key json-args "{\"account_id\":\"$ALICE\"}" network-config sandbox now 2>/dev/null | tr -d '"[:space:]')
[ "$onchain" = "$key" ] || die "published key $key != onchain $onchain"
ok "publish-key: set_enc_key sent by near-cli"

if python3 -c 'import pexpect' 2>/dev/null; then
  # Interactive: near-drive asks for the rule, then near-cli asks for the signer.
  NEAR_DRIVE_NEAR_SIGN= BIN="$BIN" ALICE="$ALICE" python3 - <<'PY' || die "interactive grant"
import os, pexpect
env = dict(os.environ, TERM="xterm", NO_COLOR="1")
env.pop("NEAR_DRIVE_NEAR_SIGN")
p = pexpect.spawn(os.environ["BIN"] + "/near-drive", ["--account", os.environ["ALICE"], "grant"], env=env, encoding="utf-8", timeout=60, dimensions=(40, 200))
p.expect("Folder")
p.send("team/\r")  # appended to the suggested near://<account>/
p.expect("Who can read"); p.send("carol.test.near\r")
p.expect("Who can write"); p.send("\r")
p.expect("Who pays"); p.send("\r")
p.expect("grant near://\\S+/team/ --read carol.test.near")
p.expect("Select a tool for signing"); p.send("legacy"); p.send("\r")
p.expect("How would you like to proceed"); p.send("\r")  # send
p.expect('"carol.test.near"')
p.expect(pexpect.EOF)
PY
  nd rules "$ALICE" | grep -q '"carol.test.near"' || die "interactive grant not applied"
  ok "interactive grant: rule prompts, then near-cli's own signer menu"
fi

echo "== as a near-cli extension"
out=$(PATH="$BIN:$PATH" "$NEAR" drive --no-interactive --account "$ALICE" ls "near://$ALICE/docs/" </dev/null)
grep -q "docs/blob.bin" <<<"$out" || { echo "$out"; die "near drive ls"; }
PATH="$BIN:$PATH" "$NEAR" drive --help | grep -q "NEAR Drive" || die "near drive --help"
ok "\`near drive ...\` runs near-drive"

echo "== logout"
nd logout >"$T/logout.log" 2>&1 || { cat "$T/logout.log"; die "logout"; }
out=$(nd whoami)
grep -q "signing:  $ALICE_PK (full-access key" <<<"$out" || { echo "$out"; die "after logout whoami should fall back to the full-access key"; }
ok "logout: session key deleted onchain"

echo
echo "$pass passed"
