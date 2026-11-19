#!/usr/bin/env bash
# Cross-language interop: Rust (`nst`), TypeScript (@nstorage/sdk) and Python (nstorage)
# against one real gateway on 127.0.0.1.
#
#   testvectors/interop.sh            # build everything, run the matrix
#   SKIP_BUILD=1 testvectors/interop.sh
#
# Covers: every writer x every reader (small, multi-chunk, empty, unicode path, public),
# sharing via `--share` at write time and `share` afterwards (x25519 keys taken from
# `whoami`), app-writes-for-user (writer has no root key), ls and rm. Also regenerates
# the SDK-encrypted object vectors and runs the Rust test that decrypts them.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HEAVY="${HEAVY:-/data/illia/nearproof-deps/bin/heavy}"
[ -x "$HEAVY" ] || HEAVY=""
TS="$ROOT/sdk/ts"
PY="$ROOT/sdk/python"
NST="$ROOT/target/debug/nst"
GW="$ROOT/target/debug/nstorage-gateway"

log() { printf '\n== %s\n' "$*"; }

if [ -z "${SKIP_BUILD:-}" ]; then
  log "build rust"
  (cd "$ROOT" && $HEAVY cargo build -j 8 --bins) || exit 1
  log "build ts"
  (cd "$TS" && { [ -d node_modules ] || npm install --no-audit --no-fund; } && npm run build --silent) || exit 1
  log "python venv"
  if [ ! -x "$PY/.venv/bin/python" ]; then
    python3 -m venv "$PY/.venv" && "$PY/.venv/bin/pip" install -q -e "$PY[test]" || exit 1
  fi
fi
PYBIN="$PY/.venv/bin/python"

WORK="$(mktemp -d -t nst-interop.XXXXXX)"
GW_PID=""
cleanup() {
  [ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null
  [ -z "${KEEP:-}" ] && rm -rf "$WORK"
}
trap cleanup EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }

export NSTORAGE_HOME="$WORK/home"
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
export NSTORAGE_GATEWAY="http://127.0.0.1:$PORT"

# run <lang> <account> <args...>
run() {
  local lang=$1 acct=$2
  shift 2
  local envs=(NSTORAGE_ACCOUNT="$acct" NSTORAGE_CREDENTIALS="$WORK/$acct.json")
  case $lang in
    rs) env "${envs[@]}" "$NST" "$@" ;;
    ts) env "${envs[@]}" node "$TS/scripts/nst-ts.mjs" "$@" ;;
    py) env "${envs[@]}" "$PYBIN" -m nstorage "$@" ;;
  esac
}

log "accounts + gateway (127.0.0.1:$PORT)"
declare -A PK
for a in alice.near bob.near app.near; do
  PK[$a]="$(NSTORAGE_ACCOUNT=$a "$NST" dev-key --out "$WORK/$a.json")"
done
NSTORAGE_ACCOUNT=alice.near "$NST" keygen 2>/dev/null
NSTORAGE_ACCOUNT=bob.near "$NST" keygen 2>/dev/null
# app.near deliberately has no root key: it can write for users but never read.
cat >"$WORK/gw.json" <<JSON
{"listen":"127.0.0.1:$PORT","data_dir":"$WORK/data",
 "dev_keys":{"alice.near":["${PK[alice.near]}"],"bob.near":["${PK[bob.near]}"],"app.near":["${PK[app.near]}"]},
 "policies":{
   "alice.near":[{"prefix":"shared/","read":["bob.near"],"write":[]}],
   "app.near":[{"prefix":"users/{account}/","read":["{account}"],"write":["{account}","app.near"],"payer":"app.near"}]}}
JSON
RUST_LOG=warn "$GW" --config "$WORK/gw.json" >"$WORK/gw.log" 2>&1 &
GW_PID=$!
for _ in $(seq 50); do curl -sf "$NSTORAGE_GATEWAY/healthz" >/dev/null && break; sleep 0.1; done
curl -sf "$NSTORAGE_GATEWAY/healthz" >/dev/null || { cat "$WORK/gw.log"; echo "gateway did not start"; exit 1; }

log "whoami: same x25519 key from all three languages"
for a in alice.near bob.near; do
  k_rs="$(run rs $a whoami | awk '/x25519:/{print $2}')"
  k_ts="$(run ts $a whoami | awk '/x25519:/{print $2}')"
  k_py="$(run py $a whoami | awk '/x25519:/{print $2}')"
  if [[ $k_rs == x25519:* && $k_rs == "$k_ts" && $k_rs == "$k_py" ]]; then ok "$a $k_rs"; else bad "$a rs=$k_rs ts=$k_ts py=$k_py"; fi
done
BOB_X="$(run rs bob.near whoami | awk '/x25519:/{print $2}')"

log "fixtures"
mkdir -p "$WORK/in" "$WORK/out"
printf 'hello nstorage\n' >"$WORK/in/small"
: >"$WORK/in/empty"
head -c 9437184 /dev/urandom >"$WORK/in/big" # 9 MiB = 3 chunks at the default 4 MiB
head -c 4096 /dev/urandom >"$WORK/in/public"

# expect_read <reader> <account> <uri> <expected file> <label>
expect_read() {
  local out="$WORK/out/r.$RANDOM"
  if run "$1" "$2" get "$3" "$out" 2>"$out.err" && cmp -s "$out" "$4"; then ok "$5"; else bad "$5: $(tail -1 "$out.err")"; fi
}
# expect_no_read <reader> <account> <uri> <label>
expect_no_read() {
  local out="$WORK/out/n.$RANDOM"
  if run "$1" "$2" get "$3" "$out" 2>"$out.err"; then bad "$4 (read succeeded)"; else ok "$4 ($(tail -1 "$out.err" | cut -c1-70))"; fi
}

LANGS="rs ts py"
log "owner writes -> owner reads (every writer x every reader)"
for w in $LANGS; do
  for f in small empty big; do
    run $w alice.near put "$WORK/in/$f" "near://alice.near/interop/$w/$f" 2>/dev/null || bad "$w put $f"
  done
  run $w alice.near put "$WORK/in/small" "near://alice.near/interop/$w/x y/ü 🙂+?#.txt" --content-type 'text/plain; charset="utf-8"' 2>/dev/null || bad "$w put unicode"
  run $w alice.near put "$WORK/in/public" "near://alice.near/interop/$w/public" --public 2>/dev/null || bad "$w put public"
done
for w in $LANGS; do
  for r in $LANGS; do
    for f in small empty big public; do
      expect_read $r alice.near "near://alice.near/interop/$w/$f" "$WORK/in/$f" "$w -> $r  $f"
    done
    expect_read $r alice.near "near://alice.near/interop/$w/x y/ü 🙂+?#.txt" "$WORK/in/small" "$w -> $r  unicode path"
  done
done

log "overwrite bumps seq; ls in every language"
for w in $LANGS; do
  run $w alice.near put "$WORK/in/big" "near://alice.near/interop/rs/small" 2>/dev/null || bad "$w overwrite"
done
expect_read py alice.near "near://alice.near/interop/rs/small" "$WORK/in/big" "after 3 overwrites, py reads latest"
for r in $LANGS; do
  out="$(run $r alice.near ls near://alice.near/interop/rs/)"
  if grep -q 'seq=4 .*interop/rs/small' <<<"$out" && [ "$(wc -l <<<"$out")" -eq 5 ]; then ok "$r ls (5 entries, seq=4)"; else bad "$r ls: $out"; fi
done

log "share at write time (--share bob's x25519) and afterwards (share)"
for w in $LANGS; do
  run $w alice.near put "$WORK/in/small" "near://alice.near/shared/$w/at-write" --share "$BOB_X" 2>/dev/null || bad "$w put --share"
  run $w alice.near put "$WORK/in/big" "near://alice.near/shared/$w/later" 2>/dev/null || bad "$w put later"
done
for w in $LANGS; do
  for r in $LANGS; do
    expect_read $r bob.near "near://alice.near/shared/$w/at-write" "$WORK/in/small" "alice($w) --share -> bob($r)"
    expect_read $r alice.near "near://alice.near/shared/$w/at-write" "$WORK/in/small" "alice($w) --share -> alice($r) still reads"
  done
  expect_no_read rs bob.near "near://alice.near/shared/$w/later" "bob cannot read $w object before share"
done
# share with a different language than the writer: rs->ts->py->rs
for pair in "rs ts" "ts py" "py rs"; do
  set -- $pair
  run "$2" alice.near share "near://alice.near/shared/$1/later" "$BOB_X" 2>/dev/null || bad "$2 share of $1 object"
done
for w in $LANGS; do
  for r in $LANGS; do
    expect_read $r bob.near "near://alice.near/shared/$w/later" "$WORK/in/big" "alice($w) put, shared later -> bob($r)"
  done
  expect_read $w alice.near "near://alice.near/shared/$w/later" "$WORK/in/big" "alice($w) still reads after share"
done

log "app writes for user (app.near has no root key; encrypts only to bob)"
for w in $LANGS; do
  run $w app.near put "$WORK/in/small" "near://app.near/users/bob.near/from-$w" --share "$BOB_X" 2>/dev/null || bad "app($w) put for bob"
done
for w in $LANGS; do
  for r in $LANGS; do
    expect_read $r bob.near "near://app.near/users/bob.near/from-$w" "$WORK/in/small" "app($w) -> bob($r)"
  done
  expect_no_read $w app.near "near://app.near/users/bob.near/from-$w" "app($w) cannot decrypt what it wrote"
  expect_no_read $w alice.near "near://app.near/users/bob.near/from-$w" "alice($w) denied by policy"
done

log "rm in every language"
for r in $LANGS; do
  if run $r alice.near rm "near://alice.near/interop/$r/big" && ! run rs alice.near get "near://alice.near/interop/$r/big" >/dev/null 2>&1; then
    ok "$r rm"
  else bad "$r rm"; fi
done

log "SDK-encrypted object vectors -> Rust decrypt (offline)"
# Emit fresh vectors into testvectors/ for the cargo test, then restore the committed ones.
for l in ts py; do cp "$ROOT/testvectors/sdk_objects_$l.json" "$WORK/committed_$l.json"; done
if node "$TS/scripts/emit-objects.mjs" "$ROOT/testvectors/sdk_objects_ts.json" &&
  "$PYBIN" "$PY/scripts/emit_objects.py" "$ROOT/testvectors/sdk_objects_py.json"; then
  if (cd "$ROOT" && $HEAVY cargo test -j 8 -q -p nstorage-core --test sdk_vectors >"$WORK/cargo-test.log" 2>&1); then
    ok "rust decrypts freshly encrypted TS + Python objects"
  else bad "rust sdk_vectors: $(tail -5 "$WORK/cargo-test.log")"; fi
else
  bad "emit sdk objects"
fi
for l in ts py; do cp "$WORK/committed_$l.json" "$ROOT/testvectors/sdk_objects_$l.json"; done

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
