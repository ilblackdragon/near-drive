#!/bin/sh
# Reproducible build of the drive.near contract.
#
#   contracts/build-reproducible.sh [git-rev] [out-dir]
#
# Clones the public repository at <git-rev> (default: origin/main) into a
# temporary directory and runs `cargo near build reproducible-wasm`: the build
# runs in the Docker image pinned (by digest) in contracts/drive/Cargo.toml,
# so anyone gets the same bytes. The wasm records the image, command and
# source commit (NEP-330 `contract_source_metadata`).
# Needs: git, docker, cargo-near (`cargo install cargo-near`).
set -eu
REPO="${NEAR_DRIVE_REPO:-https://github.com/ilblackdragon/near-drive.git}"
REV="${1:-main}"
OUT="${2:-$(pwd)/contracts/res}"

command -v docker >/dev/null || { echo "needs docker" >&2; exit 1; }
cargo near --version >/dev/null 2>&1 || { echo "needs cargo-near: cargo install cargo-near" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
git clone --quiet "$REPO" "$work/src"
git -C "$work/src" checkout --quiet "$REV"
commit=$(git -C "$work/src" rev-parse HEAD)
echo "building drive.near reproducibly from $REPO @ $commit" >&2

(cd "$work/src/contracts/drive" && cargo near build reproducible-wasm) >&2

built="$work/src/contracts/target/near/near_drive_contract"
mkdir -p "$OUT"
cp "$built/near_drive_contract.wasm" "$OUT/"
# The ABI is embedded in the wasm (`__contract_abi`); the JSON exists only when built outside Docker.
[ -f "$built/near_drive_contract_abi.json" ] && cp "$built/near_drive_contract_abi.json" "$OUT/"
hex=$(sha256sum "$OUT/near_drive_contract.wasm" | cut -d' ' -f1)
b58=$(python3 -c "import sys,hashlib
alpha='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
n=int(sys.argv[1],16); s=''
while n: n,r=divmod(n,58); s=alpha[r]+s
print(s)" "$hex")
echo "$hex  near_drive_contract.wasm" > "$OUT/near_drive_contract.wasm.sha256"
echo "commit:      $commit"
echo "wasm:        $OUT/near_drive_contract.wasm ($(wc -c <"$OUT/near_drive_contract.wasm") bytes)"
echo "sha256 hex:  $hex"
echo "code hash:   $b58   (what NEAR reports for a deployed contract)"
