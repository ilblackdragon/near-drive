#!/bin/sh
# Build drive.near and the sandbox-test mocks to contracts/target/near/.
set -e
cd "$(dirname "$0")"
cargo near build non-reproducible-wasm --manifest-path drive/Cargo.toml "$@"
cargo near build non-reproducible-wasm --no-abi --manifest-path mock-ft/Cargo.toml
cargo near build non-reproducible-wasm --no-abi --manifest-path mock-mt/Cargo.toml
