#!/bin/sh
# NEAR Drive installer for Linux and macOS.
#
#   curl -fsSL https://github.com/ilblackdragon/near-drive/releases/latest/download/install.sh | sh
#
# Installs near-drive, near-drive-gateway and near-drive-tray from the latest
# GitHub release into ~/.local/bin (override with NEAR_DRIVE_INSTALL_DIR), after
# checking the archive against the release's SHA256SUMS.
# NEAR_DRIVE_VERSION=v0.1.0 pins a version.
set -eu

REPO="ilblackdragon/near-drive"
VERSION="${NEAR_DRIVE_VERSION:-latest}"
INSTALL_DIR="${NEAR_DRIVE_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*" >&2; }
die() { say "error: $*"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "needs '$1'"; }

need uname
need tar
if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  die "needs curl or wget"
fi

os=$(uname -s)
arch=$(uname -m)
case "$os" in
  Linux)
    case "$arch" in
      x86_64 | amd64) target=x86_64-unknown-linux-gnu ;;
      aarch64 | arm64) target=aarch64-unknown-linux-gnu ;;
      *) die "no prebuilt binary for Linux $arch; build from source: cargo install --git https://github.com/$REPO near-drive-cli" ;;
    esac ;;
  Darwin) target=universal-apple-darwin ;;
  *) die "unsupported OS $os (Windows: use install.ps1)" ;;
esac

if [ -n "${NEAR_DRIVE_DOWNLOAD_BASE:-}" ]; then
  base="$NEAR_DRIVE_DOWNLOAD_BASE" # mirrors / tests
elif [ "$VERSION" = latest ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi
asset="near-drive-$target.tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading NEAR Drive ($VERSION, $target)..."
fetch "$base/$asset" "$tmp/$asset" || die "download failed: $base/$asset"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "download failed: $base/SHA256SUMS"

expected=$(grep " $asset\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)
[ -n "$expected" ] || die "$asset is not listed in SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$asset" | cut -d' ' -f1)
else
  actual=$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1)
fi
[ "$expected" = "$actual" ] || die "checksum mismatch for $asset (expected $expected, got $actual)"

tar xzf "$tmp/$asset" -C "$tmp"
mkdir -p "$INSTALL_DIR"
for b in near-drive near-drive-gateway near-drive-tray; do
  src="$tmp/near-drive-$target/$b"
  [ -f "$src" ] || continue
  # Replace atomically (works while an old copy is running).
  cp "$src" "$INSTALL_DIR/.$b.new"
  chmod 755 "$INSTALL_DIR/.$b.new"
  mv -f "$INSTALL_DIR/.$b.new" "$INSTALL_DIR/$b"
done

say "Installed $("$INSTALL_DIR/near-drive" --version) to $INSTALL_DIR"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) say ""
     say "Add it to your PATH, e.g.:"
     say "  echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.profile && . ~/.profile" ;;
esac
if ! command -v near >/dev/null 2>&1; then
  say ""
  say "NEAR Drive uses near-cli-rs for your NEAR keys; install it with:"
  say "  curl --proto '=https' --tlsv1.2 -LsSf https://github.com/near/near-cli-rs/releases/latest/download/near-cli-rs-installer.sh | sh"
fi
if [ "$os" = Linux ] && ! command -v fusermount3 >/dev/null 2>&1; then
  say ""
  say "For 'near drive mount' (files on demand) install FUSE 3, e.g. 'sudo apt install fuse3'."
fi
say ""
say "Get started: near drive login"
