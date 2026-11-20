# Installing NEAR Drive

Prebuilt binaries for every release are on the [releases page](https://github.com/ilblackdragon/near-drive/releases):

| platform | archive |
|---|---|
| Linux x86_64 (glibc 2.35+: Ubuntu 22.04, Debian 12, Fedora 36 and newer) | `near-drive-x86_64-unknown-linux-gnu.tar.gz` |
| Linux arm64 | `near-drive-aarch64-unknown-linux-gnu.tar.gz` |
| macOS 11+ (Apple Silicon and Intel, universal) | `near-drive-universal-apple-darwin.tar.gz` |
| Windows 10 / 11 x64 (also runs on Windows on Arm) | `near-drive-x86_64-pc-windows-msvc.zip` |

Each archive holds `near-drive` (the CLI, also `near drive`), `near-drive-gateway` and `near-drive-tray`.
`SHA256SUMS` lists the checksum of every archive.

## Quick install

**Linux / macOS**

```sh
curl -fsSL https://github.com/ilblackdragon/near-drive/releases/latest/download/install.sh | sh
```

Installs into `~/.local/bin` (set `NEAR_DRIVE_INSTALL_DIR` to change it) and tells you if that isn't on your `PATH`.

**Windows** (PowerShell)

```powershell
irm https://github.com/ilblackdragon/near-drive/releases/latest/download/install.ps1 | iex
```

Installs into `%LOCALAPPDATA%\NEAR Drive\bin` and adds it to your user `PATH` (open a new terminal afterwards).

Both installers verify the archive against `SHA256SUMS` before installing, and accept `NEAR_DRIVE_VERSION=v0.1.0` to
pin a version. Running them again upgrades in place.

## Homebrew (macOS, Linux)

This repository is also a Homebrew tap:

```sh
brew tap ilblackdragon/near-drive https://github.com/ilblackdragon/near-drive
brew install near-drive
```

`brew upgrade near-drive` picks up new releases (the formula in `Formula/` is regenerated for every release).

## winget (Windows)

```powershell
winget install ilblackdragon.NEARDrive
```

The manifests live in `packaging/winget/manifests/` and are submitted to
[microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) for each release; until a version is merged there,
install it from the manifest directly (needs `winget settings --enable LocalManifestFiles` once, as administrator):

```powershell
winget install --manifest packaging\winget\manifests\i\ilblackdragon\NEARDrive\0.1.0
```

## Then

1. Install [near-cli-rs](https://github.com/near/near-cli-rs), which keeps your NEAR keys (the installers print the
   command if `near` is missing):
   ```sh
   curl --proto '=https' --tlsv1.2 -LsSf https://github.com/near/near-cli-rs/releases/latest/download/near-cli-rs-installer.sh | sh
   ```
   ```powershell
   irm https://github.com/near/near-cli-rs/releases/latest/download/near-cli-rs-installer.ps1 | iex
   ```
2. `near drive login` and `near drive keygen --ckd` (see the [quick start](../README.md#quick-start)).
3. Optional, per feature:
   - **Files on demand on Linux** (`near drive mount`): FUSE 3, e.g. `sudo apt install fuse3` / `sudo dnf install fuse3`.
   - **Tray icon on Linux**: a desktop with StatusNotifierItem support (KDE, XFCE, Cinnamon; GNOME with the
     AppIndicator extension). Start `near-drive-tray` from your session's autostart.
   - **Finder integration on macOS**: build the File Provider app in `macos/` ([mount.md](mount.md#macos-file-provider)).

## Manual install

Download the archive for your platform and `SHA256SUMS`, then:

```sh
sha256sum -c --ignore-missing SHA256SUMS        # macOS: shasum -a 256 -c --ignore-missing SHA256SUMS
tar xzf near-drive-<target>.tar.gz
cp near-drive-<target>/near-drive* ~/.local/bin/
```

On Windows, check with `Get-FileHash near-drive-x86_64-pc-windows-msvc.zip`, extract, and put the `.exe` files in a
folder on your `PATH`.

**macOS:** the binaries are not notarized. Installing with `curl` (as above) is fine; if you downloaded the archive
with a browser, clear the quarantine flag first: `xattr -d com.apple.quarantine near-drive*`.

## From source

With [Rust](https://rustup.rs):

```sh
cargo install --git https://github.com/ilblackdragon/near-drive near-drive-cli          # near-drive
cargo install --git https://github.com/ilblackdragon/near-drive near-drive-tray         # tray app
cargo install --git https://github.com/ilblackdragon/near-drive near-drive-gateway      # to run a gateway
```

On macOS add `--features macfuse` to the CLI to get the FUSE-based `near drive mount` (needs macFUSE or FUSE-T).

## Uninstall

`near drive down`, then delete the binaries (`~/.local/bin/near-drive*` or `%LOCALAPPDATA%\NEAR Drive`). Settings
are in `~/.near-drive`; synced folders keep their files.

**`~/.near-drive/keys/` holds your encryption root keys** (`<account>.root`). Deleting it without a backup makes your
private files unreadable, unless the key came from `keygen --ckd` (then `keygen --ckd` derives it again). Back each key
up first:

```sh
near drive --account <you> key export --out <file on a USB stick / password manager>   # restore: near drive key import --file <file>
```

## Releasing (maintainers)

Push a tag: `git tag v0.2.0 && git push origin v0.2.0`. `.github/workflows/release.yml`:
1. builds all platforms and publishes the release with `SHA256SUMS`, `install.sh` and `install.ps1`;
2. installs it with both installers on Linux, macOS and Windows as a check;
3. runs `packaging.yml`: regenerates `Formula/near-drive.rb` and the winget manifests from the release's checksums
   (`packaging/generate.py`), validates the manifests against the winget schema, commits them to `main`, and
   installs + tests the formula with Homebrew on macOS and Linux.

Then submit the winget manifests (once per release), e.g. with
[wingetcreate](https://github.com/microsoft/winget-create):
`wingetcreate submit packaging/winget/manifests/i/ilblackdragon/NEARDrive/<version>` (or open a PR to
microsoft/winget-pkgs with that folder). Bump `version` in the workspace `Cargo.toml` before tagging.
