# Files on demand: `near drive mount`

Shows a NEAR Drive folder as a drive: every file is listed with its real size and date, but nothing is downloaded
until a file is opened. Edits upload when the file is closed. Use it when the remote holds more than you want on disk;
use a [synced folder](sync.md) when you want everything available offline.

```sh
near drive mount ~/NEAR\ Drive               # near://<you>/Drive/ ; Ctrl-C to unmount
near drive mount /mnt/models models/ --read-only --cache-mib 50000
```

| platform | how | needs |
|---|---|---|
| Linux | FUSE | `/dev/fuse` and `fusermount3` (package `fuse3`); no libraries to build |
| macOS | **File Provider extension** (native: Finder sidebar, cloud badges, "Remove Download"), see [below](#macos-file-provider) | macOS 13+, the `macos/` app built and signed with your Apple Developer team |
| macOS (alternative) | FUSE | [macFUSE](https://osxfuse.github.io) or [FUSE-T](https://www.fuse-t.org), and a build with `--features macfuse` |
| Windows | Cloud Files API, like OneDrive: placeholders with cloud icons in an ordinary folder; Explorer shows download state | Windows 10 1709+ on NTFS |

## Behaviour

- **Reading** downloads the file's current version (verified and decrypted) into a local cache
  (`~/.near-drive/cache/<account>`; Windows: into the placeholder itself). Least recently used files are evicted
  above `--cache-mib` (default 10 GiB); open files are never evicted. On Windows, "Free up space" in Explorer
  dehydrates files.
- **Writing** happens on a private copy, uploaded end-to-end encrypted when the file is closed, as a conditional
  write on the version it was based on. If the file changed elsewhere meanwhile, nothing is overwritten: your version
  is saved next to it as `name (conflicted copy from <device> <date>).ext`.
- **Rename, move, delete** and new folders work as usual and are applied remotely (renames copy and delete, so
  renaming a large folder takes time). Empty folders exist locally until something is put in them.
- **Changes made elsewhere** appear within seconds (gateway change notifications), and the kernel's cached copy of a
  changed file is dropped, so the next open reads the new version.
- **Offline:** what is in the cache stays readable; listing shows the last known tree.
- Close waits for the upload, so saving a large file blocks until it is stored.

## Windows notes

- The folder is registered as a Cloud Files sync root named "NEAR Drive (<remote>)" and appears in Explorer's
  navigation pane. `near drive mount` keeps it connected; after Ctrl-C the placeholders stay and the files that were
  downloaded stay readable. Running `mount` again on the same folder reconnects.
- Folders are listed the first time they are opened; new files you create are uploaded about 2 s after they stop
  changing and then show as in sync.

## macOS File Provider

The native way on macOS: "NEAR Drive" appears in Finder's sidebar like iCloud Drive; files show cloud badges, download
when opened, and can be evicted with "Remove Download".

How it fits together:
- `near drive up --file-provider [remote]` (default `Drive/`) adds a **provider API** to the background service:
  loopback HTTP with a random bearer token, published to `~/.near-drive/provider.json` and to the App Group container
  (`~/Library/Group Containers/<group>/provider.json`; group from `NEAR_DRIVE_APP_GROUP`, default
  `group.ai.near.drive`). The Rust service keeps the NEAR keys and does all encryption, retries and resumable
  transfers; see `crates/near-drive-mount/src/provider.rs`.
- `macos/` is the Swift side: a sandboxed `NSFileProviderReplicatedExtension` that maps Finder's requests to that
  API (enumerate, fetch contents, create / modify / rename / delete, change sets since a sync anchor), and a small
  menu-bar app that registers the File Provider domain and signals Finder when the remote changes.
- Writes are conditional on the version Finder based its change on; if the file changed elsewhere, your version is
  uploaded as a "conflicted copy" next to it.

Building (needs Xcode and an Apple Developer team, because File Provider extensions and App Groups require signing):

```sh
brew install xcodegen
cd macos && xcodegen generate && open NEARDrive.xcodeproj
# set DEVELOPMENT_TEAM, and an App Group you own in APP_GROUP (project.yml), then run the NEARDrive scheme
near drive up --file-provider          # with NEAR_DRIVE_APP_GROUP set to the same group
```

Then choose "Add NEAR Drive to Finder" in the menu-bar icon. CI builds the app and extension (unsigned) on every
push; running it needs your signing identity, so it has not been run end to end yet.
