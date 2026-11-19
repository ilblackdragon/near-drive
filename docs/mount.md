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
| macOS | FUSE | [macFUSE](https://osxfuse.github.io) or [FUSE-T](https://www.fuse-t.org), and a build with `--features macfuse` (`cargo install --git … near-drive-cli --features macfuse`) |
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
