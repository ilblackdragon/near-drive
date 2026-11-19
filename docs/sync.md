# Synced folders

A local folder kept in two-way sync with a NEAR Drive folder, like Dropbox, on Linux, macOS and Windows. It is a real
folder (no kernel drivers or virtual file system), so it works offline and with every app.

```sh
near drive sync add ~/NearDrive               # <-> near://<you>/Drive/   (or: sync add ~/Work Work/)
near drive up                                 # keep registered folders in sync in the background (--no-s3: no S3 endpoint)
near drive sync status                        # last sync, conflicts, errors per folder
near drive sync run ~/NearDrive [--watch]     # sync now in the foreground instead
near drive sync remove ~/NearDrive            # stop syncing (the files stay)
```

## How it behaves

- **Encrypted** like any other upload: the gateway and storage only see ciphertext. Every device of the account with
  the same encryption key (`keygen --ckd` derives it anywhere) sees the same files.
- **Changes** on this device are noticed right away (file-system events), changes elsewhere within 30 seconds. A file
  is uploaded once it has been unchanged for 2 seconds, so half-saved files don't go up. Touching a file without
  changing it transfers nothing.
- **Nothing is overwritten unseen.** An upload or delete only happens if the remote file is still the version this
  device last synced. If both sides changed a file, the remote version keeps the name and yours is saved next to it
  as `name (conflicted copy from <device> <date>).ext` and uploaded too. The same content on both sides (for example
  a copied folder) is not a conflict.
- **Deletes.** A file deleted on another device is moved to `<folder>/.near-drive/trash/` here, not removed. A file
  you delete is deleted remotely, unless it changed there. A file edited on one side and deleted on the other is kept.
- **Transfers** are chunked, parallel, retried and resumable. Downloads land in a hidden temporary file and replace
  the target in one step. Edits made offline go up when the gateway is reachable again.
- **File names.** Names a system can't hold (on Windows: `<>:"|?*`, `CON`, trailing dots; on macOS and Windows: two
  names that differ only in case) are skipped and reported in `sync status`, never deleted. Accented names written on
  macOS match the same names from other systems. OS clutter (`.DS_Store`, `Thumbs.db`, `~$*`, `*.tmp`, partial
  downloads) is not synced.
- **Where things live.** Sync state, trash and temporary files: `<folder>/.near-drive/` (never synced). Registered
  folders: `~/.near-drive/sync.json`. The background service re-reads it, so `sync add` / `remove` take effect within
  seconds. Log: `~/.near-drive/daemon.log`.

## Not yet

Files on demand (placeholders that download when opened: Windows Cloud Files API, macOS File Provider, FUSE on
Linux), choosing which subfolders to sync, push notifications instead of polling, and a tray / menu-bar app.
