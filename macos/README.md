# NEAR Drive for macOS (File Provider)

Swift app + File Provider extension that shows NEAR Drive in Finder. The extension talks to the Rust background
service (`near drive up --file-provider`) over a loopback API; it holds no keys. See
[docs/mount.md](../docs/mount.md#macos-file-provider).

```sh
brew install xcodegen
xcodegen generate          # -> NEARDrive.xcodeproj (from project.yml)
open NEARDrive.xcodeproj   # set DEVELOPMENT_TEAM and APP_GROUP, run "NEARDrive"
```

| path | |
|---|---|
| `Shared/DriveAPI.swift` | client for the provider API (`provider.json` in the App Group container) |
| `FileProvider/FileProviderExtension.swift` | `NSFileProviderReplicatedExtension`: fetch, create, modify, rename, delete |
| `FileProvider/Enumerator.swift` | folder / working-set enumeration and change sets since a sync anchor |
| `FileProvider/Item.swift` | `NSFileProviderItem`; item versions carry the remote seq for conditional writes |
| `App/NEARDriveApp.swift` | menu-bar app: add / remove the Finder location, signal changes |
