// macOS File Provider extension: NEAR Drive in Finder's sidebar, files
// download when opened (with Finder's own progress and "Remove Download").
// All storage work happens in the Rust background service; see DriveAPI.
import FileProvider

final class FileProviderExtension: NSObject, NSFileProviderReplicatedExtension {
    let domain: NSFileProviderDomain

    required init(domain: NSFileProviderDomain) {
        self.domain = domain
        super.init()
    }

    func invalidate() {}

    /// Run `body` and report through `done`, returning a Progress for the system.
    private func run(_ body: @escaping () async throws -> Void, onError: @escaping (Error) -> Void) -> Progress {
        let progress = Progress(totalUnitCount: 1)
        Task {
            do { try await body() } catch { onError(error.fileProviderError) }
            progress.completedUnitCount = 1
        }
        return progress
    }

    private func id(parent: NSFileProviderItemIdentifier, name: String, folder: Bool) -> String {
        parent.driveID + name + (folder ? "/" : "")
    }

    // MARK: - Reading

    func item(for identifier: NSFileProviderItemIdentifier, request: NSFileProviderRequest,
              completionHandler: @escaping (NSFileProviderItem?, Error?) -> Void) -> Progress {
        if identifier == .rootContainer {
            completionHandler(FileProviderItem.root(), nil)
            return Progress()
        }
        return run({
            completionHandler(FileProviderItem(try await DriveAPI.shared().item(identifier.driveID)), nil)
        }, onError: { completionHandler(nil, $0) })
    }

    func fetchContents(for itemIdentifier: NSFileProviderItemIdentifier, version requestedVersion: NSFileProviderItemVersion?,
                       request: NSFileProviderRequest, completionHandler: @escaping (URL?, NSFileProviderItem?, Error?) -> Void) -> Progress {
        run({
            let manager = NSFileProviderManager(for: self.domain)
            let dir = try manager?.temporaryDirectoryURL() ?? FileManager.default.temporaryDirectory
            let dest = dir.appendingPathComponent(UUID().uuidString)
            let item = try await DriveAPI.shared().download(itemIdentifier.driveID, to: dest)
            completionHandler(dest, FileProviderItem(item), nil)
        }, onError: { completionHandler(nil, nil, $0) })
    }

    // MARK: - Writing

    func createItem(basedOn itemTemplate: NSFileProviderItem, fields: NSFileProviderItemFields, contents url: URL?,
                    options: NSFileProviderCreateItemOptions = [], request: NSFileProviderRequest,
                    completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void) -> Progress {
        let folder = itemTemplate.contentType == .folder
        let newID = id(parent: itemTemplate.parentItemIdentifier, name: itemTemplate.filename, folder: folder)
        return run({
            let api = try DriveAPI.shared()
            let item = folder ? try await api.createFolder(newID) : try await api.upload(newID, from: url, baseSeq: 0)
            completionHandler(FileProviderItem(item), [], false, nil)
        }, onError: { completionHandler(nil, [], false, $0) })
    }

    func modifyItem(_ item: NSFileProviderItem, baseVersion version: NSFileProviderItemVersion, changedFields: NSFileProviderItemFields,
                    contents newContents: URL?, options: NSFileProviderModifyItemOptions = [], request: NSFileProviderRequest,
                    completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void) -> Progress {
        let folder = item.contentType == .folder
        var currentID = item.itemIdentifier.driveID
        let targetID = id(parent: item.parentItemIdentifier, name: item.filename, folder: folder)
        return run({
            let api = try DriveAPI.shared()
            var result: DriveItem?
            // Move / rename first, then new contents under the new name.
            if (changedFields.contains(.filename) || changedFields.contains(.parentItemIdentifier)) && targetID != currentID {
                result = try await api.rename(from: currentID, to: targetID)
                currentID = targetID
            }
            if changedFields.contains(.contents), !folder, let newContents {
                let base = result?.seq ?? Version.seq(version)
                do {
                    result = try await api.upload(currentID, from: newContents, baseSeq: base)
                } catch DriveError.conflict {
                    // Changed elsewhere meanwhile: keep this version as a
                    // conflicted copy and take the remote one under the name.
                    let ext = (item.filename as NSString).pathExtension
                    let stem = (item.filename as NSString).deletingPathExtension
                    let copyName = "\(stem) (conflicted copy from \(Host.current().localizedName ?? "Mac"))" + (ext.isEmpty ? "" : ".\(ext)")
                    _ = try await api.upload(self.id(parent: item.parentItemIdentifier, name: copyName, folder: false), from: newContents, baseSeq: 0)
                    completionHandler(FileProviderItem(try await api.item(currentID)), [], true, nil)
                    return
                }
            }
            let final = try await result ?? api.item(currentID)
            completionHandler(FileProviderItem(final), [], false, nil)
        }, onError: { completionHandler(nil, [], false, $0) })
    }

    func deleteItem(identifier: NSFileProviderItemIdentifier, baseVersion version: NSFileProviderItemVersion,
                    options: NSFileProviderDeleteItemOptions = [], request: NSFileProviderRequest,
                    completionHandler: @escaping (Error?) -> Void) -> Progress {
        run({
            try await DriveAPI.shared().delete(identifier.driveID, seq: Version.seq(version))
            completionHandler(nil)
        }, onError: { completionHandler($0) })
    }

    // MARK: - Enumeration

    func enumerator(for containerItemIdentifier: NSFileProviderItemIdentifier, request: NSFileProviderRequest) throws -> NSFileProviderEnumerator {
        if containerItemIdentifier == .trashContainer {
            throw NSFileProviderError(.noSuchItem) // deletes are final (no remote trash)
        }
        return Enumerator(container: containerItemIdentifier)
    }
}
