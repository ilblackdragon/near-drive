import FileProvider

/// Lists a folder (or, for the working set, everything) and reports changes
/// since a sync anchor. Anchors come from the Rust service; one it no longer
/// remembers (e.g. after a restart) makes the system enumerate again.
final class Enumerator: NSObject, NSFileProviderEnumerator {
    let container: NSFileProviderItemIdentifier

    init(container: NSFileProviderItemIdentifier) {
        self.container = container
    }

    func invalidate() {}

    func enumerateItems(for observer: NSFileProviderEnumerationObserver, startingAt page: NSFileProviderPage) {
        Task {
            do {
                let api = try DriveAPI.shared()
                let items: [DriveItem]
                if container == .workingSet {
                    items = try await api.all().updated
                } else {
                    items = try await api.items(parent: container.driveID)
                }
                observer.didEnumerate(items.map(FileProviderItem.init))
                observer.finishEnumerating(upTo: nil)
            } catch {
                observer.finishEnumeratingWithError(error.fileProviderError)
            }
        }
    }

    func enumerateChanges(for observer: NSFileProviderChangeObserver, from anchor: NSFileProviderSyncAnchor) {
        Task {
            do {
                let api = try DriveAPI.shared()
                let since = Anchor.decode(anchor)
                let changes = try await api.changes(since: since)
                // Folder enumerators report only their direct children.
                let mine: (String) -> Bool = { parent in self.container == .workingSet || parent == self.container.driveID }
                let updated = changes.updated.filter { mine($0.parent) }
                let deleted = changes.deleted.filter { mine(Anchor.parent(of: $0)) }
                if !updated.isEmpty { observer.didUpdate(updated.map(FileProviderItem.init)) }
                if !deleted.isEmpty { observer.didDeleteItems(withIdentifiers: deleted.map { NSFileProviderItemIdentifier(driveID: $0) }) }
                observer.finishEnumeratingChanges(upTo: Anchor.encode(changes.anchor), moreComing: false)
            } catch DriveError.anchorExpired {
                observer.finishEnumeratingWithError(NSFileProviderError(.syncAnchorExpired))
            } catch {
                observer.finishEnumeratingWithError(error.fileProviderError)
            }
        }
    }

    func currentSyncAnchor(completionHandler: @escaping (NSFileProviderSyncAnchor?) -> Void) {
        Task {
            let anchor = try? await DriveAPI.shared().all().anchor
            completionHandler(anchor.map(Anchor.encode))
        }
    }
}

enum Anchor {
    static func encode(_ n: UInt64) -> NSFileProviderSyncAnchor {
        NSFileProviderSyncAnchor(Data(String(n).utf8))
    }

    static func decode(_ a: NSFileProviderSyncAnchor) -> UInt64 {
        UInt64(String(data: a.rawValue, encoding: .utf8) ?? "") ?? 0
    }

    static func parent(of id: String) -> String {
        let t = id.hasSuffix("/") ? String(id.dropLast()) : id
        guard let i = t.lastIndex(of: "/") else { return "" }
        return String(t[...i])
    }
}

extension Error {
    /// Map provider API errors to what the File Provider framework understands.
    var fileProviderError: Error {
        switch self as? DriveError {
        case .serviceUnavailable?: return NSFileProviderError(.serverUnreachable)
        case .unauthorized?: return NSFileProviderError(.notAuthenticated)
        case .notFound?: return NSFileProviderError(.noSuchItem)
        case .anchorExpired?: return NSFileProviderError(.syncAnchorExpired)
        case .conflict?: return NSFileProviderError(.filenameCollision)
        default: return self
        }
    }
}
