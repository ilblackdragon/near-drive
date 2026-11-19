import FileProvider
import UniformTypeIdentifiers

extension NSFileProviderItemIdentifier {
    /// Provider API id: "" for the root, `a/` for folders, `a/b.txt` for files.
    var driveID: String {
        self == .rootContainer ? "" : rawValue
    }

    init(driveID: String) {
        self = driveID.isEmpty ? .rootContainer : NSFileProviderItemIdentifier(driveID)
    }
}

/// Item versions carry the remote seq, so uploads and deletes can be
/// conditional on the version the system based its change on.
enum Version {
    static func make(seq: UInt64, cid: String) -> NSFileProviderItemVersion {
        let v = Data("\(seq):\(cid)".utf8)
        return NSFileProviderItemVersion(contentVersion: v, metadataVersion: v)
    }

    static func seq(_ v: NSFileProviderItemVersion?) -> UInt64 {
        guard let v, let s = String(data: v.contentVersion, encoding: .utf8), let n = s.split(separator: ":").first else { return 0 }
        return UInt64(n) ?? 0
    }
}

final class FileProviderItem: NSObject, NSFileProviderItem {
    let item: DriveItem

    init(_ item: DriveItem) {
        self.item = item
    }

    static func root() -> FileProviderItem {
        FileProviderItem(DriveItem(id: "", parent: "", name: "NEAR Drive", is_dir: true, size: 0, seq: 0, cid: "", mtime_ms: 0))
    }

    var itemIdentifier: NSFileProviderItemIdentifier { NSFileProviderItemIdentifier(driveID: item.id) }
    var parentItemIdentifier: NSFileProviderItemIdentifier { NSFileProviderItemIdentifier(driveID: item.parent) }
    var filename: String { item.name }

    var contentType: UTType {
        item.is_dir ? .folder : (UTType(filenameExtension: (item.name as NSString).pathExtension) ?? .data)
    }

    var documentSize: NSNumber? { item.is_dir ? nil : NSNumber(value: item.size) }

    var contentModificationDate: Date? {
        item.mtime_ms == 0 ? nil : Date(timeIntervalSince1970: TimeInterval(item.mtime_ms) / 1000)
    }

    var creationDate: Date? { contentModificationDate }

    var capabilities: NSFileProviderItemCapabilities {
        item.is_dir
            ? [.allowsReading, .allowsContentEnumerating, .allowsAddingSubItems, .allowsRenaming, .allowsReparenting, .allowsDeleting]
            : [.allowsReading, .allowsWriting, .allowsRenaming, .allowsReparenting, .allowsDeleting]
    }

    var itemVersion: NSFileProviderItemVersion { Version.make(seq: item.seq, cid: item.cid) }
}
