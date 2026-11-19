// Client for the local provider API served by `near drive up --file-provider`
// (crates/near-drive-mount/src/provider.rs). The Rust service holds the NEAR
// keys and does all encryption; this side only moves bytes and metadata.
import Foundation

/// Where to find the API: `provider.json` in the App Group container,
/// written by the background service.
struct Endpoint: Decodable {
    let url: String
    let token: String
    let remote: String
}

/// One file or folder. Ids are paths below the synced prefix: files `a/b.txt`,
/// folders `a/` (trailing slash), the root `""`.
struct DriveItem: Codable, Equatable {
    let id: String
    let parent: String
    let name: String
    let is_dir: Bool
    let size: UInt64
    let seq: UInt64
    let cid: String
    let mtime_ms: UInt64
}

struct DriveChanges: Decodable {
    let anchor: UInt64
    let updated: [DriveItem]
    let deleted: [String]
}

enum DriveError: Error {
    /// The background service isn't running (or hasn't published its endpoint).
    case serviceUnavailable
    case notFound
    /// Changed elsewhere; `current` is the remote version now (0 = gone).
    case conflict(current: UInt64)
    /// Sync anchor too old: enumerate again.
    case anchorExpired
    case unauthorized
    case server(Int, String)
}

enum AppGroup {
    /// From Info.plist (`NEARDriveAppGroup`), set by the build setting APP_GROUP.
    static var identifier: String {
        Bundle.main.object(forInfoDictionaryKey: "NEARDriveAppGroup") as? String ?? "group.ai.near.drive"
    }

    static var container: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: identifier)
    }
}

final class DriveAPI {
    let endpoint: Endpoint
    private let session: URLSession

    init(endpoint: Endpoint) {
        self.endpoint = endpoint
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 120
        cfg.timeoutIntervalForResource = 7 * 24 * 3600
        session = URLSession(configuration: cfg)
    }

    /// Reads the endpoint fresh each time: the service picks a new port and
    /// token whenever it restarts.
    static func shared() throws -> DriveAPI {
        guard let dir = AppGroup.container,
              let data = try? Data(contentsOf: dir.appendingPathComponent("provider.json")),
              let ep = try? JSONDecoder().decode(Endpoint.self, from: data)
        else { throw DriveError.serviceUnavailable }
        return DriveAPI(endpoint: ep)
    }

    private func url(_ path: String, _ query: [String: String] = [:]) -> URL {
        var c = URLComponents(string: endpoint.url + path)!
        c.queryItems = query.map { URLQueryItem(name: $0.key, value: $0.value) }
        // '+' is literal in our paths, not a space.
        c.percentEncodedQuery = c.percentEncodedQuery?.replacingOccurrences(of: "+", with: "%2B")
        return c.url!
    }

    private func request(_ method: String, _ path: String, _ query: [String: String] = [:]) -> URLRequest {
        var r = URLRequest(url: url(path, query))
        r.httpMethod = method
        r.setValue("Bearer \(endpoint.token)", forHTTPHeaderField: "Authorization")
        return r
    }

    private func check(_ data: Data, _ resp: URLResponse) throws {
        guard let http = resp as? HTTPURLResponse else { throw DriveError.serviceUnavailable }
        switch http.statusCode {
        case 200 ..< 300: return
        case 401: throw DriveError.unauthorized
        case 404: throw DriveError.notFound
        case 409:
            let current = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["current"] as? UInt64 ?? 0
            throw DriveError.conflict(current: current)
        case 410: throw DriveError.anchorExpired
        default: throw DriveError.server(http.statusCode, String(data: data, encoding: .utf8) ?? "")
        }
    }

    private func call<T: Decodable>(_ req: URLRequest) async throws -> T {
        let (data, resp): (Data, URLResponse)
        do { (data, resp) = try await session.data(for: req) } catch { throw DriveError.serviceUnavailable }
        try check(data, resp)
        return try JSONDecoder().decode(T.self, from: data)
    }

    func item(_ id: String) async throws -> DriveItem {
        try await call(request("GET", "/v1/item", ["id": id]))
    }

    func items(parent: String) async throws -> [DriveItem] {
        try await call(request("GET", "/v1/items", ["parent": parent]))
    }

    func all() async throws -> DriveChanges {
        try await call(request("GET", "/v1/all"))
    }

    func changes(since anchor: UInt64) async throws -> DriveChanges {
        try await call(request("GET", "/v1/changes", ["anchor": String(anchor)]))
    }

    /// Long poll; true when the remote changed.
    func watch(timeout: TimeInterval = 50) async throws -> Bool {
        var r = request("GET", "/v1/watch", ["timeout_ms": String(Int(timeout * 1000))])
        r.timeoutInterval = timeout + 30
        struct W: Decodable { let changed: Bool }
        let w: W = try await call(r)
        return w.changed
    }

    /// Download a file (decrypted) to `dest`; returns the version it holds.
    func download(_ id: String, to dest: URL) async throws -> DriveItem {
        let (tmp, resp): (URL, URLResponse)
        do { (tmp, resp) = try await session.download(for: request("GET", "/v1/content", ["id": id])) } catch { throw DriveError.serviceUnavailable }
        try check(Data(), resp)
        guard let http = resp as? HTTPURLResponse,
              let header = http.value(forHTTPHeaderField: "x-near-drive-item"),
              let item = try? JSONDecoder().decode(DriveItem.self, from: Data(header.utf8))
        else { throw DriveError.server(0, "missing item header") }
        try? FileManager.default.removeItem(at: dest)
        try FileManager.default.moveItem(at: tmp, to: dest)
        return item
    }

    /// Upload a file as `id`, only if the remote is still at `baseSeq` (0 = new).
    func upload(_ id: String, from file: URL?, baseSeq: UInt64) async throws -> DriveItem {
        let r = request("PUT", "/v1/content", ["id": id, "base_seq": String(baseSeq)])
        let (data, resp): (Data, URLResponse)
        do {
            if let file { (data, resp) = try await session.upload(for: r, fromFile: file) } else { (data, resp) = try await session.upload(for: r, from: Data()) }
        } catch { throw DriveError.serviceUnavailable }
        try check(data, resp)
        return try JSONDecoder().decode(DriveItem.self, from: data)
    }

    func createFolder(_ id: String) async throws -> DriveItem {
        try await call(request("POST", "/v1/folder", ["id": id]))
    }

    func rename(from: String, to: String) async throws -> DriveItem {
        try await call(request("POST", "/v1/rename", ["from": from, "to": to]))
    }

    func delete(_ id: String, seq: UInt64) async throws {
        let (data, resp): (Data, URLResponse)
        do { (data, resp) = try await session.data(for: request("DELETE", "/v1/item", ["id": id, "seq": String(seq)])) } catch { throw DriveError.serviceUnavailable }
        try check(data, resp)
    }
}
