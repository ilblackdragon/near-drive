// Host app for the File Provider extension: a menu-bar item that adds
// "NEAR Drive" to Finder (registers the File Provider domain) and tells the
// system when the remote changed, so Finder updates within seconds.
import FileProvider
import SwiftUI

@main
struct NEARDriveApp: App {
    @StateObject private var model = DriveModel()

    var body: some Scene {
        MenuBarExtra("NEAR Drive", systemImage: model.symbol) {
            Text(model.status)
            Divider()
            if model.added {
                Button("Open in Finder") { model.openInFinder() }
                Button("Remove from Finder") { model.remove() }
            } else {
                Button("Add NEAR Drive to Finder") { model.add() }
            }
            Divider()
            Button("Quit") { NSApplication.shared.terminate(nil) }
        }
    }
}

@MainActor
final class DriveModel: ObservableObject {
    static let domain = NSFileProviderDomain(identifier: NSFileProviderDomainIdentifier("near-drive"), displayName: "NEAR Drive")

    @Published var status = "Starting…"
    @Published var added = false
    @Published var symbol = "externaldrive.badge.icloud"

    init() {
        Task { await refreshDomains() }
        Task.detached { await DriveModel.signalLoop(self) }
    }

    func refreshDomains() async {
        let domains = (try? await NSFileProviderManager.domains()) ?? []
        added = domains.contains { $0.identifier == Self.domain.identifier }
        if (try? DriveAPI.shared()) == nil {
            status = "Background service not running (near drive up --file-provider)"
            symbol = "externaldrive.badge.xmark"
        } else {
            status = added ? "NEAR Drive is in Finder" : "Not in Finder yet"
            symbol = "externaldrive.badge.icloud"
        }
    }

    func add() {
        Task {
            do {
                try await NSFileProviderManager.add(Self.domain)
                await refreshDomains()
                openInFinder()
            } catch {
                status = "Could not add: \(error.localizedDescription)"
            }
        }
    }

    func remove() {
        Task {
            try? await NSFileProviderManager.remove(Self.domain)
            await refreshDomains()
        }
    }

    func openInFinder() {
        Task {
            guard let manager = NSFileProviderManager(for: Self.domain),
                  let url = try? await manager.getUserVisibleURL(for: .rootContainer) else { return }
            NSWorkspace.shared.open(url)
        }
    }

    /// Long-poll the service; on each remote change, ask the system to
    /// re-enumerate (the extension then fetches only what changed).
    nonisolated static func signalLoop(_ model: DriveModel) async {
        while true {
            do {
                if try await DriveAPI.shared().watch(), let manager = NSFileProviderManager(for: domain) {
                    try? await manager.signalEnumerator(for: .workingSet)
                }
            } catch {
                try? await Task.sleep(nanoseconds: 5_000_000_000)
                await model.refreshDomains()
            }
        }
    }
}
