//! NEAR Drive tray / menu-bar app.
//!
//! Shows whether the background service is syncing, up to date, paused or
//! failing; opens synced folders; pauses / resumes the service. It holds no
//! keys and talks to nothing on the network: it reads
//! `near-drive sync status --json` and runs `near-drive up` / `down`.
//!
//! Linux: StatusNotifierItem (KDE, GNOME with the AppIndicator extension,
//! XFCE, ...). Windows: notification area. macOS: menu bar.
#![cfg_attr(windows, windows_subsystem = "windows")]
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
struct Folder {
    local: PathBuf,
    remote: String,
    account: String,
    network: String,
    ok: Option<bool>,
    error: Option<String>,
    #[serde(default)]
    pending: bool,
    #[serde(default)]
    conflicts: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
struct Service {
    account: String,
    network: String,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
struct Status {
    running: bool,
    service: Option<Service>,
    log: PathBuf,
    folders: Vec<Folder>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum State {
    UpToDate,
    Syncing,
    Paused,
    Error,
    NoFolders,
}

impl Status {
    fn state(&self) -> State {
        if self.folders.is_empty() {
            State::NoFolders
        } else if !self.running {
            State::Paused
        } else if self.folders.iter().any(|f| f.ok == Some(false)) {
            State::Error
        } else if self.folders.iter().any(|f| f.pending || f.ok.is_none()) {
            State::Syncing
        } else {
            State::UpToDate
        }
    }

    fn headline(&self) -> String {
        let n = self.folders.len();
        let conflicts: usize = self.folders.iter().map(|f| f.conflicts.len()).sum();
        let mut s = match self.state() {
            State::NoFolders => "No synced folders".to_string(),
            State::Paused => "Paused".to_string(),
            State::Syncing => "Syncing…".to_string(),
            State::Error => format!("Problem: {}", self.folders.iter().find_map(|f| f.error.clone()).unwrap_or_else(|| "sync failed".into())),
            State::UpToDate => format!("Up to date · {n} folder{}", if n == 1 { "" } else { "s" }),
        };
        if conflicts > 0 {
            s.push_str(&format!(" · {conflicts} conflicted cop{}", if conflicts == 1 { "y" } else { "ies" }));
        }
        s.chars().take(80).collect()
    }
}

/// The `near-drive` CLI: next to this binary, else on PATH.
fn cli() -> PathBuf {
    let name = if cfg!(windows) { "near-drive.exe" } else { "near-drive" };
    std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join(name))).filter(|p| p.exists()).unwrap_or_else(|| PathBuf::from(name))
}

fn command(args: &[&str]) -> Command {
    let mut c = Command::new(cli());
    c.args(["--no-interactive"]).args(args);
    #[cfg(windows)]
    std::os::windows::process::CommandExt::creation_flags(&mut c, 0x0800_0000); // no console window
    c
}

fn read_status() -> Result<Status> {
    let out = command(&["sync", "status", "--json"]).output().context("running near-drive")?;
    anyhow::ensure!(out.status.success(), "near-drive sync status failed: {}", String::from_utf8_lossy(&out.stderr));
    Ok(serde_json::from_slice(&out.stdout)?)
}

fn open_path(p: &Path) {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(windows) {
        "explorer"
    } else {
        "xdg-open"
    };
    let _ = Command::new(opener).arg(p).spawn();
}

/// A 32×32 round icon in the state's color (no image files to ship).
fn icon(state: State) -> Icon {
    let (r, g, b) = match state {
        State::UpToDate => (0x2e, 0xa0, 0x43),
        State::Syncing => (0x1f, 0x6f, 0xeb),
        State::Paused | State::NoFolders => (0x8b, 0x94, 0x9e),
        State::Error => (0xd1, 0x24, 0x2f),
    };
    const N: u32 = 32;
    let mut rgba = Vec::with_capacity((N * N * 4) as usize);
    for y in 0..N {
        for x in 0..N {
            let (dx, dy) = (x as f32 - 15.5, y as f32 - 15.5);
            let d = (dx * dx + dy * dy).sqrt();
            // ring with a filled center ("drive" dot), anti-aliased edge
            let a = ((15.5 - d).clamp(0.0, 1.0) * 255.0) as u8;
            let inner = d < 6.0 || (10.0..13.5).contains(&d);
            let (pr, pg, pb) = if inner || d >= 13.5 { (r, g, b) } else { (0xff, 0xff, 0xff) };
            rgba.extend_from_slice(&[pr, pg, pb, a]);
        }
    }
    Icon::from_rgba(rgba, N, N).expect("valid icon")
}

/// Menu items whose clicks we handle.
struct Items {
    headline: MenuItem,
    toggle: MenuItem,
    add: MenuItem,
    log: MenuItem,
    quit: MenuItem,
    open: Vec<(MenuItem, PathBuf)>,
}

struct App {
    tray: TrayIcon,
    items: Items,
    status: Status,
    last_poll: Instant,
}

fn build_menu(status: &Status) -> Result<(Menu, Items)> {
    let menu = Menu::new();
    let headline = MenuItem::new(status.headline(), false, None);
    menu.append(&headline)?;
    menu.append(&PredefinedMenuItem::separator())?;
    let mut open = vec![];
    for f in &status.folders {
        let name = f.local.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| f.local.display().to_string());
        let item = MenuItem::new(format!("Open {name}"), true, None);
        menu.append(&item)?;
        open.push((item, f.local.clone()));
    }
    let add = MenuItem::new("Sync ~/NearDrive", status.folders.is_empty(), None);
    if status.folders.is_empty() {
        menu.append(&add)?;
    }
    menu.append(&PredefinedMenuItem::separator())?;
    let toggle = MenuItem::new(if status.running { "Pause syncing" } else { "Resume syncing" }, !status.folders.is_empty(), None);
    menu.append(&toggle)?;
    let log = MenuItem::new("Show log", true, None);
    menu.append(&log)?;
    menu.append(&PredefinedMenuItem::separator())?;
    let quit = MenuItem::new("Quit tray", true, None);
    menu.append(&quit)?;
    Ok((menu, Items { headline, toggle, add, log, quit, open }))
}

impl App {
    fn new() -> Result<Self> {
        let status = read_status().unwrap_or_default();
        let (menu, items) = build_menu(&status)?;
        let tray = TrayIconBuilder::new().with_menu(Box::new(menu)).with_tooltip(format!("NEAR Drive: {}", status.headline())).with_icon(icon(status.state())).build()?;
        Ok(Self { tray, items, status, last_poll: Instant::now() })
    }

    /// Re-read the status; rebuild the menu if folders or state changed.
    fn poll(&mut self) {
        if self.last_poll.elapsed() < Duration::from_secs(3) {
            return;
        }
        self.last_poll = Instant::now();
        let status = match read_status() {
            Ok(s) => s,
            Err(e) => Status { folders: vec![Folder { ok: Some(false), error: Some(format!("{e:#}")), ..Default::default() }], ..Default::default() },
        };
        if status == self.status {
            return;
        }
        let rebuild = status.folders.len() != self.status.folders.len() || status.running != self.status.running;
        self.status = status;
        let _ = self.tray.set_icon(Some(icon(self.status.state())));
        let _ = self.tray.set_tooltip(Some(format!("NEAR Drive: {}", self.status.headline())));
        if rebuild {
            if let Ok((menu, items)) = build_menu(&self.status) {
                self.tray.set_menu(Some(Box::new(menu)));
                self.items = items;
            }
        } else {
            self.items.headline.set_text(self.status.headline());
        }
    }

    /// Handle menu clicks; false = quit.
    fn handle(&mut self, ev: MenuEvent) -> bool {
        let id = ev.id;
        if id == *self.items.quit.id() {
            return false;
        }
        if id == *self.items.log.id() {
            open_path(&self.status.log);
        } else if id == *self.items.toggle.id() {
            if self.status.running {
                let _ = command(&["down"]).status();
            } else if let Some(f) = self.status.folders.first() {
                let _ = command(&["--account", &f.account, "--network", &f.network, "up", "--no-s3"]).status();
            }
            self.last_poll = Instant::now() - Duration::from_secs(10);
        } else if id == *self.items.add.id() {
            let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from).unwrap_or_default();
            let dir = home.join("NearDrive");
            let _ = command(&["sync", "add", &dir.display().to_string()]).status();
            let _ = command(&["up", "--no-s3"]).status();
            open_path(&dir);
            self.last_poll = Instant::now() - Duration::from_secs(10);
        } else if let Some((_, p)) = self.items.open.iter().find(|(i, _)| *i.id() == id) {
            open_path(p);
        }
        self.poll();
        true
    }
}

/// `--version` / `--help` without starting the tray.
fn handle_args() -> bool {
    match std::env::args().nth(1).as_deref() {
        Some("--version" | "-V") => println!("near-drive-tray {}", env!("CARGO_PKG_VERSION")),
        Some("--help" | "-h") => println!("near-drive-tray: NEAR Drive status in the system tray / menu bar.\nUsage: near-drive-tray [--version]"),
        _ => return false,
    }
    true
}

#[cfg(target_os = "linux")]
fn main() -> Result<()> {
    if handle_args() {
        return Ok(());
    }
    // ksni runs the tray on its own thread; this thread polls and handles clicks.
    let mut app = App::new()?;
    loop {
        if let Ok(ev) = MenuEvent::receiver().recv_timeout(Duration::from_millis(500)) {
            if !app.handle(ev) {
                return Ok(());
            }
        }
        app.poll();
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<()> {
    if handle_args() {
        return Ok(());
    }
    use tao::event::{Event, StartCause};
    use tao::event_loop::{ControlFlow, EventLoopBuilder};
    let event_loop = EventLoopBuilder::new().build();
    let mut app: Option<App> = None;
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::WaitUntil(Instant::now() + Duration::from_millis(500));
        // macOS: the tray must be created once the app's run loop is up.
        if let Event::NewEvents(StartCause::Init) = event {
            match App::new() {
                Ok(a) => app = Some(a),
                Err(e) => {
                    eprintln!("near-drive-tray: {e:#}");
                    *control_flow = ControlFlow::Exit;
                    return;
                }
            }
        }
        let Some(a) = app.as_mut() else { return };
        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            if !a.handle(ev) {
                *control_flow = ControlFlow::Exit;
                return;
            }
        }
        a.poll();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(json: &str) -> Status {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn states_and_headlines() {
        let none = status(r#"{"folders":[],"log":"/l","running":false,"service":null}"#);
        assert_eq!((none.state(), none.headline().as_str()), (State::NoFolders, "No synced folders"));
        let f = |extra: &str| format!(r#"{{"local":"/x","remote":"near://a/Drive/","account":"a","network":"mainnet","conflicts":[]{extra}}}"#);
        let paused = status(&format!(r#"{{"folders":[{}],"log":"/l","running":false,"service":null}}"#, f(r#","ok":true"#)));
        assert_eq!(paused.state(), State::Paused);
        let ok = status(&format!(r#"{{"folders":[{},{}],"log":"/l","running":true,"service":{{"account":"a","network":"mainnet"}}}}"#, f(r#","ok":true"#), f(r#","ok":true"#)));
        assert_eq!((ok.state(), ok.headline().as_str()), (State::UpToDate, "Up to date · 2 folders"));
        let syncing = status(&format!(r#"{{"folders":[{}],"log":"/l","running":true}}"#, f(r#","ok":true,"pending":true"#)));
        assert_eq!(syncing.state(), State::Syncing);
        let err = status(&format!(r#"{{"folders":[{}],"log":"/l","running":true}}"#, f(r#","ok":false,"error":"gateway unreachable""#)));
        assert_eq!((err.state(), err.headline().as_str()), (State::Error, "Problem: gateway unreachable"));
        let conflict = status(r#"{"folders":[{"local":"/x","remote":"r","account":"a","network":"n","ok":true,"conflicts":["a (conflicted copy).txt"]}],"log":"/l","running":true}"#);
        assert_eq!(conflict.headline(), "Up to date · 1 folder · 1 conflicted copy");
    }

    #[test]
    fn icons_render() {
        for s in [State::UpToDate, State::Syncing, State::Paused, State::Error, State::NoFolders] {
            let _ = icon(s);
        }
    }
}
