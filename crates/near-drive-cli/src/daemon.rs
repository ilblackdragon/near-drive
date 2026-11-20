//! `near drive up` / `down`: one background process running the S3 endpoint
//! and every synced folder (`near drive sync add`). State lives in
//! `<home>/daemon.pid` (JSON), output in `<home>/daemon.log`.
use crate::{s3_credentials, Ctx, ProxyArgs};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize)]
struct State {
    pid: i32,
    /// None: started with `--no-s3`.
    listen: Option<SocketAddr>,
    account: String,
    network: String,
    log: PathBuf,
}

fn state_path(home: &Path) -> PathBuf {
    home.join("daemon.pid")
}

fn read_state(home: &Path) -> Option<State> {
    serde_json::from_slice(&std::fs::read(state_path(home)).ok()?).ok()
}

/// The running service's account and network.
pub fn service(home: &Path) -> Option<(String, String)> {
    read_state(home).filter(|s| alive(s.pid)).map(|s| (s.account, s.network))
}

/// Is the background service up?
pub fn running(home: &Path) -> bool {
    read_state(home).is_some_and(|s| alive(s.pid))
}

/// Running, and (where /proc exists) still a near-drive process, not a reused pid.
#[cfg(unix)]
fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 only checks that the process exists.
    if pid <= 0 || unsafe { libc::kill(pid, 0) } != 0 {
        return false;
    }
    match std::fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(c) => String::from_utf8_lossy(&c).contains("near-drive"),
        Err(_) => true,
    }
}

#[cfg(windows)]
fn alive(pid: i32) -> bool {
    let out = std::process::Command::new("tasklist").args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"]).output();
    out.is_ok_and(|o| String::from_utf8_lossy(&o.stdout).to_ascii_lowercase().contains("near-drive"))
}

/// Ask the process to stop (SIGTERM / taskkill), then force it.
fn stop(pid: i32, force: bool) {
    #[cfg(unix)]
    // SAFETY: plain kill(2) on a pid we checked is our process.
    unsafe {
        libc::kill(pid, if force { libc::SIGKILL } else { libc::SIGTERM });
    }
    #[cfg(windows)]
    {
        let mut c = std::process::Command::new("taskkill");
        c.args(["/PID", &pid.to_string()]);
        if force {
            c.arg("/F");
        }
        let _ = c.output();
    }
}

/// Detach the child from this terminal: Ctrl-C here must not stop it.
fn detach(cmd: &mut std::process::Command) {
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(cmd, 0);
    #[cfg(windows)]
    {
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        std::os::windows::process::CommandExt::creation_flags(cmd, DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
}

fn listening(addr: &SocketAddr) -> bool {
    TcpStream::connect_timeout(addr, Duration::from_millis(200)).is_ok()
}

fn tail(log: &Path) -> String {
    let s = std::fs::read_to_string(log).unwrap_or_default();
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(15)..].join("\n")
}

fn print_running(st: &State, creds: Option<&near_drive_s3::sigv4::Credentials>, home: &Path) {
    println!("NEAR Drive background service: account {} on {}, pid {}", st.account, st.network, st.pid);
    if let (Some(listen), Some(creds)) = (st.listen, creds) {
        let ep = format!("http://{listen}");
        println!("\nS3 endpoint {ep} (bucket = namespace: s3://{}/<path> is near://{}/<path>)", st.account, st.account);
        println!("export AWS_ENDPOINT_URL={ep}");
        println!("export AWS_ACCESS_KEY_ID={}", creds.access_key);
        println!("export AWS_SECRET_ACCESS_KEY={}", creds.secret_key);
        println!("export AWS_REGION=us-east-1");
    }
    let folders: Vec<_> = crate::syncs::SyncConfig::load(home)
        .map(|c| c.folders.into_iter().filter(|f| f.account == st.account && f.network == st.network).collect())
        .unwrap_or_default();
    if folders.is_empty() {
        println!("\nno synced folders (add one: near drive sync add ~/NearDrive)");
    } else {
        println!("\nsynced folders:");
        for f in folders {
            println!("  {} <-> {}", f.local.display(), f.remote);
        }
    }
    println!("\nlog: {}   status: near drive sync status   stop: near drive down", st.log.display());
}

fn abs(p: &Path) -> Result<PathBuf> {
    Ok(std::path::absolute(p)?)
}

pub async fn up(ctx: &mut Ctx, proxy: ProxyArgs, no_s3: bool, file_provider: Option<String>) -> Result<()> {
    let home = abs(&ctx.drive_home()?)?;
    std::fs::create_dir_all(&home)?;
    if let Some(st) = read_state(&home).filter(|s| alive(s.pid)) {
        eprintln!("already running");
        let creds = if st.listen.is_some() { Some(s3_credentials(ctx, &proxy)?) } else { None };
        print_running(&st, creds.as_ref(), &home);
        return Ok(());
    }
    if !no_s3 {
        near_drive_s3::check_listen(&proxy.listen, proxy.public_listen)?;
        if listening(&proxy.listen) {
            bail!("something is already listening on {}; pick another with --listen (or --no-s3)", proxy.listen);
        }
    }
    // Resolve (and, interactively, ask for) everything the child needs, and
    // fail here on a missing key rather than in a background log.
    let (account, _, _) = ctx.request_key().await?;
    // A root key that does not match the published keys would make the
    // service write records nobody accepts: refuse here, not in the log.
    ctx.check_before_write(&account).await?;
    let creds = if no_s3 { None } else { Some(s3_credentials(ctx, &proxy)?) };

    let mut words = vec!["daemon".to_string(), "--listen".into(), proxy.listen.to_string()];
    if no_s3 {
        words.push("--no-s3".into());
    }
    if let Some(r) = &file_provider {
        words.extend(["--file-provider".into(), r.clone()]);
    }
    for b in &proxy.buckets {
        words.extend(["--bucket".into(), b.clone()]);
    }
    for p in &proxy.public_prefixes {
        words.extend(["--public-prefix".into(), p.clone()]);
    }
    words.extend(["--max-body-mib".into(), proxy.max_body_mib.to_string(), "--region".into(), proxy.region.clone()]);
    for a in &proxy.bucket_aliases {
        words.extend(["--bucket-alias".into(), a.clone()]);
    }
    for o in &proxy.cors_origins {
        words.extend(["--cors-origin".into(), o.clone()]);
    }
    for d in &proxy.vhost_domains {
        words.extend(["--virtual-host-domain".into(), d.clone()]);
    }
    if proxy.public_listen {
        words.push("--public-listen".into());
    }
    let mut echo = words.clone();
    echo[0] = "up".into();
    ctx.echo(&echo);

    let log = home.join("daemon.log");
    let out = std::fs::File::create(&log).with_context(|| format!("creating {}", log.display()))?;
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    cmd.args(["--no-interactive", "--account", &account, "--network", &ctx.network])
        .args(&words)
        .env("NEAR_DRIVE_GATEWAY", &ctx.cli.gateway)
        .env("NEAR_DRIVE_CONTRACT", &ctx.cli.contract)
        .env("NEAR_DRIVE_HOME", &home)
        .env("NEAR_DRIVE_PARALLEL", ctx.cli.parallel.to_string())
        .env("NEAR_DRIVE_CHUNK_MIB", ctx.cli.chunk_mib.to_string())
        .env("NEAR_DRIVE_NEAR_BIN", &ctx.cli.near_bin)
        .stdin(std::process::Stdio::null())
        .stdout(out.try_clone()?)
        .stderr(out);
    if let Some(creds) = &creds {
        // The child uses exactly these keys, also when they came from the file.
        cmd.env("NEAR_DRIVE_S3_ACCESS_KEY", &creds.access_key).env("NEAR_DRIVE_S3_SECRET_KEY", &creds.secret_key);
    }
    if let Some(r) = &ctx.cli.rpc_url {
        cmd.env("NEAR_RPC_URL", r);
    }
    if let Some(c) = &ctx.cli.credentials {
        cmd.env("NEAR_DRIVE_CREDENTIALS", abs(c)?);
    }
    detach(&mut cmd);
    let mut child = cmd.spawn().context("starting the background service")?;

    // Ready: the S3 port answers (or, without S3, the process is still up after a moment).
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            bail!("the background service exited ({status}):\n{}", tail(&log));
        }
        if if no_s3 { started.elapsed() > Duration::from_millis(1500) } else { listening(&proxy.listen) } {
            break;
        }
        if started.elapsed() > Duration::from_secs(20) {
            let _ = child.kill();
            bail!("the S3 endpoint did not start listening on {} within 20s:\n{}", proxy.listen, tail(&log));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let st = State { pid: child.id() as i32, listen: (!no_s3).then_some(proxy.listen), account, network: ctx.network.clone(), log };
    std::fs::write(state_path(&home), serde_json::to_vec_pretty(&st)?)?;
    print_running(&st, creds.as_ref(), &home);
    Ok(())
}

pub fn down(home: &Path) -> Result<()> {
    let path = state_path(home);
    let Some(st) = read_state(home) else {
        eprintln!("not running");
        return Ok(());
    };
    if !alive(st.pid) {
        std::fs::remove_file(&path)?;
        eprintln!("not running (removed stale {})", path.display());
        return Ok(());
    }
    stop(st.pid, false);
    let deadline = Instant::now() + Duration::from_secs(5);
    while alive(st.pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    if alive(st.pid) {
        stop(st.pid, true);
    }
    std::fs::remove_file(&path)?;
    eprintln!("stopped the background service (pid {})", st.pid);
    Ok(())
}
