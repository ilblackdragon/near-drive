//! `near drive up` / `down`: the S3 endpoint (`s3-proxy`) as a background
//! process. State lives in `<home>/s3-proxy.pid` (JSON), output in
//! `<home>/s3-proxy.log`.
use crate::{s3_credentials, Ctx, ProxyArgs};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize)]
struct State {
    pid: i32,
    listen: SocketAddr,
    account: String,
    network: String,
    log: PathBuf,
}

fn state_path(home: &Path) -> PathBuf {
    home.join("s3-proxy.pid")
}

fn read_state(home: &Path) -> Option<State> {
    serde_json::from_slice(&std::fs::read(state_path(home)).ok()?).ok()
}

/// Running, and (where /proc exists) still a near-drive process, not a reused pid.
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

fn listening(addr: &SocketAddr) -> bool {
    TcpStream::connect_timeout(addr, Duration::from_millis(200)).is_ok()
}

fn tail(log: &Path) -> String {
    let s = std::fs::read_to_string(log).unwrap_or_default();
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(15)..].join("\n")
}

fn print_running(st: &State, creds: &near_drive_s3::sigv4::Credentials) {
    let ep = format!("http://{}", st.listen);
    println!("NEAR Drive S3 endpoint: {ep}  (account {} on {}, pid {})", st.account, st.network, st.pid);
    println!("bucket = namespace: s3://{}/<path> is near://{}/<path>", st.account, st.account);
    println!();
    println!("export AWS_ENDPOINT_URL={ep}");
    println!("export AWS_ACCESS_KEY_ID={}", creds.access_key);
    println!("export AWS_SECRET_ACCESS_KEY={}", creds.secret_key);
    println!("export AWS_REGION=us-east-1");
    println!();
    println!("log: {}   stop: near drive down", st.log.display());
}

fn abs(p: &Path) -> Result<PathBuf> {
    Ok(std::path::absolute(p)?)
}

pub async fn up(ctx: &mut Ctx, proxy: ProxyArgs) -> Result<()> {
    let home = abs(&ctx.drive_home()?)?;
    std::fs::create_dir_all(&home)?;
    if let Some(st) = read_state(&home).filter(|s| alive(s.pid)) {
        eprintln!("already running");
        print_running(&st, &s3_credentials(ctx, &proxy)?);
        return Ok(());
    }
    near_drive_s3::check_loopback(&proxy.listen)?;
    if listening(&proxy.listen) {
        bail!("something is already listening on {}; pick another with --listen", proxy.listen);
    }
    // Resolve (and, interactively, ask for) everything the child needs, and
    // fail here on a missing key rather than in a background log.
    let (account, _, _) = ctx.request_key().await?;
    let creds = s3_credentials(ctx, &proxy)?;

    let mut words = vec!["s3-proxy".to_string(), "--listen".into(), proxy.listen.to_string()];
    for b in &proxy.buckets {
        words.extend(["--bucket".into(), b.clone()]);
    }
    for p in &proxy.public_prefixes {
        words.extend(["--public-prefix".into(), p.clone()]);
    }
    words.extend(["--max-body-mib".into(), proxy.max_body_mib.to_string(), "--region".into(), proxy.region.clone()]);
    let mut echo = words.clone();
    echo[0] = "up".into();
    ctx.echo(&echo);

    let log = home.join("s3-proxy.log");
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
        // The child uses exactly these keys, also when they came from the file.
        .env("NEAR_DRIVE_S3_ACCESS_KEY", &creds.access_key)
        .env("NEAR_DRIVE_S3_SECRET_KEY", &creds.secret_key)
        .stdin(std::process::Stdio::null())
        .stdout(out.try_clone()?)
        .stderr(out);
    if let Some(r) = &ctx.cli.rpc_url {
        cmd.env("NEAR_RPC_URL", r);
    }
    if let Some(c) = &ctx.cli.credentials {
        cmd.env("NEAR_DRIVE_CREDENTIALS", abs(c)?);
    }
    // Own process group: Ctrl-C in this terminal does not stop it.
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    let mut child = cmd.spawn().context("starting s3-proxy")?;

    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait()? {
            bail!("s3-proxy exited ({status}):\n{}", tail(&log));
        }
        if listening(&proxy.listen) {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            bail!("s3-proxy did not start listening on {} within 20s:\n{}", proxy.listen, tail(&log));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let st = State { pid: child.id() as i32, listen: proxy.listen, account, network: ctx.network.clone(), log };
    std::fs::write(state_path(&home), serde_json::to_vec_pretty(&st)?)?;
    print_running(&st, &creds);
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
    // SAFETY: plain kill(2) on a pid we checked is our s3-proxy.
    unsafe { libc::kill(st.pid, libc::SIGTERM) };
    let deadline = Instant::now() + Duration::from_secs(5);
    while alive(st.pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    if alive(st.pid) {
        unsafe { libc::kill(st.pid, libc::SIGKILL) };
    }
    std::fs::remove_file(&path)?;
    eprintln!("stopped S3 endpoint on {} (pid {})", st.listen, st.pid);
    Ok(())
}
