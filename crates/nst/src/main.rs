//! `nst` — command-line client for nstorage.
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use nstorage_client::{
    nstorage_core::{crypto::RootKey, keys, NearUri},
    Client, PutOptions,
};
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "nst", about = "NEAR storage client")]
struct Cli {
    #[arg(long, env = "NSTORAGE_GATEWAY", default_value = "http://127.0.0.1:8787", global = true)]
    gateway: String,
    /// NEAR account to act as.
    #[arg(long, env = "NSTORAGE_ACCOUNT", global = true)]
    account: Option<String>,
    /// NEAR credentials JSON (default ~/.near-credentials/<network>/<account>.json).
    #[arg(long, env = "NSTORAGE_CREDENTIALS", global = true)]
    credentials: Option<PathBuf>,
    #[arg(long, env = "NEAR_NETWORK", default_value = "mainnet", global = true)]
    network: String,
    /// Directory for nstorage root keys (default ~/.nstorage).
    #[arg(long, env = "NSTORAGE_HOME", global = true)]
    home: Option<PathBuf>,
    /// Concurrent chunk transfers for put/get.
    #[arg(long, env = "NSTORAGE_PARALLEL", default_value_t = nstorage_client::DEFAULT_PARALLELISM, global = true)]
    parallel: usize,
    /// Chunk size in MiB for uploads (1..=64).
    #[arg(long, env = "NSTORAGE_CHUNK_MIB", default_value_t = 4, global = true)]
    chunk_mib: usize,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the account's encryption root key: random local key, or with
    /// `--ckd` derive it via NEAR MPC Confidential Key Derivation (sends one
    /// `request_app_private_key` tx on `--network`; same key on every device).
    Keygen {
        #[arg(long)]
        ckd: bool,
        /// MPC contract (default: v1.signer / v1.signer-prod.testnet by --network).
        #[arg(long, requires = "ckd")]
        ckd_contract: Option<String>,
        /// NEAR RPC URL (default: rpc.<network>.near.org).
        #[arg(long, requires = "ckd")]
        ckd_rpc: Option<String>,
        /// CKD domain id (default 2).
        #[arg(long, requires = "ckd")]
        ckd_domain: Option<u64>,
    },
    /// Generate an ed25519 key in NEAR credentials format (for dev gateways).
    DevKey {
        #[arg(long)]
        out: PathBuf,
    },
    /// Upload a file (or `-` for stdin).
    Put {
        src: String,
        uri: String,
        /// Store unencrypted (public data).
        #[arg(long)]
        public: bool,
        #[arg(long)]
        content_type: Option<String>,
        /// Also encrypt to this recipient (`x25519:<base58>`); repeatable.
        #[arg(long = "share")]
        share: Vec<String>,
        /// Storage class (`hot`, `bulk`, ...); default: the gateway's default.
        #[arg(long)]
        class: Option<String>,
    },
    /// Give a recipient (`x25519:<base58>`) the key to an existing object.
    Share { uri: String, recipient: String },
    /// Print this account's public key for receiving shared objects.
    Whoami,
    /// Download to a file (default stdout).
    Get {
        uri: String,
        dst: Option<PathBuf>,
        /// Only bytes START-END (inclusive, like HTTP Range), e.g. `0-1023` or `1048576-`.
        #[arg(long)]
        range: Option<String>,
    },
    /// List objects under a prefix.
    Ls { uri: String },
    /// Delete an object.
    Rm { uri: String },
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).context("HOME not set")
}

fn root_key_path(cli: &Cli, account: &str) -> Result<PathBuf> {
    let base = match &cli.home {
        Some(h) => h.clone(),
        None => home_dir()?.join(".nstorage"),
    };
    Ok(base.join("keys").join(format!("{account}.root")))
}

fn load_root(path: &PathBuf) -> Result<Option<RootKey>> {
    match std::fs::read_to_string(path) {
        Ok(s) => {
            let b: [u8; 32] = hex::decode(s.trim())
                .ok()
                .and_then(|v| v.try_into().ok())
                .with_context(|| format!("{} is not a 32-byte hex key", path.display()))?;
            Ok(Some(RootKey::from_bytes(b)))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn write_private(path: &PathBuf, contents: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {} (refusing to overwrite an existing key)", path.display()))?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}

fn account(cli: &Cli) -> Result<String> {
    cli.account.clone().context("--account (or NSTORAGE_ACCOUNT) is required")
}

fn credentials_path(cli: &Cli, account: &str) -> Result<PathBuf> {
    Ok(match &cli.credentials {
        Some(p) => p.clone(),
        None => home_dir()?.join(".near-credentials").join(&cli.network).join(format!("{account}.json")),
    })
}

fn client(cli: &Cli) -> Result<Client> {
    let account = account(cli)?;
    let (cred_account, sk) = keys::NearCredentials::load(&credentials_path(cli, &account)?)?;
    if cred_account != account {
        bail!("credentials are for {cred_account}, not {account}");
    }
    let root = load_root(&root_key_path(cli, &account)?)?;
    if !(1..=64).contains(&cli.chunk_mib) {
        bail!("--chunk-mib must be in 1..=64");
    }
    let mut c = Client::new(&cli.gateway, account, sk, root);
    c.parallelism = cli.parallel.max(1);
    c.chunk_size = cli.chunk_mib * 1024 * 1024;
    Ok(c)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.cmd {
        Cmd::Keygen { ckd: true, ckd_contract, ckd_rpc, ckd_domain } => {
            let account = account(&cli)?;
            let path = root_key_path(&cli, &account)?;
            if path.exists() {
                bail!("{} already exists; refusing to overwrite", path.display());
            }
            let net = nstorage_ckd::CkdNetwork::resolve(&cli.network, ckd_contract.clone(), ckd_rpc.clone(), *ckd_domain)?;
            let (cred_account, key) = keys::NearCredentials::load(&credentials_path(&cli, &account)?)?;
            if cred_account != account {
                bail!("credentials are for {cred_account}, not {account}");
            }
            eprintln!("requesting CKD root key from {} (domain {}) on {} as {account} (1 yoctoNEAR + gas)…", net.contract, net.domain_id, net.network);
            let signer = nstorage_ckd::near::Signer { account_id: account.clone(), key };
            let root = nstorage_ckd::near::request_root_key(&net, &signer, nstorage_ckd::DERIVATION_PATH).await?;
            write_private(&path, &hex::encode(root.as_bytes()))?;
            eprintln!("CKD root key cached at {}; rerun `nst keygen --ckd` on any device to recover it", path.display());
        }
        Cmd::Keygen { ckd: false, .. } => {
            let account = account(&cli)?;
            let path = root_key_path(&cli, &account)?;
            write_private(&path, &hex::encode(RootKey::generate().as_bytes()))?;
            eprintln!("root key written to {} — back it up; losing it loses your encrypted data", path.display());
        }
        Cmd::DevKey { out } => {
            let account = account(&cli)?;
            let sk = ed25519_dalek_key();
            let json = serde_json::json!({
                "account_id": account,
                "public_key": keys::format_public_key(&sk.verifying_key()),
                "private_key": keys::format_secret_key(&sk),
            });
            write_private(out, &serde_json::to_string_pretty(&json)?)?;
            println!("{}", keys::format_public_key(&sk.verifying_key()));
        }
        Cmd::Put { src, uri, public, content_type, share, class } => {
            let c = client(&cli)?;
            let uri = NearUri::parse(uri)?;
            let opts = PutOptions { public: *public, content_type: content_type.clone(), share_with: share.clone(), class: class.clone() };
            // streaming: bounded memory, parallel chunk uploads
            let rec = if src == "-" { c.put_reader(tokio::io::stdin(), &uri, &opts).await? } else { c.put_file(src, &uri, &opts).await? };
            eprintln!("{uri} seq={} size={} stored={}", rec.seq, rec.size, rec.stored_size);
        }
        Cmd::Get { uri, dst, range } => {
            let c = client(&cli)?;
            let uri = NearUri::parse(uri)?;
            if let Some(r) = range {
                let data = c.get_range(&uri, parse_range(r)?).await?;
                match dst {
                    Some(p) => std::fs::write(p, &data)?,
                    None => std::io::stdout().write_all(&data)?,
                }
            } else {
                match dst {
                    Some(p) => c.get_to_file(&uri, p).await.map(|_| ())?,
                    None => c.get_to_writer(&uri, tokio::io::stdout()).await.map(|_| ())?,
                }
            }
        }
        Cmd::Ls { uri } => {
            let c = client(&cli)?;
            for e in c.list(&NearUri::parse(uri)?).await? {
                println!("{:>12}  seq={:<4} {:<24} {}", e.size, e.seq, e.writer, e.path);
            }
        }
        Cmd::Share { uri, recipient } => {
            let rec = client(&cli)?.share(&NearUri::parse(uri)?, recipient).await?;
            eprintln!("shared; seq={}", rec.seq);
        }
        Cmd::Whoami => {
            let c = client(&cli)?;
            println!("account: {}", c.account());
            println!("x25519:  {}", c.x25519_public().unwrap_or_else(|| "(no root key; run `nst keygen`)".into()));
        }
        Cmd::Rm { uri } => {
            client(&cli)?.delete(&NearUri::parse(uri)?).await?;
        }
    }
    Ok(())
}

/// `A-B` (inclusive) or `A-` -> half-open range.
fn parse_range(s: &str) -> Result<std::ops::Range<u64>> {
    let (a, b) = s.split_once('-').context("range must look like START-END or START-")?;
    let start: u64 = a.trim().parse().context("bad range start")?;
    let end = if b.trim().is_empty() { u64::MAX } else { b.trim().parse::<u64>().context("bad range end")?.saturating_add(1) };
    if end <= start {
        bail!("empty range");
    }
    Ok(start..end)
}

fn ed25519_dalek_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng)
}
