//! `nst` — command-line client for nstorage.
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use nstorage_client::{
    nstorage_core::{crypto::RootKey, keys, NearUri},
    Client, PutOptions,
};
use std::io::{Read, Write};
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
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the account's encryption root key (v0: local; later NEAR MPC CKD).
    Keygen,
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
    },
    /// Give a recipient (`x25519:<base58>`) the key to an existing object.
    Share { uri: String, recipient: String },
    /// Print this account's public key for receiving shared objects.
    Whoami,
    /// Download to a file (default stdout).
    Get { uri: String, dst: Option<PathBuf> },
    /// List objects under a prefix.
    Ls { uri: String },
    /// Delete an object.
    Rm { uri: String },
    /// Run a local S3-compatible endpoint (loopback only) backed by nstorage.
    /// boto3 / aws-cli: set endpoint_url=http://127.0.0.1:9000 and the printed keys.
    S3Proxy {
        #[arg(long, default_value = "127.0.0.1:9000")]
        listen: std::net::SocketAddr,
        /// S3 access key (default: generated once and stored in <home>/s3-proxy.json).
        #[arg(long, env = "NSTORAGE_S3_ACCESS_KEY", requires = "secret_key")]
        access_key: Option<String>,
        #[arg(long, env = "NSTORAGE_S3_SECRET_KEY", requires = "access_key", hide_env_values = true)]
        secret_key: Option<String>,
        /// Extra namespace to show in ListBuckets; repeatable.
        #[arg(long = "bucket")]
        buckets: Vec<String>,
        /// Store keys under this prefix unencrypted (public data); repeatable.
        #[arg(long = "public-prefix")]
        public_prefixes: Vec<String>,
        /// Largest single request body (PUT / part) accepted, in MiB.
        #[arg(long, default_value_t = 5120)]
        max_body_mib: usize,
        /// Region reported by GetBucketLocation.
        #[arg(long, default_value = "us-east-1")]
        region: String,
    },
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).context("HOME not set")
}

fn nstorage_home(cli: &Cli) -> Result<PathBuf> {
    match &cli.home {
        Some(h) => Ok(h.clone()),
        None => Ok(home_dir()?.join(".nstorage")),
    }
}

fn root_key_path(cli: &Cli, account: &str) -> Result<PathBuf> {
    Ok(nstorage_home(cli)?.join("keys").join(format!("{account}.root")))
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

fn client(cli: &Cli) -> Result<Client> {
    let account = account(cli)?;
    let cred_path = match &cli.credentials {
        Some(p) => p.clone(),
        None => home_dir()?.join(".near-credentials").join(&cli.network).join(format!("{account}.json")),
    };
    let (cred_account, sk) = keys::NearCredentials::load(&cred_path)?;
    if cred_account != account {
        bail!("credentials are for {cred_account}, not {account}");
    }
    let root = load_root(&root_key_path(cli, &account)?)?;
    Ok(Client::new(&cli.gateway, account, sk, root))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.cmd {
        Cmd::Keygen => {
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
        Cmd::Put { src, uri, public, content_type, share } => {
            let c = client(&cli)?;
            let uri = NearUri::parse(uri)?;
            let mut data = vec![];
            if src == "-" {
                std::io::stdin().read_to_end(&mut data)?;
            } else {
                data = std::fs::read(src).with_context(|| format!("reading {src}"))?;
            }
            let rec = c.put(&uri, &data, &PutOptions { public: *public, content_type: content_type.clone(), share_with: share.clone() }).await?;
            eprintln!("{uri} seq={} size={} stored={}", rec.seq, rec.size, rec.stored_size);
        }
        Cmd::Get { uri, dst } => {
            let c = client(&cli)?;
            let (_, data) = c.get(&NearUri::parse(uri)?).await?;
            match dst {
                Some(p) => std::fs::write(p, &data)?,
                None => std::io::stdout().write_all(&data)?,
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
        Cmd::S3Proxy { listen, access_key, secret_key, buckets, public_prefixes, max_body_mib, region } => {
            use nstorage_s3::{backend::ClientBackend, credentials, sigv4::Credentials, Proxy, ProxyConfig};
            nstorage_s3::check_loopback(listen)?;
            tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn,nstorage_s3=info".into()))
                .with_writer(std::io::stderr)
                .init();
            let c = client(&cli)?;
            let home = nstorage_home(&cli)?;
            let creds = match (access_key, secret_key) {
                (Some(a), Some(s)) => Credentials { access_key: a.clone(), secret_key: s.clone() },
                _ => {
                    let path = home.join("s3-proxy.json");
                    let (creds, created) = credentials::load_or_create(&path)?;
                    if created {
                        eprintln!("generated S3 credentials (saved to {}):", path.display());
                        eprintln!("  aws_access_key_id     = {}", creds.access_key);
                        eprintln!("  aws_secret_access_key = {}", creds.secret_key);
                    } else {
                        eprintln!("using S3 credentials from {} (access key {})", path.display(), creds.access_key);
                    }
                    creds
                }
            };
            if c.x25519_public().is_none() && public_prefixes.is_empty() {
                eprintln!("warning: no root key loaded (run `nst keygen`); private writes will fail");
            }
            let account = c.account().to_string();
            let mut cfg = ProxyConfig::new(creds, home.join("s3-staging"));
            cfg.extra_buckets = buckets.clone();
            cfg.public_prefixes = public_prefixes.clone();
            cfg.max_body_bytes = max_body_mib * 1024 * 1024;
            cfg.region = region.clone();
            let proxy = Proxy::new(cfg, ClientBackend::new(c));
            eprintln!("nstorage S3 proxy for {account} on http://{listen} (bucket = namespace, e.g. http://{listen}/{account}/key)");
            nstorage_s3::run(*listen, proxy).await?;
        }
    }
    Ok(())
}

fn ed25519_dalek_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng)
}
