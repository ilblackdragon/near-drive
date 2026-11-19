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
    #[arg(
        long,
        env = "NSTORAGE_GATEWAY",
        default_value = "http://127.0.0.1:8787",
        global = true
    )]
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
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME not set")
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
        .with_context(|| {
            format!(
                "creating {} (refusing to overwrite an existing key)",
                path.display()
            )
        })?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}

fn account(cli: &Cli) -> Result<String> {
    cli.account
        .clone()
        .context("--account (or NSTORAGE_ACCOUNT) is required")
}

fn credentials_path(cli: &Cli, account: &str) -> Result<PathBuf> {
    Ok(match &cli.credentials {
        Some(p) => p.clone(),
        None => home_dir()?
            .join(".near-credentials")
            .join(&cli.network)
            .join(format!("{account}.json")),
    })
}

fn client(cli: &Cli) -> Result<Client> {
    let account = account(cli)?;
    let (cred_account, sk) = keys::NearCredentials::load(&credentials_path(cli, &account)?)?;
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
        Cmd::Keygen { ckd: false, .. } => {
            let account = account(&cli)?;
            let path = root_key_path(&cli, &account)?;
            write_private(&path, &hex::encode(RootKey::generate().as_bytes()))?;
            eprintln!(
                "root key written to {} — back it up; losing it loses your encrypted data",
                path.display()
            );
        }
        Cmd::Keygen {
            ckd: true,
            ckd_contract,
            ckd_rpc,
            ckd_domain,
        } => {
            let account = account(&cli)?;
            let path = root_key_path(&cli, &account)?;
            if path.exists() {
                bail!("{} already exists; refusing to overwrite", path.display());
            }
            let mut net = match nstorage_ckd::CkdNetwork::for_network(&cli.network) {
                Ok(n) => n,
                Err(_) => nstorage_ckd::CkdNetwork {
                    network: cli.network.clone(),
                    rpc_url: ckd_rpc
                        .clone()
                        .context("--ckd-rpc is required for this network")?,
                    contract: ckd_contract
                        .clone()
                        .context("--ckd-contract is required for this network")?,
                    domain_id: 2,
                },
            };
            if let Some(c) = ckd_contract {
                net.contract = c.clone();
            }
            if let Some(r) = ckd_rpc {
                net.rpc_url = r.clone();
            }
            if let Some(d) = ckd_domain {
                net.domain_id = *d;
            }
            let (cred_account, key) =
                keys::NearCredentials::load(&credentials_path(&cli, &account)?)?;
            if cred_account != account {
                bail!("credentials are for {cred_account}, not {account}");
            }
            eprintln!(
                "requesting CKD root key from {} (domain {}) on {} as {account} (1 yoctoNEAR + gas)…",
                net.contract, net.domain_id, net.network
            );
            let signer = nstorage_ckd::near::Signer {
                account_id: account.clone(),
                key,
            };
            let root =
                nstorage_ckd::near::request_root_key(&net, &signer, nstorage_ckd::DERIVATION_PATH)
                    .await?;
            write_private(&path, &hex::encode(root.as_bytes()))?;
            eprintln!(
                "CKD root key cached at {}; rerun `nst keygen --ckd` on any device to recover it",
                path.display()
            );
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
        Cmd::Put {
            src,
            uri,
            public,
            content_type,
            share,
        } => {
            let c = client(&cli)?;
            let uri = NearUri::parse(uri)?;
            let mut data = vec![];
            if src == "-" {
                std::io::stdin().read_to_end(&mut data)?;
            } else {
                data = std::fs::read(src).with_context(|| format!("reading {src}"))?;
            }
            let rec = c
                .put(
                    &uri,
                    &data,
                    &PutOptions {
                        public: *public,
                        content_type: content_type.clone(),
                        share_with: share.clone(),
                    },
                )
                .await?;
            eprintln!(
                "{uri} seq={} size={} stored={}",
                rec.seq, rec.size, rec.stored_size
            );
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
                println!(
                    "{:>12}  seq={:<4} {:<24} {}",
                    e.size, e.seq, e.writer, e.path
                );
            }
        }
        Cmd::Share { uri, recipient } => {
            let rec = client(&cli)?
                .share(&NearUri::parse(uri)?, recipient)
                .await?;
            eprintln!("shared; seq={}", rec.seq);
        }
        Cmd::Whoami => {
            let c = client(&cli)?;
            println!("account: {}", c.account());
            println!(
                "x25519:  {}",
                c.x25519_public()
                    .unwrap_or_else(|| "(no root key; run `nst keygen`)".into())
            );
        }
        Cmd::Rm { uri } => {
            client(&cli)?.delete(&NearUri::parse(uri)?).await?;
        }
    }
    Ok(())
}

fn ed25519_dalek_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng)
}
