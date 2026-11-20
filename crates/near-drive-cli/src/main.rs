//! `near-drive`: the NEAR Drive CLI.
//!
//! Runs standalone (`near-drive ls ...`) or as a near-cli-rs extension
//! (`near drive ls ...`: `near` runs `near-drive` for subcommands it does not
//! know). NEAR keys are never managed here: request-signing keys are read from
//! near-cli's keychain, and transactions are signed and sent by `near`
//! (see `nearcli.rs`). Run with no subcommand, or with missing arguments, in a
//! terminal to be asked for them.
mod daemon;
mod interactive;
mod nearcli;
mod syncs;

use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use interactive::{basename, choice, split_list, Prompter};
use near_drive_client::{
    near_drive_core::{crypto::RootKey, keys, policy::Rule, NearUri},
    Client, PublishedKeys, PutOptions,
};
use nearcli::{FunctionCall, KeyKind, NearCli, NearCliConfig};
use std::io::{IsTerminal, Write};
use std::path::PathBuf;

const DEFAULT_GATEWAY: &str = "http://127.0.0.1:8787";
const DEFAULT_CONTRACT: &str = "drive.near";
const CALL_TGAS: u64 = 50;

#[derive(Parser)]
#[command(name = "near-drive", version, about = "NEAR Drive: end-to-end encrypted storage addressed by NEAR accounts (also runs as `near drive`)")]
struct Cli {
    #[arg(long, env = "NEAR_DRIVE_GATEWAY", default_value = DEFAULT_GATEWAY, global = true)]
    gateway: String,
    /// NEAR account to act as (asked for in interactive mode).
    #[arg(long, env = "NEAR_DRIVE_ACCOUNT", global = true)]
    account: Option<String>,
    /// near-cli network connection (`mainnet`, `testnet`, or any name from
    /// `near config show-connections`). Default: mainnet.
    #[arg(long, env = "NEAR_DRIVE_NETWORK", global = true)]
    network: Option<String>,
    /// Use this key file (NEAR credentials JSON) for everything instead of
    /// near-cli: request signing and transactions. For dev gateways and CI.
    #[arg(long, env = "NEAR_DRIVE_CREDENTIALS", global = true)]
    credentials: Option<PathBuf>,
    /// Directory for encryption root keys (default ~/.near-drive).
    #[arg(long, env = "NEAR_DRIVE_HOME", global = true)]
    home: Option<PathBuf>,
    /// Concurrent chunk transfers for put/get.
    #[arg(long, env = "NEAR_DRIVE_PARALLEL", default_value_t = near_drive_client::DEFAULT_PARALLELISM, global = true)]
    parallel: usize,
    /// Attempts per network request (transient failures are retried with backoff).
    #[arg(long, env = "NEAR_DRIVE_RETRIES", default_value_t = 8, global = true)]
    retries: u32,
    /// Chunk size in MiB for uploads (1..=64).
    #[arg(long, env = "NEAR_DRIVE_CHUNK_MIB", default_value_t = 4, global = true)]
    chunk_mib: usize,
    /// NEAR RPC (default: the near-cli connection's). With
    /// `--gateway auto` a gateway is picked from the onchain registry.
    #[arg(long, env = "NEAR_RPC_URL", global = true)]
    rpc_url: Option<String>,
    /// The NEAR Drive contract account.
    #[arg(long, env = "NEAR_DRIVE_CONTRACT", default_value = DEFAULT_CONTRACT, global = true)]
    contract: String,
    /// near-cli-rs binary.
    #[arg(long, env = "NEAR_DRIVE_NEAR_BIN", default_value = "near", global = true)]
    near_bin: String,
    /// near-cli words that pick the transaction signer, e.g.
    /// "sign-with-keychain send" or "sign-with-ledger send". Default: near-cli
    /// asks (interactive), or "sign-with-keychain send".
    #[arg(long, env = "NEAR_DRIVE_NEAR_SIGN", global = true)]
    near_sign: Option<String>,
    /// Never prompt; fail on missing arguments.
    #[arg(long, env = "NEAR_DRIVE_NO_INTERACTIVE", value_parser = clap::builder::BoolishValueParser::new(), global = true)]
    no_interactive: bool,
    /// INSECURE, dev gateways only: accept records without checking that the
    /// writer published the signing key (a gateway could then forge data).
    #[arg(long, env = "NEAR_DRIVE_INSECURE_SKIP_WRITER_CHECK", value_parser = clap::builder::BoolishValueParser::new(), global = true)]
    insecure_skip_writer_check: bool,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(clap::Args, Clone)]
struct ProxyArgs {
    #[arg(long, default_value = "127.0.0.1:9000")]
    listen: std::net::SocketAddr,
    /// S3 access key (default: generated once and stored in <home>/s3-proxy.json).
    #[arg(long, env = "NEAR_DRIVE_S3_ACCESS_KEY", requires = "secret_key")]
    access_key: Option<String>,
    #[arg(long, env = "NEAR_DRIVE_S3_SECRET_KEY", requires = "access_key", hide_env_values = true)]
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
    /// Serve an existing bucket name from a NEAR Drive folder, e.g.
    /// `delta-artifacts=near://app.near/artifacts/`; repeatable.
    #[arg(long = "bucket-alias", value_name = "NAME=near://ACCOUNT/PREFIX/")]
    bucket_aliases: Vec<String>,
    /// Browser origin allowed to call the endpoint (CORS, e.g. presigned
    /// uploads from a web page); repeatable, `*` = any.
    #[arg(long = "cors-origin")]
    cors_origins: Vec<String>,
    /// Domain for virtual-host addressing (`<bucket>.<domain>`); repeatable.
    #[arg(long = "virtual-host-domain")]
    vhost_domains: Vec<String>,
    /// Allow listening on a non-loopback address, so other machines can use
    /// the endpoint (and its presigned URLs). Put it behind TLS.
    #[arg(long, env = "NEAR_DRIVE_S3_PUBLIC_LISTEN", value_parser = clap::builder::BoolishValueParser::new())]
    public_listen: bool,
}

#[derive(Subcommand, Clone)]
enum Cmd {
    /// List files under a prefix (default: your whole namespace).
    /// Paths without `near://` are in your own namespace: `docs/` = `near://<you>/docs/`.
    Ls {
        uri: Option<String>,
        /// One level only: files directly under the prefix plus its subfolders
        /// (listed with a trailing `/`), instead of everything recursively.
        #[arg(long)]
        dir: bool,
    },
    /// Download a file (to stdout when no destination is given).
    Get {
        uri: Option<String>,
        dst: Option<PathBuf>,
        /// Only bytes START-END (inclusive, like HTTP Range), e.g. `0-1023` or `1048576-`.
        #[arg(long)]
        range: Option<String>,
    },
    /// Upload a file (or `-` for stdin): `put notes.txt` stores
    /// `near://<you>/notes.txt`; `put notes.txt docs/` stores `docs/notes.txt`.
    Put {
        src: Option<String>,
        uri: Option<String>,
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
        /// Start over instead of resuming an interrupted upload of this file.
        #[arg(long)]
        no_resume: bool,
    },
    /// Delete a file.
    Rm { uri: Option<String> },
    /// Give someone the key to a file: an account name (its key is looked up
    /// in the contract) or an `x25519:<base58>` key.
    Share { uri: Option<String>, recipient: Option<String> },
    /// Add or replace (by prefix) an access rule in your namespace (transaction via near-cli).
    /// Example: `near drive grant 'near://app.near/users/{account}/' --read '{account}' --write '{account},app.near' --payer app.near`
    Grant {
        /// `near://<your account>/<prefix>`
        uri: Option<String>,
        #[arg(long, value_delimiter = ',')]
        read: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        write: Vec<String>,
        #[arg(long)]
        payer: Option<String>,
    },
    /// Print a namespace's access rules.
    Rules { namespace: Option<String> },
    /// Add a NEAR Drive session key to your account with near-cli: a
    /// function-call key limited to the drive contract, kept in near-cli's keychain.
    Login {
        /// Gas allowance of the key (it only signs storage requests, not transactions).
        #[arg(long, default_value = "0.25 NEAR")]
        allowance: String,
    },
    /// Delete the NEAR Drive session key from your account (transaction via near-cli).
    Logout,
    /// Create your encryption root key (`--ckd` or `--random`; asked for in a terminal).
    Keygen {
        /// Derive it from your NEAR account with MPC Confidential Key
        /// Derivation (one transaction; the same key on every device). Recommended.
        #[arg(long, conflicts_with = "random")]
        ckd: bool,
        /// A random key stored only on this machine (back it up with `key export`).
        #[arg(long)]
        random: bool,
        /// MPC contract. Pinned on mainnet (`v1.signer`) and testnet
        /// (`v1.signer-prod.testnet`); required on other networks.
        #[arg(long)]
        ckd_contract: Option<String>,
        /// CKD domain id. Pinned to 2 on mainnet/testnet; required on other networks.
        #[arg(long)]
        ckd_domain: Option<u64>,
        /// Allow an MPC contract or CKD domain other than the pinned ones
        /// (including the near-cli connection's `mpc_contract_account_id`).
        /// Each derives a different root key.
        #[arg(long)]
        ckd_unpinned: bool,
        /// Save the key even if it does not match the keys already published
        /// for the account (then `publish-key` to rotate; data encrypted to the
        /// old key stays unreadable to the new one).
        #[arg(long)]
        force: bool,
    },
    /// Back up or restore your encryption root key.
    Key {
        #[command(subcommand)]
        action: Option<KeyCmd>,
    },
    /// Publish your X25519 key (so others can share to you) and your record-signing key (so readers
    /// accept what you write) in the contract (transactions via near-cli).
    PublishKey,
    /// Show the account, the key used to sign requests and your sharing key.
    Whoami,
    /// List gateways registered in the contract.
    Gateways,
    /// Generate an ed25519 key in NEAR credentials format (for dev gateways).
    DevKey {
        #[arg(long)]
        out: PathBuf,
    },
    /// Start the background service: the local S3-compatible endpoint
    /// (loopback only; boto3 / aws-cli: endpoint_url=http://127.0.0.1:9000 and
    /// the printed keys) and every synced folder (`near drive sync add`).
    Up {
        #[command(flatten)]
        proxy: ProxyArgs,
        /// Only sync folders; no S3 endpoint.
        #[arg(long)]
        no_s3: bool,
        /// Also serve the local provider API for the macOS File Provider
        /// extension (Finder shows the folder, files download on open).
        #[arg(long, value_name = "REMOTE", num_args = 0..=1, default_missing_value = "Drive/")]
        file_provider: Option<String>,
    },
    /// Stop the background service started by `up`.
    Down,
    /// Mount a NEAR Drive folder as a drive: everything is listed, files
    /// download when opened and upload when closed (Linux; macOS with
    /// macFUSE / FUSE-T). Runs until Ctrl-C.
    Mount {
        /// Empty local folder to mount on.
        mountpoint: Option<PathBuf>,
        /// NEAR Drive folder (default `Drive/` in your namespace).
        remote: Option<String>,
        #[arg(long)]
        read_only: bool,
        /// Local cache for opened files, in MiB.
        #[arg(long, default_value_t = 10240)]
        cache_mib: u64,
    },
    /// Keep local folders in sync with NEAR Drive (like Dropbox).
    Sync {
        #[command(subcommand)]
        action: Option<SyncCmd>,
    },
    /// Run the local S3-compatible endpoint in the foreground (for containers / systemd).
    S3Proxy {
        #[command(flatten)]
        proxy: ProxyArgs,
    },
    /// What `up` runs in the background (S3 endpoint + synced folders), in the foreground.
    #[command(hide = true)]
    Daemon {
        #[command(flatten)]
        proxy: ProxyArgs,
        #[arg(long)]
        no_s3: bool,
        #[arg(long)]
        file_provider: Option<String>,
    },
}

#[derive(Subcommand, Clone)]
enum KeyCmd {
    /// Print your root key (hex), or write it to a file (mode 0600). Anyone
    /// with it can read your private files and sign records as you.
    Export {
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Install a root key exported elsewhere (`-` reads it from stdin). It is
    /// checked against the keys published for your account first.
    Import {
        #[arg(conflicts_with = "file")]
        hex: Option<String>,
        /// Read the key from this file (e.g. one written by `key export --out`).
        #[arg(long)]
        file: Option<PathBuf>,
        /// Replace a different existing key, and/or save a key that does not
        /// match the published ones.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Default)]
struct KeygenOpts {
    ckd: bool,
    ckd_contract: Option<String>,
    ckd_domain: Option<u64>,
    ckd_unpinned: bool,
    force: bool,
}

#[derive(Subcommand, Clone)]
enum SyncCmd {
    /// Sync a local folder (created if missing) with a NEAR Drive folder
    /// (default `Drive/` in your namespace). `near drive up` keeps it in sync.
    Add { dir: Option<PathBuf>, remote: Option<String> },
    /// Stop syncing a folder (its files stay).
    Remove { dir: Option<PathBuf> },
    /// Synced folders, last sync, conflicts and errors.
    Status {
        /// Machine-readable (used by the tray app).
        #[arg(long)]
        json: bool,
    },
    /// Selective sync: stop syncing a subfolder (e.g. `Videos`) of a synced folder.
    Exclude { dir: PathBuf, subfolder: String },
    /// Sync a previously excluded subfolder again.
    Include { dir: PathBuf, subfolder: String },
    /// Sync a folder now, in the foreground (`--watch`: keep going).
    Run {
        dir: Option<PathBuf>,
        remote: Option<String>,
        #[arg(long)]
        watch: bool,
        /// Leave this subfolder out; repeatable.
        #[arg(long)]
        exclude: Vec<String>,
    },
}

fn menu() -> Vec<interactive::Choice<Cmd>> {
    vec![
        choice(Cmd::Ls { uri: None, dir: false }, "ls          - List your files"),
        choice(Cmd::Get { uri: None, dst: None, range: None }, "get         - Download a file"),
        choice(Cmd::Put { src: None, uri: None, public: false, content_type: None, share: vec![], class: None, no_resume: false }, "put         - Upload a file"),
        choice(Cmd::Rm { uri: None }, "rm          - Delete a file"),
        choice(Cmd::Share { uri: None, recipient: None }, "share       - Give another account access to a file"),
        choice(Cmd::Grant { uri: None, read: vec![], write: vec![], payer: None }, "grant       - Set who can read/write a folder (onchain rule)"),
        choice(Cmd::Rules { namespace: None }, "rules       - Show a namespace's access rules"),
        choice(Cmd::Whoami, "whoami      - Show account, signing key and sharing key"),
        choice(Cmd::Login { allowance: "0.25 NEAR".into() }, "login       - Add a NEAR Drive session key (via near-cli)"),
        choice(Cmd::Keygen { ckd: false, random: false, ckd_contract: None, ckd_domain: None, ckd_unpinned: false, force: false }, "keygen      - Create your encryption key"),
        choice(Cmd::Key { action: Some(KeyCmd::Export { out: None }) }, "key export  - Back up your encryption key"),
        choice(Cmd::Key { action: Some(KeyCmd::Import { hex: None, file: None, force: false }) }, "key import  - Restore your encryption key from a backup"),
        choice(Cmd::PublishKey, "publish-key - Publish your keys (needed to write; lets others share with you)"),
        choice(Cmd::Gateways, "gateways    - List registered gateways"),
        choice(Cmd::Sync { action: Some(SyncCmd::Add { dir: None, remote: None }) }, "sync add    - Keep a local folder in sync (like Dropbox)"),
        choice(Cmd::Sync { action: Some(SyncCmd::Status { json: false }) }, "sync status - Synced folders and their state"),
        choice(Cmd::Up { proxy: ProxyArgs::default(), no_s3: false, file_provider: None }, "up          - Start syncing + the local S3 endpoint (background)"),
        choice(Cmd::Down, "down        - Stop the local S3 endpoint"),
        choice(Cmd::Logout, "logout      - Remove the NEAR Drive session key"),
    ]
}

struct Ctx {
    cli: Cli,
    cfg: NearCliConfig,
    network: String,
    network_prompted: bool,
    account: Option<String>,
    p: Prompter,
    /// The published-key check ran (once per process).
    key_checked: bool,
}

/// `near://ns/path` as is; anything else is a path in `account`'s namespace.
fn resolve_uri(s: &str, account: &str) -> Result<NearUri> {
    if s.starts_with("near://") {
        return Ok(NearUri::parse(s)?);
    }
    Ok(NearUri::parse(&format!("near://{account}/{}", s.trim_start_matches('/')))?)
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).context("HOME not set")
}

fn parse_root_hex(s: &str, what: &str) -> Result<RootKey> {
    let b: [u8; 32] = hex::decode(s.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .with_context(|| format!("{what} is not a root key (64 hex characters)"))?;
    Ok(RootKey::from_bytes(b))
}

fn load_root(path: &PathBuf) -> Result<Option<RootKey>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(parse_root_hex(&s, &path.display().to_string())?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Like [`write_private`] but replaces an existing file (atomically).
fn replace_private(path: &PathBuf, contents: &str) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    write_private(&tmp, contents)?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
}

const BACKUP_BANNER: &str = "\
==========================================================================
 BACK UP THIS KEY NOW. It exists only on this machine. If it is lost,
 your private files are unreadable and your published keys useless:
     near drive key export --out <file on a USB stick / password manager>
==========================================================================";

/// What to tell the user when a root key and the published keys disagree.
fn mismatch_text(account: &str, contract: &str, source: &str, m: &PublishedKeys) -> String {
    let PublishedKeys::Mismatch { published_enc, published_sign, enc, sign } = m else {
        return String::new();
    };
    let show = |p: &Option<String>| p.clone().unwrap_or_else(|| "(none)".into());
    format!(
        "the root key {source} does not match the keys {account} published in {contract}:\n  \
         encryption key: published {}, this key {enc}\n  \
         signing key:    published {}, this key {sign}\n\
         The published keys belong to a different root key; your existing data and records were made with it.",
        show(published_enc),
        show(published_sign),
    )
}

fn write_private(path: &PathBuf, contents: &str) -> Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    // Unix: owner-only. Windows: files under the user profile are private to the user by default ACLs.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o
        .open(path)
        .with_context(|| format!("creating {} (refusing to overwrite an existing key)", path.display()))?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
}

impl Ctx {
    fn drive_home(&self) -> Result<PathBuf> {
        match &self.cli.home {
            Some(h) => Ok(h.clone()),
            None => Ok(home_dir()?.join(".near-drive")),
        }
    }

    fn root_key_path(&self, account: &str) -> Result<PathBuf> {
        Ok(self.drive_home()?.join("keys").join(format!("{account}.root")))
    }

    fn conn(&self) -> Result<&nearcli::Connection> {
        self.cfg.connection(&self.network)
    }

    fn rpc_url(&self) -> Result<String> {
        match &self.cli.rpc_url {
            Some(u) => Ok(u.clone()),
            None => Ok(self.conn()?.rpc_url.clone()),
        }
    }

    fn contract(&self) -> Result<near_drive_chain::StorageContract> {
        Ok(near_drive_chain::StorageContract::new(self.rpc_url()?, &self.cli.contract))
    }

    fn near(&self) -> NearCli {
        NearCli {
            bin: self.cli.near_bin.clone(),
            sign: self.cli.near_sign.as_deref().map(nearcli::split_words).unwrap_or_default(),
            interactive: self.p.enabled,
        }
    }

    fn account(&mut self) -> Result<String> {
        if let Some(a) = &self.account {
            return Ok(a.clone());
        }
        let mut known = self.cfg.legacy_accounts(&self.conn().map(|c| c.network_name.clone()).unwrap_or_default());
        for a in self.cfg.used_accounts() {
            if !known.contains(&a) {
                known.push(a);
            }
        }
        let a = self.p.account(self.cli.account.clone(), known)?;
        near_drive_client::near_drive_core::uri::validate_account_id(&a).with_context(|| format!("invalid account {a:?}"))?;
        self.account = Some(a.clone());
        Ok(a)
    }

    /// The key that signs gateway requests: `NEAR_DRIVE_SECRET_KEY` (services,
    /// containers), `--credentials`, else whatever near-cli has for the
    /// account (session key preferred).
    async fn request_key(&mut self) -> Result<(String, SigningKey, Option<nearcli::FoundKey>)> {
        let account = self.account()?;
        if let Ok(sk) = std::env::var("NEAR_DRIVE_SECRET_KEY") {
            return Ok((account, keys::parse_secret_key(sk.trim()).context("NEAR_DRIVE_SECRET_KEY")?, None));
        }
        if let Some(path) = &self.cli.credentials {
            let (_, sk) = keys::NearCredentials::load_for(path, Some(&account))?;
            return Ok((account, sk, None));
        }
        let conn = self.conn()?.clone();
        let found = nearcli::find_request_key(&self.cfg, &conn, &account, &self.cli.contract).await?;
        Ok((account, found.key.clone(), Some(found)))
    }

    async fn client(&mut self) -> Result<Client> {
        let (account, sk, _) = self.request_key().await?;
        let root = self.load_root_key(&account)?.map(|(r, _)| r);
        if !(1..=64).contains(&self.cli.chunk_mib) {
            bail!("--chunk-mib must be in 1..=64");
        }
        let rpc = self.rpc_url().ok();
        let gateway = match (self.cli.gateway.as_str(), &rpc) {
            ("auto", Some(rpc)) => near_drive_client::discover_gateway(rpc, &self.cli.contract).await?,
            ("auto", None) => bail!("--gateway auto needs --rpc-url"),
            (g, _) => g.to_string(),
        };
        let mut c = Client::new(gateway, account, sk, root);
        if self.cli.insecure_skip_writer_check {
            eprintln!("WARNING: --insecure-skip-writer-check: records are not checked against published signing keys");
            c = c.insecure_skip_writer_check();
        }
        if let Some(rpc) = &rpc {
            c = c.with_chain(rpc, &self.cli.contract);
        }
        c.parallelism = self.cli.parallel.max(1);
        c.set_net(near_drive_client::NetConfig { attempts: self.cli.retries.max(1), ..Default::default() });
        c.chunk_size = self.cli.chunk_mib * 1024 * 1024;
        Ok(c)
    }

    /// [`client`](Self::client) for commands that write: first checks the
    /// root key against the keys published for the account.
    async fn write_client(&mut self) -> Result<Client> {
        let c = self.client().await?;
        self.check_before_write(c.account()).await?;
        Ok(c)
    }

    /// The root key commands use: `NEAR_DRIVE_ROOT_KEY` (services,
    /// containers), else `<home>/keys/<account>.root`; with where it came from.
    fn load_root_key(&self, account: &str) -> Result<Option<(RootKey, String)>> {
        if let Ok(hex_key) = std::env::var("NEAR_DRIVE_ROOT_KEY") {
            return Ok(Some((parse_root_hex(&hex_key, "NEAR_DRIVE_ROOT_KEY")?, "from NEAR_DRIVE_ROOT_KEY".into())));
        }
        let path = self.root_key_path(account)?;
        Ok(load_root(&path)?.map(|r| (r, format!("in {}", path.display()))))
    }

    /// The contract to compare root keys with; `None` in dev setups (no
    /// usable RPC, or `--insecure-skip-writer-check`), where the check is skipped.
    fn key_check_contract(&self) -> Option<near_drive_chain::StorageContract> {
        if self.cli.insecure_skip_writer_check {
            return None;
        }
        self.contract().ok()
    }

    /// Before saving a new root key (keygen, key import): refuse one that does
    /// not match what the account already published, unless `force`.
    async fn check_before_save(&mut self, account: &str, root: &RootKey, source: &str, force: bool) -> Result<Option<PublishedKeys>> {
        let Some(contract) = self.key_check_contract() else { return Ok(None) };
        self.key_checked = true;
        let r = match near_drive_client::check_published_keys(&contract, account, root).await {
            Ok(r) => r,
            Err(e) if force => {
                eprintln!("warning: could not compare with the keys published for {account} ({e:#}); saving anyway (--force)");
                return Ok(None);
            }
            Err(e) => bail!("could not compare the key with the keys published for {account} in {}: {e:#}\nRetry, or pass --force to save it unchecked", contract.contract_id),
        };
        if matches!(r, PublishedKeys::Mismatch { .. }) {
            let text = mismatch_text(account, &contract.contract_id, source, &r);
            if !force {
                bail!(
                    "{text}\nRefusing to save it. Use `near drive key import` with the right key (`near drive key export` prints it on a device that has it; \
                     a key from `keygen --ckd` can be derived again with `keygen --ckd`).\n\
                     Or pass --force and then run `near drive publish-key` to rotate to this key: data encrypted to the old key stays unreadable to this one."
                );
            }
            eprintln!("warning: {text}\nSaving anyway (--force). Run `near drive publish-key` to rotate the published keys to this one.");
        }
        Ok(Some(r))
    }

    /// Before a command writes with the cached / env root key: a key that does
    /// not match the published ones is an error (its records would be rejected
    /// and nobody could share to it); unpublished keys are a warning. One
    /// view-call pair per process; skipped in dev setups.
    async fn check_before_write(&mut self, account: &str) -> Result<()> {
        if self.key_checked {
            return Ok(());
        }
        self.key_checked = true;
        let Some(contract) = self.key_check_contract() else { return Ok(()) };
        let Some((root, source)) = self.load_root_key(account)? else { return Ok(()) };
        match near_drive_client::check_published_keys(&contract, account, &root).await {
            Ok(PublishedKeys::Match | PublishedKeys::NoContract) => Ok(()),
            Ok(PublishedKeys::Missing { enc, sign }) => {
                let what = match (enc, sign) {
                    (true, true) => "its keys",
                    (false, true) => "its record-signing key",
                    _ => "its encryption key",
                };
                eprintln!(
                    "warning: {account} has not published {what} in {}; run `near drive publish-key`{}",
                    contract.contract_id,
                    if sign { " (until then others reject the records you write)" } else { " (until then nobody can share files with you)" }
                );
                Ok(())
            }
            Ok(m) => bail!(
                "{}\nRefusing to write. Use the matching key (`near drive key import`, or NEAR_DRIVE_ROOT_KEY), \
                 or run `near drive publish-key` to rotate the published keys to this one (data encrypted to the old key stays unreadable to this one).",
                mismatch_text(account, &contract.contract_id, &source, &m)
            ),
            Err(e) => {
                eprintln!("warning: could not check the keys published for {account} ({e:#})");
                Ok(())
            }
        }
    }

    /// After prompting, show the command that does the same without prompts.
    fn echo(&self, words: &[String]) {
        if !self.p.used {
            return;
        }
        let mut argv: Vec<String> = Vec::new();
        if self.cli.network.is_some() || self.network_prompted {
            argv.extend(["--network".into(), self.network.clone()]);
        }
        if let Some(a) = &self.account {
            argv.extend(["--account".into(), a.clone()]);
        }
        if self.cli.gateway != DEFAULT_GATEWAY {
            argv.extend(["--gateway".into(), self.cli.gateway.clone()]);
        }
        if self.cli.contract != DEFAULT_CONTRACT {
            argv.extend(["--contract".into(), self.cli.contract.clone()]);
        }
        argv.extend(words.iter().cloned());
        let prog = if on_path(&self.cli.near_bin) { "near drive" } else { "near-drive" };
        eprintln!("\nTo repeat without prompts:\n  {prog} {}\n", nearcli::shell_join(&argv));
    }

    /// An object URI: given, or typed with a `near://<account>/` start and
    /// picked from a listing when the answer ends with `/`.
    async fn object_uri(&mut self, value: Option<String>, msg: &str, c: &Client) -> Result<NearUri> {
        if let Some(v) = value {
            return resolve_uri(&v, c.account());
        }
        let start = format!("near://{}/", c.account());
        let mut s = self.p.uri(None, msg, &start, Some("end with / to pick from a listing"))?;
        while s.ends_with('/') {
            let prefix = NearUri::parse(&s)?;
            let entries = c.list(&prefix).await?;
            if entries.is_empty() {
                bail!("nothing under {s}");
            }
            let opts = entries
                .iter()
                .map(|e| choice(format!("near://{}/{}", prefix.namespace, e.path), format!("{:<48} {:>12}", e.path, human(e.size))))
                .collect();
            s = self.p.select("Pick a file:", "URI", opts)?;
        }
        Ok(NearUri::parse(&s)?)
    }

    async fn keygen(&mut self, o: KeygenOpts) -> Result<()> {
        let account = self.account()?;
        let path = self.root_key_path(&account)?;
        if path.exists() {
            bail!("{} already exists; refusing to overwrite (`near drive key export` shows it; `key import --force` replaces it)", path.display());
        }
        let root = if o.ckd { self.ckd_root(&account, &o).await? } else { RootKey::generate() };
        let source = if o.ckd { "derived with CKD" } else { "just generated" };
        let published = self.check_before_save(&account, &root, source, o.force).await?;
        write_private(&path, &hex::encode(root.as_bytes()))?;
        if o.ckd {
            eprintln!("CKD root key cached at {}; `near drive keygen --ckd` recovers it on any device", path.display());
        } else {
            eprintln!("root key written to {}\n{BACKUP_BANNER}", path.display());
        }
        match published {
            Some(PublishedKeys::Match) => eprintln!("it matches the keys {account} published"),
            Some(PublishedKeys::Missing { .. }) => eprintln!("next: `near drive publish-key` (others reject your records until your keys are published)"),
            _ => {}
        }
        Ok(())
    }

    /// Requests the account's root key from the MPC network (CKD).
    async fn ckd_root(&mut self, account: &str, o: &KeygenOpts) -> Result<RootKey> {
        use near_drive_ckd::{near as ckdnear, CkdRequestArgs, CkdResponse, EphemeralKey, DERIVATION_PATH};
        let conn = self.conn()?.clone();
        let rpc = self.rpc_url()?;
        let target = near_drive_ckd::resolve_target(&conn.network_name, conn.mpc_contract_account_id.as_deref(), o.ckd_contract.as_deref(), o.ckd_domain, o.ckd_unpinned)?;
        let (contract, domain) = (target.contract.clone(), target.domain_id);
        if !target.pinned && near_drive_ckd::pinned_contract(&conn.network_name).is_some() {
            eprintln!("warning: CKD from {contract} domain {domain} is not NEAR Drive's pinned target; it derives a different root key than `keygen --ckd`");
        }
        let mpc_pk = ckdnear::Rpc::new(&rpc).mpc_public_key(&contract, domain).await?;
        let eph = EphemeralKey::generate();
        if let Some(cred) = &self.cli.credentials {
            // Explicit key file: sign here, without near-cli.
            let (_, key) = keys::NearCredentials::load_for(cred, Some(account))?;
            let net = near_drive_ckd::CkdNetwork { network: conn.network_name.clone(), rpc_url: rpc, contract, domain_id: domain };
            return ckdnear::request_root_key(&net, &ckdnear::Signer { account_id: account.to_string(), key }, DERIVATION_PATH).await;
        }
        let args: serde_json::Value = serde_json::from_slice(&CkdRequestArgs::new(&eph, DERIVATION_PATH, domain).to_call_args())?;
        eprintln!("requesting your CKD root key from {contract} (domain {domain}); costs ~0.002 NEAR of gas + 1 yoctoNEAR and needs a full-access key");
        let out = self.near().call_capture(&FunctionCall {
            signer: account,
            network: &self.network,
            contract: &contract,
            method: ckdnear::METHOD,
            args: &args,
            gas_tgas: ckdnear::DEFAULT_GAS / 1_000_000_000_000,
            deposit_yocto: ckdnear::DEPOSIT_YOCTO,
        })?;
        let resp: CkdResponse = serde_json::from_slice(nearcli::json_value(&out)).with_context(|| format!("parsing CKD response from near: {:?}", String::from_utf8_lossy(&out)))?;
        near_drive_ckd::root_key_from_response(&resp, &eph, account, DERIVATION_PATH, &mpc_pk)
    }

    /// A contract call: near-cli signs, unless `--credentials` was given.
    async fn transact(&mut self, method: &str, args: serde_json::Value, deposit: u128) -> Result<()> {
        let account = self.account()?;
        if let Some(path) = &self.cli.credentials {
            let signer = near_drive_chain::Signer::from_credentials_file_for(path, &account)?;
            let out = self.contract()?.rpc.call(&signer, &self.cli.contract, method, &args, CALL_TGAS * near_drive_chain::TGAS, deposit).await?;
            eprintln!("{method}: transaction {}", out.tx_hash);
            return Ok(());
        }
        self.near().call(&FunctionCall {
            signer: &account,
            network: &self.network,
            contract: &self.cli.contract,
            method,
            args: &args,
            gas_tgas: CALL_TGAS,
            deposit_yocto: deposit,
        })
    }
}

fn human(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut cli = Cli::parse();
    let interactive = !cli.no_interactive && std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    let cfg = NearCliConfig::load()?;
    let mut p = Prompter::new(interactive);
    let cmd = match cli.cmd.take() {
        Some(c) => c,
        None if interactive => p.select("What do you want to do?", "COMMAND", menu())?,
        None => {
            Cli::command().print_help()?;
            std::process::exit(2);
        }
    };
    let (network, network_prompted) = match &cli.network {
        Some(n) => (n.clone(), false),
        None if p.used && cfg.connections.len() > 1 => {
            let mut names: Vec<String> = cfg.connections.keys().cloned().collect();
            names.sort_by_key(|n| (n != "mainnet", n != "testnet", n.clone()));
            let n = p.select("Which network (near-cli connection)?", "--network", names.into_iter().map(|n| choice(n.clone(), n)).collect())?;
            (n, true)
        }
        None => ("mainnet".to_string(), false),
    };
    let mut ctx = Ctx { account: None, cli, cfg, network, network_prompted, p, key_checked: false };
    run(&mut ctx, cmd).await
}

async fn run(ctx: &mut Ctx, cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Ls { uri, dir } => {
            let c = ctx.client().await?;
            let uri = match uri {
                Some(u) => resolve_uri(&u, c.account())?,
                None => resolve_uri("", c.account())?,
            };
            let mut echo = vec!["ls".to_string(), uri.to_string()];
            if dir {
                echo.push("--dir".into());
            }
            ctx.echo(&echo);
            // Page by page, so huge listings start printing at once.
            let mut cursor: Option<String> = None;
            loop {
                let page = c.list_page(&uri, dir.then_some("/"), cursor.as_deref(), None).await?;
                let mut lines: Vec<(String, String)> = page.entries.iter().map(|e| (e.path.clone(), format!("{:>12}  seq={:<4} {:<24} {}", e.size, e.seq, e.writer, e.path))).collect();
                lines.extend(page.common_prefixes.iter().map(|p| (p.clone(), format!("{:>12}  {:<33} {p}", "-", "(folder)"))));
                lines.sort();
                for (_, l) in lines {
                    println!("{l}");
                }
                match page.next_cursor {
                    Some(n) if Some(&n) != cursor.as_ref() => cursor = Some(n),
                    _ => break,
                }
            }
        }
        Cmd::Get { uri, dst, range } => {
            let c = ctx.client().await?;
            let uri = ctx.object_uri(uri, "File to download:", &c).await?;
            let dst = match dst {
                Some(d) => Some(d),
                // Don't dump file bytes into a terminal: ask where to save.
                None if ctx.p.enabled && std::io::stdout().is_terminal() => {
                    Some(PathBuf::from(ctx.p.text(None, "Save to:", "DST", Some(&basename(&uri.path)?), None)?))
                }
                None => None,
            };
            let mut words = vec!["get".to_string(), uri.to_string()];
            words.extend(dst.as_ref().map(|d| d.display().to_string()));
            if let Some(r) = &range {
                words.extend(["--range".into(), r.clone()]);
            }
            ctx.echo(&words);
            if let Some(r) = range {
                let data = c.get_range(&uri, parse_range(&r)?).await?;
                match dst {
                    Some(p) => std::fs::write(p, &data)?,
                    None => std::io::stdout().write_all(&data)?,
                }
            } else {
                match &dst {
                    Some(p) => {
                        c.get_to_file(&uri, p).await?;
                        if ctx.p.used {
                            eprintln!("saved {}", p.display());
                        }
                    }
                    None => c.get_to_writer(&uri, tokio::io::stdout()).await.map(|_| ())?,
                }
            }
        }
        Cmd::Put { src, uri, public, content_type, share, class, no_resume } => {
            let c = ctx.write_client().await?;
            let src = ctx.p.text(src, "File to upload:", "SRC", None, Some("path, or - for stdin"))?;
            if src != "-" && !std::path::Path::new(&src).is_file() {
                bail!("{src} is not a file");
            }
            let prompted_src = ctx.p.used;
            let uri = match uri {
                Some(u) => u,
                None if prompted_src => {
                    let start = if src == "-" { format!("near://{}/", c.account()) } else { format!("near://{}/{}", c.account(), basename(&src)?) };
                    ctx.p.uri(None, "Save as:", &start, None)?
                }
                None if src == "-" => bail!("missing destination path (reading from stdin)"),
                None => String::new(),
            };
            // A folder (or nothing) as destination: keep the local file name.
            let uri = if (uri.is_empty() || uri.ends_with('/')) && src != "-" { format!("{uri}{}", basename(&src)?) } else { uri };
            let uri = resolve_uri(&uri, c.account())?;
            let public = public || (prompted_src && ctx.p.confirm("Store it unencrypted (public)?", false)?);
            let mut words = vec!["put".to_string(), src.clone(), uri.to_string()];
            if public {
                words.push("--public".into());
            }
            if let Some(cl) = &class {
                words.extend(["--class".into(), cl.clone()]);
            }
            ctx.echo(&words);
            // Interrupted file uploads resume from a journal in <home>/uploads.
            let resume_dir = if src == "-" || no_resume { None } else { Some(ctx.drive_home()?.join("uploads")) };
            let opts = PutOptions { public, content_type, share_with: share, class, resume_dir, ..Default::default() };
            // streaming: bounded memory, parallel chunk uploads
            let rec = if src == "-" { c.put_reader(tokio::io::stdin(), &uri, &opts).await? } else { c.put_file(&src, &uri, &opts).await? };
            eprintln!("{uri} seq={} size={} stored={}", rec.seq, rec.size, rec.stored_size);
        }
        Cmd::Rm { uri } => {
            let c = ctx.write_client().await?;
            let asked = uri.is_none();
            let uri = ctx.object_uri(uri, "File to delete:", &c).await?;
            if asked && !ctx.p.confirm(&format!("Delete {uri}?"), false)? {
                bail!("cancelled");
            }
            ctx.echo(&["rm".into(), uri.to_string()]);
            c.delete(&uri).await?;
        }
        Cmd::Share { uri, recipient } => {
            let c = ctx.write_client().await?;
            let uri = ctx.object_uri(uri, "File to share:", &c).await?;
            let recipient = ctx.p.text(recipient, "Share with:", "RECIPIENT", None, Some("an account (bob.near) or an x25519:<base58> key"))?;
            ctx.echo(&["share".into(), uri.to_string(), recipient.clone()]);
            let rec = if recipient.starts_with("x25519:") { c.share(&uri, &recipient).await? } else { c.share_with_account(&uri, &recipient).await? };
            eprintln!("shared; seq={}", rec.seq);
        }
        Cmd::Grant { uri, mut read, mut write, mut payer } => {
            let account = ctx.account()?;
            let asked = uri.is_none();
            let uri = ctx.p.uri(uri, "Folder (prefix) the rule applies to:", &format!("near://{account}/"), Some("{account} matches any account id in that segment"))?;
            let uri = resolve_uri(&uri, &account)?;
            if uri.namespace != account {
                bail!("you can only set rules for your own namespace ({account}), not {}", uri.namespace);
            }
            if asked {
                let help = Some("comma-separated accounts; {account} = the account named in the path; empty = only you");
                read = split_list(&ctx.p.optional_text("Who can read:", help)?.unwrap_or_default());
                write = split_list(&ctx.p.optional_text("Who can write:", help)?.unwrap_or_default());
                payer = ctx.p.optional_text("Who pays for storage (empty = you):", None)?;
            }
            let rule = Rule { prefix: uri.path.clone(), read, write, payer };
            let mut words = vec!["grant".to_string(), uri.to_string()];
            if !rule.read.is_empty() {
                words.extend(["--read".into(), rule.read.join(",")]);
            }
            if !rule.write.is_empty() {
                words.extend(["--write".into(), rule.write.join(",")]);
            }
            if let Some(p) = &rule.payer {
                words.extend(["--payer".into(), p.clone()]);
            }
            ctx.echo(&words);
            let mut rules = ctx.contract()?.get_rules(&account).await?;
            near_drive_chain::upsert_rule(&mut rules, rule);
            let args = serde_json::json!({ "rules": rules });
            let deposit = near_drive_chain::storage_deposit_for(args.to_string().len());
            ctx.transact("set_rules", args, deposit).await?;
            println!("{}", serde_json::to_string_pretty(&rules)?);
        }
        Cmd::Rules { namespace } => {
            let namespace = match namespace {
                Some(n) => n,
                None if ctx.cli.account.is_some() || !ctx.p.enabled => ctx.account()?,
                None => {
                    let a = ctx.account()?;
                    ctx.p.text(None, "Namespace (account):", "NAMESPACE", Some(&a), None)?
                }
            };
            ctx.echo(&["rules".into(), namespace.clone()]);
            let rules = ctx.contract()?.get_rules(&namespace).await?;
            println!("{}", serde_json::to_string_pretty(&rules)?);
        }
        Cmd::Login { allowance } => {
            if ctx.cli.credentials.is_some() {
                bail!("login adds a key through near-cli; drop --credentials");
            }
            let account = ctx.account()?;
            ctx.echo(&["login".into()]);
            let conn = ctx.conn()?.clone();
            if let Ok(found) = nearcli::find_request_key(&ctx.cfg, &conn, &account, &ctx.cli.contract).await {
                if found.kind == KeyKind::Session {
                    eprintln!("{account} already has a NEAR Drive session key {} ({})", found.public_key, found.source);
                    return offer_keygen(ctx, &account).await;
                }
            }
            ctx.near().add_session_key(&account, &ctx.network, &ctx.cli.contract, &allowance)?;
            let found = nearcli::find_request_key(&ctx.cfg, &conn, &account, &ctx.cli.contract).await?;
            if found.kind != KeyKind::Session {
                bail!("the new key is not visible yet (found {} instead); retry `near drive whoami` in a few seconds", found.public_key);
            }
            eprintln!("logged in: requests from {account} are signed with {} ({})", found.public_key, found.source);
            offer_keygen(ctx, &account).await?;
        }
        Cmd::Logout => {
            let account = ctx.account()?;
            ctx.echo(&["logout".into()]);
            let conn = ctx.conn()?.clone();
            let found = nearcli::find_request_key(&ctx.cfg, &conn, &account, &ctx.cli.contract).await?;
            if found.kind != KeyKind::Session {
                bail!("{account} has no NEAR Drive session key stored here (found {:?} key {})", found.kind, found.public_key);
            }
            ctx.near().delete_key(&account, &ctx.network, &found.public_key)?;
            eprintln!("deleted {} from {account} (the local copy in {} is now unused)", found.public_key, found.source);
        }
        Cmd::Keygen { ckd, random, ckd_contract, ckd_domain, ckd_unpinned, force } => {
            if !(ckd || random || ctx.p.enabled) {
                bail!(
                    "keygen needs --ckd or --random when not run in a terminal.\n  \
                     --ckd (recommended): derived from your NEAR account by NEAR's MPC network; the same key on every device, recoverable with one transaction.\n  \
                     --random: a key that exists only on this machine; back it up with `near drive key export`."
                );
            }
            ctx.account()?; // ask for the account before the key type
            let ckd = if ckd || random { ckd } else { choose_ckd(ctx)? };
            let mut words = vec!["keygen".to_string(), if ckd { "--ckd" } else { "--random" }.into()];
            if let Some(c) = &ckd_contract {
                words.extend(["--ckd-contract".into(), c.clone()]);
            }
            if let Some(d) = ckd_domain {
                words.extend(["--ckd-domain".into(), d.to_string()]);
            }
            if ckd_unpinned {
                words.push("--ckd-unpinned".into());
            }
            if force {
                words.push("--force".into());
            }
            ctx.echo(&words);
            ctx.keygen(KeygenOpts { ckd, ckd_contract, ckd_domain, ckd_unpinned, force }).await?;
        }
        Cmd::Key { action } => {
            let action = match action {
                Some(a) => a,
                None => ctx.p.select(
                    "Key:",
                    "SUBCOMMAND",
                    vec![
                        choice(KeyCmd::Export { out: None }, "export - Back up your encryption key"),
                        choice(KeyCmd::Import { hex: None, file: None, force: false }, "import - Restore your encryption key from a backup"),
                    ],
                )?,
            };
            key_cmd(ctx, action).await?;
        }
        Cmd::PublishKey => {
            let account = ctx.account()?;
            ctx.echo(&["publish-key".into()]);
            let root = load_root(&ctx.root_key_path(&account)?)?.context("no root key; run `near drive keygen` first")?;
            let key = root.x25519_public();
            ctx.transact("set_enc_key", serde_json::json!({ "key": key }), near_drive_chain::storage_deposit_for(key.len())).await?;
            let sign = root.sign_public_key();
            ctx.transact("set_sign_key", serde_json::json!({ "key": sign }), near_drive_chain::storage_deposit_for(sign.len() + 32)).await?;
            println!("{key}\n{sign}");
        }
        Cmd::Whoami => {
            let (account, sk, found) = ctx.request_key().await?;
            ctx.echo(&["whoami".into()]);
            println!("account:  {account} ({})", ctx.network);
            println!(
                "near-cli: {} (keys in {})",
                ctx.cfg.path.as_ref().map_or("no config.toml; built-in networks".into(), |p| p.display().to_string()),
                ctx.cfg.credentials_home.display()
            );
            let pk = keys::format_public_key(&sk.verifying_key());
            match found {
                Some(f) => {
                    let kind = match f.kind {
                        KeyKind::Session => "NEAR Drive session key",
                        KeyKind::FullAccess => "full-access key; `near drive login` adds a limited session key",
                        KeyKind::Unverified => "not checked onchain",
                    };
                    println!("signing:  {pk} ({kind}; from {})", f.source);
                }
                None => println!("signing:  {pk} (from --credentials)"),
            }
            let root_path = ctx.root_key_path(&account)?;
            match load_root(&root_path)? {
                Some(r) => println!("x25519:   {}\nrecords:  {} (record-signing key)\nroot key: {}", r.x25519_public(), r.sign_public_key(), root_path.display()),
                None => println!("x25519:   (no root key; run `near drive keygen`)"),
            }
        }
        Cmd::Gateways => {
            for g in ctx.contract()?.all_gateways().await? {
                let state = if g.active { "active" } else { "leaving" };
                println!("{:<24} {:<7} {:<40} regions={} backends={} {}", g.operator, state, g.url, g.regions.join(","), g.backends.join(","), g.price_hint);
            }
        }
        Cmd::DevKey { out } => {
            let account = ctx.account()?;
            let sk = SigningKey::generate(&mut rand::rngs::OsRng);
            let json = serde_json::json!({
                "account_id": account,
                "public_key": keys::format_public_key(&sk.verifying_key()),
                "private_key": keys::format_secret_key(&sk),
            });
            write_private(&out, &serde_json::to_string_pretty(&json)?)?;
            println!("{}", keys::format_public_key(&sk.verifying_key()));
        }
        Cmd::S3Proxy { proxy } => {
            syncs::init_tracing();
            ctx.echo(&["s3-proxy".into()]);
            run_s3(ctx, proxy).await?;
        }
        Cmd::Daemon { proxy, no_s3, file_provider } => {
            syncs::init_tracing();
            let c = std::sync::Arc::new(ctx.write_client().await?);
            let (home, account, network) = (ctx.drive_home()?, c.account().to_string(), ctx.network.clone());
            // Kept alive for the life of the service.
            let _provider = match file_provider {
                Some(r) => Some(file_provider_api(c.clone(), &r, &home).await?),
                None => None,
            };
            let sync = syncs::supervise(c, home, account, network);
            if no_s3 {
                sync.await?;
            } else {
                tokio::try_join!(run_s3(ctx, proxy), sync)?;
            }
        }
        Cmd::Sync { action } => {
            let action = match action {
                Some(a) => a,
                None => ctx.p.select(
                    "Sync:",
                    "SUBCOMMAND",
                    vec![
                        choice(SyncCmd::Add { dir: None, remote: None }, "add    - Sync a local folder"),
                        choice(SyncCmd::Status { json: false }, "status - Synced folders and their state"),
                        choice(SyncCmd::Run { dir: None, remote: None, watch: false, exclude: vec![] }, "run    - Sync a folder now"),
                        choice(SyncCmd::Remove { dir: None }, "remove - Stop syncing a folder"),
                    ],
                )?,
            };
            match action {
                SyncCmd::Add { dir, remote } => {
                    let account = ctx.account()?;
                    let default_dir = home_dir().map(|h| h.join("NearDrive").display().to_string()).unwrap_or_else(|_| "NearDrive".into());
                    let asked = dir.is_none();
                    let dir = PathBuf::from(ctx.p.text(dir.map(|d| d.display().to_string()), "Local folder:", "DIR", Some(&default_dir), Some("created if it doesn't exist"))?);
                    let remote = match remote {
                        Some(r) => Some(r),
                        None if asked => Some(ctx.p.text(None, "NEAR Drive folder:", "REMOTE", Some(&format!("near://{account}/Drive/")), None)?),
                        None => None,
                    };
                    let mut words = vec!["sync".to_string(), "add".into(), dir.display().to_string()];
                    words.extend(remote.clone());
                    ctx.echo(&words);
                    syncs::add(ctx, dir, remote).await?;
                }
                SyncCmd::Remove { dir } => {
                    let dir = PathBuf::from(ctx.p.text(dir.map(|d| d.display().to_string()), "Folder to stop syncing:", "DIR", None, None)?);
                    syncs::remove(ctx, dir)?;
                }
                SyncCmd::Status { json: false } => syncs::status(ctx)?,
                SyncCmd::Status { json: true } => syncs::status_json(ctx)?,
                SyncCmd::Exclude { dir, subfolder } => syncs::set_excluded(ctx, dir, &subfolder, true)?,
                SyncCmd::Include { dir, subfolder } => syncs::set_excluded(ctx, dir, &subfolder, false)?,
                SyncCmd::Run { dir, remote, watch, exclude } => {
                    let dir = PathBuf::from(ctx.p.text(dir.map(|d| d.display().to_string()), "Local folder:", "DIR", None, None)?);
                    syncs::run(ctx, dir, remote, watch, exclude).await?;
                }
            }
        }
        Cmd::Up { proxy, no_s3, file_provider } => daemon::up(ctx, proxy, no_s3, file_provider).await?,
        Cmd::Mount { mountpoint, remote, read_only, cache_mib } => {
            if !near_drive_mount::SUPPORTED {
                bail!("{}", if cfg!(target_os = "macos") {
                    "this build has no mount support: install macFUSE or FUSE-T and build with `--features macfuse` (or use `near drive sync`)"
                } else {
                    "mounting is not available on this platform; use `near drive sync add <folder>` instead"
                });
            }
            let account = ctx.account()?;
            let default_mp = home_dir().map(|h| h.join("NEAR Drive").display().to_string()).unwrap_or_else(|_| "NEAR Drive".into());
            let mp = PathBuf::from(ctx.p.text(mountpoint.map(|d| d.display().to_string()), "Mount at:", "MOUNTPOINT", Some(&default_mp), Some("an empty folder; created if missing"))?);
            let remote = syncs::remote_prefix(remote.as_deref(), &account)?;
            ctx.echo(&["mount".into(), mp.display().to_string(), remote.to_string()]);
            std::fs::create_dir_all(&mp)?;
            // FUSE mounts over the folder, hiding what's there; on Windows the
            // folder itself holds the placeholders, so reconnecting is fine.
            if cfg!(unix) && std::fs::read_dir(&mp)?.next().is_some() {
                bail!("{} is not empty", mp.display());
            }
            syncs::init_tracing();
            let c = std::sync::Arc::new(if read_only { ctx.client().await? } else { ctx.write_client().await? });
            let mut opts = near_drive_mount::MountOptions::new(ctx.drive_home()?.join("cache").join(&account));
            opts.read_only = read_only;
            opts.cache_max_bytes = cache_mib << 20;
            let m = near_drive_mount::mount(c, remote.clone(), &mp, opts, tokio::runtime::Handle::current())?;
            eprintln!("{remote} mounted at {} (files download when opened). Ctrl-C to {}.", mp.display(), if cfg!(windows) { "disconnect" } else { "unmount" });
            tokio::signal::ctrl_c().await?;
            tokio::task::spawn_blocking(move || m.unmount()).await??;
            eprintln!("unmounted {}", mp.display());
        }
        Cmd::Down => {
            ctx.echo(&["down".into()]);
            daemon::down(&ctx.drive_home()?)?;
        }
    }
    Ok(())
}

/// Serve the provider API for the macOS File Provider extension and publish
/// where to find it: `<home>/provider.json`, and on macOS the App Group
/// container the extension can read (`NEAR_DRIVE_APP_GROUP`, default
/// `group.ai.near.drive`).
async fn file_provider_api(c: std::sync::Arc<near_drive_client::Client>, remote: &str, home: &std::path::Path) -> Result<near_drive_mount::provider::ProviderApi> {
    let remote = syncs::remote_prefix(Some(remote), c.account())?;
    let api = near_drive_mount::provider::serve(c, remote, home.join("provider-tmp")).await?;
    near_drive_mount::provider::publish(&api.endpoint, &home.join("provider.json"))?;
    if cfg!(target_os = "macos") {
        let group = std::env::var("NEAR_DRIVE_APP_GROUP").unwrap_or_else(|_| "group.ai.near.drive".into());
        if let Some(dir) = near_drive_mount::provider::app_group_dir(&group) {
            near_drive_mount::provider::publish(&api.endpoint, &dir.join("provider.json"))?;
        }
    }
    tracing::info!("file provider API for {} on {}", api.endpoint.remote, api.endpoint.url);
    Ok(api)
}

/// The S3 endpoint (foreground `s3-proxy`, or part of the background service).
async fn run_s3(ctx: &mut Ctx, proxy: ProxyArgs) -> Result<()> {
    let ProxyArgs { listen, buckets, public_prefixes, max_body_mib, region, bucket_aliases, cors_origins, vhost_domains, public_listen, .. } = proxy.clone();
    use near_drive_s3::{backend::ClientBackend, Proxy, ProxyConfig};
    near_drive_s3::check_listen(&listen, public_listen)?;
    let mut aliases = std::collections::BTreeMap::new();
    for a in &bucket_aliases {
        let (name, target) = a.split_once('=').with_context(|| format!("--bucket-alias {a}: expected NAME=near://ACCOUNT/PREFIX/"))?;
        aliases.insert(name.to_string(), near_drive_s3::backend::Alias::parse(target).map_err(|e| anyhow::anyhow!("--bucket-alias {a}: {e}"))?);
    }
    let c = ctx.write_client().await?;
    let creds = s3_credentials(ctx, &proxy)?;
    if c.x25519_public().is_none() && public_prefixes.is_empty() {
        eprintln!("warning: no root key loaded (run `near drive keygen`); private writes will fail");
    }
    let account = c.account().to_string();
    let mut cfg = ProxyConfig::new(creds, ctx.drive_home()?.join("s3-staging"));
    cfg.extra_buckets = buckets;
    cfg.public_prefixes = public_prefixes;
    cfg.max_body_bytes = max_body_mib * 1024 * 1024;
    cfg.region = region;
    cfg.aliases = aliases;
    cfg.cors_origins = cors_origins;
    cfg.vhost_domains.extend(vhost_domains);
    if public_listen && !listen.ip().is_loopback() {
        eprintln!("warning: serving on {listen} for other machines; put it behind TLS (presigned URLs carry signatures)");
    }
    let proxy = Proxy::new(cfg, ClientBackend::new(c));
    eprintln!("NEAR Drive S3 proxy for {account} on http://{listen} (bucket = namespace, e.g. http://{listen}/{account}/key)");
    near_drive_s3::run(listen, proxy, public_listen).await?;
    Ok(())
}

/// `--access-key/--secret-key`, else the ones in `<home>/s3-proxy.json` (created once).
fn s3_credentials(ctx: &Ctx, proxy: &ProxyArgs) -> Result<near_drive_s3::sigv4::Credentials> {
    if let (Some(a), Some(s)) = (&proxy.access_key, &proxy.secret_key) {
        return Ok(near_drive_s3::sigv4::Credentials { access_key: a.clone(), secret_key: s.clone() });
    }
    let path = ctx.drive_home()?.join("s3-proxy.json");
    let (creds, created) = near_drive_s3::credentials::load_or_create(&path)?;
    if created {
        eprintln!("generated S3 credentials (saved to {})", path.display());
    }
    Ok(creds)
}

impl Default for ProxyArgs {
    fn default() -> Self {
        #[derive(Parser)]
        struct W {
            #[command(flatten)]
            a: ProxyArgs,
        }
        W::parse_from(["up"]).a
    }
}

fn choose_ckd(ctx: &mut Ctx) -> Result<bool> {
    ctx.p.select(
        "How should your encryption key be created?",
        "--ckd/--random",
        vec![
            choice(true, "Derive from my NEAR account (MPC CKD; same key on every device; one transaction)"),
            choice(false, "Random key on this machine only (back it up yourself)"),
        ],
    )
}

/// `key export` / `key import`.
async fn key_cmd(ctx: &mut Ctx, action: KeyCmd) -> Result<()> {
    let account = ctx.account()?;
    match action {
        KeyCmd::Export { out } => {
            let mut words = vec!["key".to_string(), "export".into()];
            words.extend(out.iter().flat_map(|o| ["--out".into(), o.display().to_string()]));
            ctx.echo(&words);
            let (root, source) = ctx
                .load_root_key(&account)?
                .with_context(|| format!("no root key for {account} (run `near drive keygen`, or `near drive key import`)"))?;
            eprintln!(
                "WARNING: this is the NEAR Drive root key of {account} ({source}). Anyone with it can read your private files \
                 and sign records as you. Keep it offline (password manager, USB stick); never paste it into chats or tickets."
            );
            let hex_key = hex::encode(root.as_bytes());
            match out {
                Some(p) => {
                    write_private(&p, &format!("{hex_key}\n"))?;
                    eprintln!("written to {} (mode 0600). Restore with `near drive key import --file {}`", p.display(), p.display());
                }
                None => println!("{hex_key}"),
            }
        }
        KeyCmd::Import { hex, file, force } => {
            let text = match (hex, &file) {
                (_, Some(f)) => std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?,
                (Some(h), None) if h == "-" => std::io::read_to_string(std::io::stdin())?,
                (Some(h), None) => h,
                (None, None) => ctx.p.text(None, "Root key (64 hex characters):", "HEX or --file", None, Some("from `near drive key export`"))?,
            };
            let root = parse_root_hex(&text, "the key to import")?;
            let mut words = vec!["key".to_string(), "import".into()];
            words.extend(file.iter().flat_map(|f| ["--file".into(), f.display().to_string()]));
            if force {
                words.push("--force".into());
            }
            ctx.echo(&words);
            let path = ctx.root_key_path(&account)?;
            let existing = load_root(&path)?;
            if let Some(e) = &existing {
                if e.as_bytes() == root.as_bytes() {
                    eprintln!("{} already holds this key", path.display());
                    return Ok(());
                }
                if !force {
                    bail!(
                        "{} holds a different root key; refusing to overwrite it. Data made with it would become unreadable here: \
                         `near drive key export` it first, then pass --force",
                        path.display()
                    );
                }
            }
            let published = ctx.check_before_save(&account, &root, "being imported", force).await?;
            if existing.is_some() {
                replace_private(&path, &hex::encode(root.as_bytes()))?;
            } else {
                write_private(&path, &hex::encode(root.as_bytes()))?;
            }
            eprintln!("root key for {account} saved to {}", path.display());
            match published {
                Some(PublishedKeys::Match) => eprintln!("it matches the keys {account} published"),
                Some(PublishedKeys::Missing { .. }) => eprintln!("next: `near drive publish-key` (others reject your records until your keys are published)"),
                _ => {}
            }
            if std::env::var_os("NEAR_DRIVE_ROOT_KEY").is_some() {
                eprintln!("note: NEAR_DRIVE_ROOT_KEY is set and takes precedence over this file");
            }
        }
    }
    Ok(())
}

/// After login: offer to create the root key when there is none.
async fn offer_keygen(ctx: &mut Ctx, account: &str) -> Result<()> {
    if ctx.root_key_path(account)?.exists() || !ctx.p.enabled {
        return Ok(());
    }
    if ctx.p.confirm("No encryption key on this machine yet. Create it now?", true)? {
        let ckd = choose_ckd(ctx)?;
        ctx.keygen(KeygenOpts { ckd, ..Default::default() }).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    /// Mock NEAR RPC: `get_enc_key` / `get_sign_keys` of `root` (or nothing published).
    async fn mock_rpc(root: Option<RootKey>) -> String {
        use axum::{routing::post, Json, Router};
        let (enc, sign) = match &root {
            Some(r) => (json!(r.x25519_public()), json!([{"key": r.sign_public_key(), "since_ms": "1"}])),
            None => (Value::Null, json!([])),
        };
        let app = Router::new().route(
            "/",
            post(move |Json(req): Json<Value>| {
                let v = match req["params"]["method_name"].as_str() {
                    Some("get_enc_key") => enc.clone(),
                    Some("get_sign_keys") => sign.clone(),
                    m => panic!("unexpected rpc {m:?}"),
                };
                async move { Json(json!({"jsonrpc": "2.0", "id": req["id"], "result": {"result": serde_json::to_vec(&v).unwrap(), "logs": []}})) }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        url
    }

    /// A non-interactive context (as without a terminal) for alice.near.
    fn ctx(home: &std::path::Path, rpc: &str, args: &[&str]) -> (Ctx, Cmd) {
        let mut argv = vec!["near-drive", "--no-interactive", "--account", "alice.near", "--contract", "drive.test", "--rpc-url", rpc];
        let h = home.display().to_string();
        argv.extend(["--home", &h]);
        argv.extend(args);
        let mut cli = Cli::try_parse_from(argv).unwrap();
        let cmd = cli.cmd.take().unwrap();
        let conn = nearcli::Connection { network_name: "mainnet".into(), rpc_url: rpc.into(), mpc_contract_account_id: Some("v1.signer".into()) };
        let cfg = NearCliConfig { path: None, credentials_home: home.join("creds"), connections: [("mainnet".to_string(), conn)].into() };
        (Ctx { cli, cfg, network: "mainnet".into(), network_prompted: false, account: None, p: Prompter::new(false), key_checked: false }, cmd)
    }

    async fn exec(home: &std::path::Path, rpc: &str, args: &[&str]) -> Result<()> {
        let (mut c, cmd) = ctx(home, rpc, args);
        run(&mut c, cmd).await
    }

    fn key_file(home: &std::path::Path) -> PathBuf {
        home.join("keys").join("alice.near.root")
    }

    #[tokio::test]
    async fn keygen_without_terminal_needs_ckd_or_random() {
        let dir = tempfile::tempdir().unwrap();
        let e = exec(dir.path(), "http://127.0.0.1:1", &["keygen"]).await.unwrap_err().to_string();
        assert!(e.contains("--ckd") && e.contains("--random") && e.contains("recommended"), "{e}");
        assert!(!key_file(dir.path()).exists());
    }

    #[tokio::test]
    async fn keygen_random_refuses_when_other_keys_are_published() {
        let dir = tempfile::tempdir().unwrap();
        let rpc = mock_rpc(Some(RootKey::generate())).await;
        let e = exec(dir.path(), &rpc, &["keygen", "--random"]).await.unwrap_err().to_string();
        assert!(e.contains("different root key") && e.contains("key import") && e.contains("--force"), "{e}");
        assert!(!key_file(dir.path()).exists());
        // Nothing published: saved; --force overrides a mismatch.
        exec(dir.path(), &mock_rpc(None).await, &["keygen", "--random"]).await.unwrap();
        assert!(key_file(dir.path()).exists());
        let other = tempfile::tempdir().unwrap();
        exec(other.path(), &rpc, &["keygen", "--random", "--force"]).await.unwrap();
        assert!(key_file(other.path()).exists());
    }

    #[tokio::test]
    async fn export_import_roundtrip_and_refuse_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let rpc = mock_rpc(None).await;
        let k1 = hex::encode([0x11u8; 32]);
        let k2 = hex::encode([0x22u8; 32]);
        exec(dir.path(), &rpc, &["key", "import", &k1]).await.unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(key_file(dir.path())).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let out = dir.path().join("backup.hex");
        exec(dir.path(), &rpc, &["key", "export", "--out", out.to_str().unwrap()]).await.unwrap();
        assert_eq!(std::fs::read_to_string(&out).unwrap().trim(), k1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // Export never overwrites a file.
        assert!(exec(dir.path(), &rpc, &["key", "export", "--out", out.to_str().unwrap()]).await.is_err());
        // Import into a fresh home from the backup file.
        let other = tempfile::tempdir().unwrap();
        exec(other.path(), &rpc, &["key", "import", "--file", out.to_str().unwrap()]).await.unwrap();
        assert_eq!(std::fs::read_to_string(key_file(other.path())).unwrap(), k1);
        // Same key again: fine. A different key: refused without --force.
        exec(dir.path(), &rpc, &["key", "import", &k1]).await.unwrap();
        let e = exec(dir.path(), &rpc, &["key", "import", &k2]).await.unwrap_err().to_string();
        assert!(e.contains("different root key") && e.contains("--force"), "{e}");
        assert_eq!(std::fs::read_to_string(key_file(dir.path())).unwrap(), k1);
        exec(dir.path(), &rpc, &["key", "import", &k2, "--force"]).await.unwrap();
        assert_eq!(std::fs::read_to_string(key_file(dir.path())).unwrap(), k2);
        // Garbage is rejected.
        assert!(exec(other.path(), &rpc, &["key", "import", "abcd", "--force"]).await.is_err());
    }

    #[tokio::test]
    async fn import_checks_published_keys() {
        let dir = tempfile::tempdir().unwrap();
        let published = RootKey::from_bytes([0x33; 32]);
        let rpc = mock_rpc(Some(RootKey::from_bytes([0x33; 32]))).await;
        let e = exec(dir.path(), &rpc, &["key", "import", &hex::encode([0x44u8; 32])]).await.unwrap_err().to_string();
        assert!(e.contains(&published.sign_public_key()) && e.contains("Refusing to save"), "{e}");
        assert!(!key_file(dir.path()).exists());
        exec(dir.path(), &rpc, &["key", "import", &hex::encode(published.as_bytes())]).await.unwrap();
        // Dev mode (--insecure-skip-writer-check): no check, no RPC needed.
        let dev = tempfile::tempdir().unwrap();
        exec(dev.path(), "http://127.0.0.1:1", &["--insecure-skip-writer-check", "key", "import", &hex::encode([0x44u8; 32])]).await.unwrap();
    }

    #[tokio::test]
    async fn write_commands_check_the_cached_key() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("keys")).unwrap();
        std::fs::write(key_file(dir.path()), hex::encode([0x55u8; 32])).unwrap();
        // Mismatch: error before writing.
        let (mut c, _) = ctx(dir.path(), &mock_rpc(Some(RootKey::from_bytes([0x66; 32]))).await, &["whoami"]);
        let e = c.check_before_write("alice.near").await.unwrap_err().to_string();
        assert!(e.contains("Refusing to write") && e.contains("publish-key"), "{e}");
        // Once per process.
        c.check_before_write("alice.near").await.unwrap();
        // Match, nothing published (warning only), unreachable RPC (warning only).
        for rpc in [mock_rpc(Some(RootKey::from_bytes([0x55; 32]))).await, mock_rpc(None).await, "http://127.0.0.1:1".into()] {
            let (mut c, _) = ctx(dir.path(), &rpc, &["whoami"]);
            c.check_before_write("alice.near").await.unwrap();
        }
    }
}
