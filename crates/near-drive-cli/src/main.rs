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
    Client, PutOptions,
};
use nearcli::{FunctionCall, KeyKind, NearCli, NearCliConfig};
use std::io::{IsTerminal, Write};
use std::path::PathBuf;

const DEFAULT_GATEWAY: &str = "http://127.0.0.1:8787";
const DEFAULT_CONTRACT: &str = "drive.near";
const CALL_TGAS: u64 = 50;

#[derive(Parser)]
#[command(name = "near-drive", about = "NEAR Drive: end-to-end encrypted storage addressed by NEAR accounts (also runs as `near drive`)")]
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
    #[arg(long, env = "NEAR_DRIVE_NO_INTERACTIVE", global = true)]
    no_interactive: bool,
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
}

#[derive(Subcommand, Clone)]
enum Cmd {
    /// List files under a prefix (default: your whole namespace).
    /// Paths without `near://` are in your own namespace: `docs/` = `near://<you>/docs/`.
    Ls { uri: Option<String> },
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
    /// Create your encryption root key.
    Keygen {
        /// Derive it from your NEAR account with MPC Confidential Key
        /// Derivation (one transaction; the same key on every device).
        #[arg(long, conflicts_with = "random")]
        ckd: bool,
        /// A random key stored only on this machine (back it up).
        #[arg(long)]
        random: bool,
        /// MPC contract (default: the near-cli connection's `mpc_contract_account_id`).
        #[arg(long)]
        ckd_contract: Option<String>,
        /// CKD domain id (default 2).
        #[arg(long)]
        ckd_domain: Option<u64>,
    },
    /// Publish your X25519 key in the contract so others can share to you (transaction via near-cli).
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
    },
    /// Stop the background service started by `up`.
    Down,
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
    },
}

#[derive(Subcommand, Clone)]
enum SyncCmd {
    /// Sync a local folder (created if missing) with a NEAR Drive folder
    /// (default `Drive/` in your namespace). `near drive up` keeps it in sync.
    Add { dir: Option<PathBuf>, remote: Option<String> },
    /// Stop syncing a folder (its files stay).
    Remove { dir: Option<PathBuf> },
    /// Synced folders, last sync, conflicts and errors.
    Status,
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
        choice(Cmd::Ls { uri: None }, "ls          - List your files"),
        choice(Cmd::Get { uri: None, dst: None, range: None }, "get         - Download a file"),
        choice(Cmd::Put { src: None, uri: None, public: false, content_type: None, share: vec![], class: None, no_resume: false }, "put         - Upload a file"),
        choice(Cmd::Rm { uri: None }, "rm          - Delete a file"),
        choice(Cmd::Share { uri: None, recipient: None }, "share       - Give another account access to a file"),
        choice(Cmd::Grant { uri: None, read: vec![], write: vec![], payer: None }, "grant       - Set who can read/write a folder (onchain rule)"),
        choice(Cmd::Rules { namespace: None }, "rules       - Show a namespace's access rules"),
        choice(Cmd::Whoami, "whoami      - Show account, signing key and sharing key"),
        choice(Cmd::Login { allowance: "0.25 NEAR".into() }, "login       - Add a NEAR Drive session key (via near-cli)"),
        choice(Cmd::Keygen { ckd: false, random: false, ckd_contract: None, ckd_domain: None }, "keygen      - Create your encryption key"),
        choice(Cmd::PublishKey, "publish-key - Let others share files with you"),
        choice(Cmd::Gateways, "gateways    - List registered gateways"),
        choice(Cmd::Sync { action: Some(SyncCmd::Add { dir: None, remote: None }) }, "sync add    - Keep a local folder in sync (like Dropbox)"),
        choice(Cmd::Sync { action: Some(SyncCmd::Status) }, "sync status - Synced folders and their state"),
        choice(Cmd::Up { proxy: ProxyArgs::default(), no_s3: false }, "up          - Start syncing + the local S3 endpoint (background)"),
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

    /// The key that signs gateway requests: `--credentials`, else whatever
    /// near-cli has for the account (session key preferred).
    async fn request_key(&mut self) -> Result<(String, SigningKey, Option<nearcli::FoundKey>)> {
        let account = self.account()?;
        if let Some(path) = &self.cli.credentials {
            let (cred_account, sk) = keys::NearCredentials::load(path)?;
            if cred_account != account {
                bail!("credentials are for {cred_account}, not {account}");
            }
            return Ok((account, sk, None));
        }
        let conn = self.conn()?.clone();
        let found = nearcli::find_request_key(&self.cfg, &conn, &account, &self.cli.contract).await?;
        Ok((account, found.key.clone(), Some(found)))
    }

    async fn client(&mut self) -> Result<Client> {
        let (account, sk, _) = self.request_key().await?;
        let root = load_root(&self.root_key_path(&account)?)?;
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
        if let Some(rpc) = &rpc {
            c = c.with_chain(rpc, &self.cli.contract);
        }
        c.parallelism = self.cli.parallel.max(1);
        c.set_net(near_drive_client::NetConfig { attempts: self.cli.retries.max(1), ..Default::default() });
        c.chunk_size = self.cli.chunk_mib * 1024 * 1024;
        Ok(c)
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

    async fn keygen(&mut self, ckd: bool, ckd_contract: Option<String>, ckd_domain: Option<u64>) -> Result<()> {
        let account = self.account()?;
        let path = self.root_key_path(&account)?;
        if path.exists() {
            bail!("{} already exists; refusing to overwrite", path.display());
        }
        if !ckd {
            write_private(&path, &hex::encode(RootKey::generate().as_bytes()))?;
            eprintln!("root key written to {} — back it up; losing it loses your encrypted data", path.display());
            return Ok(());
        }
        use near_drive_ckd::{near as ckdnear, CkdRequestArgs, CkdResponse, EphemeralKey, DERIVATION_PATH};
        let conn = self.conn()?.clone();
        let rpc = self.rpc_url()?;
        let contract = ckd_contract
            .or(conn.mpc_contract_account_id.clone())
            .with_context(|| format!("near-cli connection {:?} has no mpc_contract_account_id; pass --ckd-contract", self.network))?;
        let domain = ckd_domain.unwrap_or(2);
        let mpc_pk = ckdnear::Rpc::new(&rpc).mpc_public_key(&contract, domain).await?;
        let eph = EphemeralKey::generate();
        let root = if let Some(cred) = &self.cli.credentials {
            // Explicit key file: sign here, without near-cli.
            let (cred_account, key) = keys::NearCredentials::load(cred)?;
            if cred_account != account {
                bail!("credentials are for {cred_account}, not {account}");
            }
            let net = near_drive_ckd::CkdNetwork { network: conn.network_name.clone(), rpc_url: rpc, contract: contract.clone(), domain_id: domain };
            ckdnear::request_root_key(&net, &ckdnear::Signer { account_id: account.clone(), key }, DERIVATION_PATH).await?
        } else {
            let args: serde_json::Value = serde_json::from_slice(&CkdRequestArgs::new(&eph, DERIVATION_PATH, domain).to_call_args())?;
            eprintln!("requesting your CKD root key from {contract} (domain {domain}); costs gas + 1 yoctoNEAR and needs a full-access key");
            let out = self.near().call_capture(&FunctionCall {
                signer: &account,
                network: &self.network,
                contract: &contract,
                method: ckdnear::METHOD,
                args: &args,
                gas_tgas: ckdnear::DEFAULT_GAS / 1_000_000_000_000,
                deposit_yocto: ckdnear::DEPOSIT_YOCTO,
            })?;
            let resp: CkdResponse = serde_json::from_slice(out.trim_ascii()).with_context(|| format!("parsing CKD response from near: {:?}", String::from_utf8_lossy(&out)))?;
            near_drive_ckd::root_key_from_response(&resp, &eph, &account, DERIVATION_PATH, &mpc_pk)?
        };
        write_private(&path, &hex::encode(root.as_bytes()))?;
        eprintln!("CKD root key cached at {}; `near drive keygen --ckd` recovers it on any device", path.display());
        Ok(())
    }

    /// A contract call: near-cli signs, unless `--credentials` was given.
    async fn transact(&mut self, method: &str, args: serde_json::Value, deposit: u128) -> Result<()> {
        let account = self.account()?;
        if let Some(path) = &self.cli.credentials {
            let signer = near_drive_chain::Signer::from_credentials_file(path)?;
            if signer.account_id != account {
                bail!("credentials are for {}, not {account}", signer.account_id);
            }
            self.contract()?.rpc.call(&signer, &self.cli.contract, method, &args, CALL_TGAS * near_drive_chain::TGAS, deposit).await?;
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
    let mut ctx = Ctx { account: None, cli, cfg, network, network_prompted, p };
    run(&mut ctx, cmd).await
}

async fn run(ctx: &mut Ctx, cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Ls { uri } => {
            let c = ctx.client().await?;
            let uri = match uri {
                Some(u) => resolve_uri(&u, c.account())?,
                None => resolve_uri("", c.account())?,
            };
            ctx.echo(&["ls".into(), uri.to_string()]);
            for e in c.list(&uri).await? {
                println!("{:>12}  seq={:<4} {:<24} {}", e.size, e.seq, e.writer, e.path);
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
            let c = ctx.client().await?;
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
            let c = ctx.client().await?;
            let asked = uri.is_none();
            let uri = ctx.object_uri(uri, "File to delete:", &c).await?;
            if asked && !ctx.p.confirm(&format!("Delete {uri}?"), false)? {
                bail!("cancelled");
            }
            ctx.echo(&["rm".into(), uri.to_string()]);
            c.delete(&uri).await?;
        }
        Cmd::Share { uri, recipient } => {
            let c = ctx.client().await?;
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
        Cmd::Keygen { ckd, random, ckd_contract, ckd_domain } => {
            ctx.account()?; // ask for the account before the key type
            let ckd = if ckd || random { ckd } else if ctx.p.enabled { choose_ckd(ctx)? } else { false };
            let mut words = vec!["keygen".to_string(), if ckd { "--ckd" } else { "--random" }.into()];
            if let Some(c) = &ckd_contract {
                words.extend(["--ckd-contract".into(), c.clone()]);
            }
            ctx.echo(&words);
            ctx.keygen(ckd, ckd_contract, ckd_domain).await?;
        }
        Cmd::PublishKey => {
            let account = ctx.account()?;
            ctx.echo(&["publish-key".into()]);
            let root = load_root(&ctx.root_key_path(&account)?)?.context("no root key; run `near drive keygen` first")?;
            let key = root.x25519_public();
            ctx.transact("set_enc_key", serde_json::json!({ "key": key }), near_drive_chain::storage_deposit_for(key.len())).await?;
            println!("{key}");
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
                Some(r) => println!("x25519:   {}\nroot key: {}", r.x25519_public(), root_path.display()),
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
        Cmd::Daemon { proxy, no_s3 } => {
            syncs::init_tracing();
            let c = std::sync::Arc::new(ctx.client().await?);
            let (home, account, network) = (ctx.drive_home()?, c.account().to_string(), ctx.network.clone());
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
                        choice(SyncCmd::Status, "status - Synced folders and their state"),
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
                SyncCmd::Status => syncs::status(ctx)?,
                SyncCmd::Exclude { dir, subfolder } => syncs::set_excluded(ctx, dir, &subfolder, true)?,
                SyncCmd::Include { dir, subfolder } => syncs::set_excluded(ctx, dir, &subfolder, false)?,
                SyncCmd::Run { dir, remote, watch, exclude } => {
                    let dir = PathBuf::from(ctx.p.text(dir.map(|d| d.display().to_string()), "Local folder:", "DIR", None, None)?);
                    syncs::run(ctx, dir, remote, watch, exclude).await?;
                }
            }
        }
        Cmd::Up { proxy, no_s3 } => daemon::up(ctx, proxy, no_s3).await?,
        Cmd::Down => {
            ctx.echo(&["down".into()]);
            daemon::down(&ctx.drive_home()?)?;
        }
    }
    Ok(())
}

/// The S3 endpoint (foreground `s3-proxy`, or part of the background service).
async fn run_s3(ctx: &mut Ctx, proxy: ProxyArgs) -> Result<()> {
    let ProxyArgs { listen, buckets, public_prefixes, max_body_mib, region, .. } = proxy.clone();
    use near_drive_s3::{backend::ClientBackend, Proxy, ProxyConfig};
    near_drive_s3::check_loopback(&listen)?;
    let c = ctx.client().await?;
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
    let proxy = Proxy::new(cfg, ClientBackend::new(c));
    eprintln!("NEAR Drive S3 proxy for {account} on http://{listen} (bucket = namespace, e.g. http://{listen}/{account}/key)");
    near_drive_s3::run(listen, proxy).await?;
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

/// After login: offer to create the root key when there is none.
async fn offer_keygen(ctx: &mut Ctx, account: &str) -> Result<()> {
    if ctx.root_key_path(account)?.exists() || !ctx.p.enabled {
        return Ok(());
    }
    if ctx.p.confirm("No encryption key on this machine yet. Create it now?", true)? {
        let ckd = choose_ckd(ctx)?;
        ctx.keygen(ckd, None, None).await?;
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
