//! near-cli-rs integration.
//!
//! NEAR Drive does not keep its own NEAR keys. It reads what `near` (near-cli-rs)
//! already manages:
//! - `config.toml` (`~/.config/near-cli/` on Linux): network connections and
//!   `credentials_home_dir`;
//! - the OS keychain entries `near` writes (service `near-<network>-<account>`,
//!   user `<account>:<public key>`);
//! - the legacy keychain files `<credentials_home_dir>/<network>/<account>/<pk>.json`
//!   and `<credentials_home_dir>/<network>/<account>.json`;
//! - `<credentials_home_dir>/accounts.json`, the accounts `near` has used.
//!
//! Transactions (adding the session key, policy rules, publishing the X25519
//! key, the CKD request) are handed to `near` itself, so every signer it
//! supports (keychain, Ledger, seed phrase, MPC, ...) works.
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use near_drive_chain::{KeyPermission, NearRpc};
use near_drive_core::keys;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// One `[network_connection.<name>]` entry.
#[derive(Debug, Clone, Deserialize)]
pub struct Connection {
    /// Directory name under the credentials home (`mainnet`, `testnet`).
    pub network_name: String,
    pub rpc_url: String,
    #[serde(default)]
    pub mpc_contract_account_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NearCliConfig {
    pub path: Option<PathBuf>,
    pub credentials_home: PathBuf,
    pub connections: BTreeMap<String, Connection>,
}

#[derive(Deserialize)]
struct RawConfig {
    credentials_home_dir: Option<PathBuf>,
    #[serde(default)]
    network_connection: BTreeMap<String, Connection>,
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).context("HOME not set")
}

/// Where near-cli-rs keeps `config.toml` (it uses `dirs::config_dir()`).
pub fn config_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("NEAR_DRIVE_NEAR_CLI_CONFIG") {
        return Some(PathBuf::from(p));
    }
    dirs::config_dir().map(|d| d.join("near-cli").join("config.toml"))
}

fn builtin(name: &str) -> Option<Connection> {
    let (rpc, mpc) = match name {
        "mainnet" => ("https://rpc.mainnet.near.org", "v1.signer"),
        "testnet" => ("https://rpc.testnet.near.org", "v1.signer-prod.testnet"),
        _ => return None,
    };
    Some(Connection { network_name: name.into(), rpc_url: rpc.into(), mpc_contract_account_id: Some(mpc.into()) })
}

impl NearCliConfig {
    /// near-cli's config, or built-in mainnet/testnet defaults when `near`
    /// has never been configured on this machine.
    pub fn load() -> Result<Self> {
        let path = config_path();
        let raw = match path.as_ref().map(std::fs::read_to_string) {
            Some(Ok(s)) => Some(toml::from_str::<RawConfig>(&s).with_context(|| format!("parsing {}", path.as_ref().unwrap().display()))?),
            Some(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => None,
            Some(Err(e)) => return Err(e).context("reading near-cli config"),
            None => None,
        };
        let (creds, mut connections) = match raw {
            Some(r) => (r.credentials_home_dir, r.network_connection),
            None => (None, BTreeMap::new()),
        };
        for n in ["mainnet", "testnet"] {
            if !connections.contains_key(n) {
                connections.insert(n.into(), builtin(n).unwrap());
            }
        }
        let credentials_home = match creds {
            Some(c) => c,
            None => home()?.join(".near-credentials"),
        };
        Ok(Self { path: path.filter(|p| p.exists()), credentials_home, connections })
    }

    /// A connection by its near-cli name (`mainnet`, `testnet`, `mainnet-fastnear`, ...).
    pub fn connection(&self, name: &str) -> Result<&Connection> {
        self.connections.get(name).ok_or_else(|| {
            anyhow!(
                "no near-cli network connection {name:?} (have: {}); add one with `near config add-connection`",
                self.connections.keys().cloned().collect::<Vec<_>>().join(", ")
            )
        })
    }

    /// Accounts near-cli has used, most recent first (from `accounts.json`).
    pub fn used_accounts(&self) -> Vec<String> {
        #[derive(Deserialize)]
        struct Used {
            account_id: String,
        }
        std::fs::read(self.credentials_home.join("accounts.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<Vec<Used>>(&b).ok())
            .map(|v| v.into_iter().map(|u| u.account_id).collect())
            .unwrap_or_default()
    }

    /// Accounts with keys in the legacy keychain for `network_name`.
    pub fn legacy_accounts(&self, network_name: &str) -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(self.credentials_home.join(network_name))
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                Some(name.strip_suffix(".json").map(str::to_string).unwrap_or(name))
            })
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

/// How a request-signing key relates to the drive contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// Function-call key for the drive contract: the recommended session key.
    Session,
    FullAccess,
    /// Found locally but not checked onchain (RPC unreachable or the account
    /// does not exist, e.g. a dev gateway with configured keys).
    Unverified,
}

pub struct FoundKey {
    pub key: SigningKey,
    pub public_key: String,
    pub kind: KeyKind,
    pub source: String,
}

fn parse_key_json(bytes: &[u8]) -> Result<SigningKey> {
    let v: serde_json::Value = serde_json::from_slice(bytes)?;
    let sk = v
        .get("private_key")
        .or_else(|| v.get("secret_key"))
        .and_then(|s| s.as_str())
        .context("no private_key in key data")?;
    keys::parse_secret_key(sk)
}

fn keychain_service(network_name: &str, account: &str) -> String {
    format!("near-{network_name}-{account}")
}

fn from_os_keychain(network_name: &str, account: &str, pk: &str) -> Option<SigningKey> {
    let entry = keyring::Entry::new(&keychain_service(network_name, account), &format!("{account}:{pk}")).ok()?;
    let secret = entry.get_password().ok()?;
    parse_key_json(secret.as_bytes()).ok()
}

fn legacy_key_file(cfg: &NearCliConfig, network_name: &str, account: &str, pk: &str) -> PathBuf {
    cfg.credentials_home.join(network_name).join(account).join(format!("{}.json", pk.replace(':', "_")))
}

fn load_matching(path: &Path, pk: &str) -> Option<SigningKey> {
    let sk = parse_key_json(&std::fs::read(path).ok()?).ok()?;
    (keys::format_public_key(&sk.verifying_key()) == pk).then_some(sk)
}

/// Finds a key near-cli manages for `account` that the gateway will accept:
/// a function-call key for `contract` first, then a full-access key. Looks in
/// the OS keychain, then the legacy keychain files.
pub async fn find_request_key(cfg: &NearCliConfig, conn: &Connection, account: &str, contract: &str) -> Result<FoundKey> {
    let net = &conn.network_name;
    match NearRpc::new(&conn.rpc_url).access_key_list(account).await {
        Ok(list) => {
            let mut candidates: Vec<(String, KeyKind)> = Vec::new();
            for (pk, perm) in &list {
                match perm {
                    KeyPermission::FunctionCall { receiver_id } if receiver_id == contract => candidates.push((pk.clone(), KeyKind::Session)),
                    _ => {}
                }
            }
            for (pk, perm) in &list {
                if *perm == KeyPermission::FullAccess {
                    candidates.push((pk.clone(), KeyKind::FullAccess));
                }
            }
            for (pk, kind) in &candidates {
                if let Some(key) = from_os_keychain(net, account, pk) {
                    return Ok(FoundKey { key, public_key: pk.clone(), kind: *kind, source: "OS keychain".into() });
                }
                for path in [legacy_key_file(cfg, net, account, pk), cfg.credentials_home.join(net).join(format!("{account}.json"))] {
                    if let Some(key) = load_matching(&path, pk) {
                        return Ok(FoundKey { key, public_key: pk.clone(), kind: *kind, source: path.display().to_string() });
                    }
                }
            }
            bail!(
                "no key for {account} on {net} found in near-cli's keychain ({} keys onchain, none stored locally).\n\
                 Run `near drive login {account}` to add a NEAR Drive session key, or import a key with `near account import-account`.",
                list.len()
            )
        }
        Err(e) => {
            // Offline / dev gateway: accept any locally stored key, unverified.
            let dir = cfg.credentials_home.join(net).join(account);
            let mut files: Vec<PathBuf> = std::fs::read_dir(&dir).into_iter().flatten().filter_map(|e| e.ok()).map(|e| e.path()).collect();
            files.sort();
            files.push(cfg.credentials_home.join(net).join(format!("{account}.json")));
            for path in files {
                if let Ok(bytes) = std::fs::read(&path) {
                    if let Ok(key) = parse_key_json(&bytes) {
                        let public_key = keys::format_public_key(&key.verifying_key());
                        return Ok(FoundKey { key, public_key, kind: KeyKind::Unverified, source: path.display().to_string() });
                    }
                }
            }
            Err(e).with_context(|| format!("listing access keys of {account} (and no key for it in {})", dir.display()))
        }
    }
}

/// Runs `near` (near-cli-rs) for transactions.
pub struct NearCli {
    pub bin: String,
    /// near-cli words appended after `network-config <net>` to choose the
    /// signer non-interactively, e.g. `sign-with-keychain send`. Empty: let
    /// near-cli ask (interactive) or default to the keychain (non-interactive).
    pub sign: Vec<String>,
    pub interactive: bool,
}

pub struct FunctionCall<'a> {
    pub signer: &'a str,
    pub network: &'a str,
    pub contract: &'a str,
    pub method: &'a str,
    pub args: &'a serde_json::Value,
    pub gas_tgas: u64,
    pub deposit_yocto: u128,
}

impl NearCli {
    fn command(&self) -> Result<Command> {
        let probe = Command::new(&self.bin).arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status();
        if probe.is_err() {
            bail!(
                "`{}` (near-cli-rs) not found. Install it: https://github.com/near/near-cli-rs#installation \
                 (e.g. `cargo install near-cli-rs`), or point --near-bin at it",
                self.bin
            );
        }
        Ok(Command::new(&self.bin))
    }

    fn tail(&self) -> Vec<String> {
        if !self.sign.is_empty() {
            self.sign.clone()
        } else if self.interactive {
            Vec::new()
        } else {
            vec!["sign-with-keychain".into(), "send".into()]
        }
    }

    /// The `near` argv for a function-call transaction.
    pub fn call_args(&self, c: &FunctionCall) -> Vec<String> {
        let mut a: Vec<String> = [
            "contract", "call-function", "as-transaction", c.contract, c.method, "json-args",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        a.push(c.args.to_string());
        a.extend(["prepaid-gas".into(), format!("{} Tgas", c.gas_tgas), "attached-deposit".into(), format!("{} yoctoNEAR", c.deposit_yocto)]);
        a.extend(["sign-as".into(), c.signer.into(), "network-config".into(), c.network.into()]);
        a.extend(self.tail());
        a
    }

    /// Sends a function call through `near`; the user picks the signer there.
    pub fn call(&self, c: &FunctionCall) -> Result<()> {
        self.run(self.call_args(c))
    }

    /// Like [`call`](Self::call) but returns the function's return value.
    /// near-cli prints the return value on stdout and everything else
    /// (prompts, the transaction ID and explorer link) on stderr, which is
    /// passed through so the user sees the transaction hash.
    pub fn call_capture(&self, c: &FunctionCall) -> Result<Vec<u8>> {
        let args = self.call_args(c);
        eprintln!("$ {} {}", self.bin, shell_join(&args));
        let out = self.command()?.args(&args).stdin(Stdio::inherit()).stderr(Stdio::inherit()).stdout(Stdio::piped()).output()?;
        if !out.status.success() {
            bail!("`near` failed ({}); if it printed a transaction ID, check it in an explorer before retrying", out.status);
        }
        Ok(out.stdout)
    }

    /// `near account add-key <account> grant-function-call-access ...`: near-cli
    /// generates the key, stores it in its keychain and signs the AddKey.
    pub fn add_session_key(&self, account: &str, network: &str, contract: &str, allowance: &str) -> Result<()> {
        let mut a: Vec<String> = vec![
            "account".into(), "add-key".into(), account.into(), "grant-function-call-access".into(),
            "--allowance".into(), allowance.into(), "--contract-account-id".into(), contract.into(),
            "--function-names".into(), String::new(), "autogenerate-new-keypair".into(), "save-to-keychain".into(),
            "network-config".into(), network.into(),
        ];
        a.extend(self.tail());
        self.run(a)
    }

    /// `near account delete-keys <account> public-keys <pk> network-config <net> ...`.
    pub fn delete_key(&self, account: &str, network: &str, public_key: &str) -> Result<()> {
        let mut a: Vec<String> = vec![
            "account".into(), "delete-keys".into(), account.into(), "public-keys".into(), public_key.into(),
            "network-config".into(), network.into(),
        ];
        a.extend(self.tail());
        self.run(a)
    }

    fn run(&self, args: Vec<String>) -> Result<()> {
        eprintln!("$ {} {}", self.bin, shell_join(&args));
        let st = self.command()?.args(&args).status()?;
        if !st.success() {
            bail!("`near` failed ({st})");
        }
        Ok(())
    }
}

/// The JSON value in near-cli's stdout (the function's return value),
/// tolerating stray text around a JSON object.
pub fn json_value(out: &[u8]) -> &[u8] {
    let t = out.trim_ascii();
    if serde_json::from_slice::<serde_json::Value>(t).is_ok() {
        return t;
    }
    match (t.iter().position(|&b| b == b'{'), t.iter().rposition(|&b| b == b'}')) {
        (Some(a), Some(b)) if a < b => &t[a..=b],
        _ => t,
    }
}

/// Quote words for display as a shell command.
pub fn shell_join<S: AsRef<str>>(words: &[S]) -> String {
    words.iter().map(|w| shell_quote(w.as_ref())).collect::<Vec<_>>().join(" ")
}

pub fn shell_quote(w: &str) -> String {
    if !w.is_empty() && w.chars().all(|c| c.is_ascii_alphanumeric() || "-_./:=@,+%".contains(c)) {
        w.to_string()
    } else {
        format!("'{}'", w.replace('\'', r"'\''"))
    }
}

/// Split a `--near-sign` value into words (whitespace, honoring simple quotes).
pub fn split_words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut any = false;
    for ch in s.chars() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                quote = Some(ch);
                any = true;
            }
            (None, c) if c.is_whitespace() => {
                if any || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            (None, c) => cur.push(c),
        }
    }
    if any || !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words() {
        assert_eq!(split_words("sign-with-keychain send"), vec!["sign-with-keychain", "send"]);
        assert_eq!(split_words("sign-with-ledger --seed-phrase-hd-path 'm/44 1' send"), vec!["sign-with-ledger", "--seed-phrase-hd-path", "m/44 1", "send"]);
        assert_eq!(split_words("a '' b"), vec!["a", "", "b"]);
        assert_eq!(shell_join(&["put", "my file", "near://a.near/x", ""]), "put 'my file' near://a.near/x ''");
    }

    #[test]
    fn json_value_from_near_stdout() {
        let v = br#"{"big_y":"a","big_c":"b"}"#;
        assert_eq!(json_value(v), v);
        let pretty = b"{\n  \"big_y\": \"a\",\n  \"big_c\": \"b\"\n}\n";
        assert_eq!(json_value(pretty), pretty.trim_ascii());
        assert_eq!(json_value(b"Function execution return value:\n{\"big_y\":\"a\"}\n\n"), br#"{"big_y":"a"}"#);
    }

    #[test]
    fn call_args_shape() {
        let cli = NearCli { bin: "near".into(), sign: vec![], interactive: false };
        let args = serde_json::json!({"key": "x25519:abc"});
        let a = cli.call_args(&FunctionCall { signer: "a.near", network: "mainnet", contract: "drive.near", method: "set_enc_key", args: &args, gas_tgas: 50, deposit_yocto: 7 });
        assert_eq!(
            shell_join(&a),
            r#"contract call-function as-transaction drive.near set_enc_key json-args '{"key":"x25519:abc"}' prepaid-gas '50 Tgas' attached-deposit '7 yoctoNEAR' sign-as a.near network-config mainnet sign-with-keychain send"#
        );
    }

    fn write(p: &Path, s: &str) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, s).unwrap();
    }

    #[test]
    fn config_and_offline_lookup() {
        let dir = std::env::temp_dir().join(format!("nd-nearcli-{}", std::process::id()));
        let creds = dir.join("creds");
        let cfg_path = dir.join("config.toml");
        write(
            &cfg_path,
            &format!(
                "version = \"4\"\ncredentials_home_dir = '{}'\n[network_connection.local]\nnetwork_name = \"localnet\"\nrpc_url = \"http://127.0.0.1:1/\"\nwallet_url = \"x\"\nexplorer_transaction_url = \"x\"\n",
                creds.display()
            ),
        );
        std::env::set_var("NEAR_DRIVE_NEAR_CLI_CONFIG", &cfg_path);
        let cfg = NearCliConfig::load().unwrap();
        assert_eq!(cfg.credentials_home, creds);
        assert!(cfg.connection("mainnet").is_ok() && cfg.connection("local").is_ok());
        assert!(cfg.connection("nope").is_err());
        let sk = SigningKey::from_bytes(&[7; 32]);
        let pk = keys::format_public_key(&sk.verifying_key());
        write(
            &legacy_key_file(&cfg, "localnet", "alice.test", &pk),
            &serde_json::json!({"public_key": pk, "private_key": keys::format_secret_key(&sk)}).to_string(),
        );
        write(&creds.join("accounts.json"), r#"[{"account_id":"alice.test","used_as_signer":true}]"#);
        assert_eq!(cfg.used_accounts(), vec!["alice.test"]);
        assert_eq!(cfg.legacy_accounts("localnet"), vec!["alice.test"]);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let found = rt.block_on(find_request_key(&cfg, cfg.connection("local").unwrap(), "alice.test", "drive.near")).unwrap();
        assert_eq!(found.public_key, pk);
        assert_eq!(found.kind, KeyKind::Unverified);
        std::env::remove_var("NEAR_DRIVE_NEAR_CLI_CONFIG");
        std::fs::remove_dir_all(&dir).ok();
    }
}
