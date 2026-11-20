# CLI reference: `near drive` / `near-drive`

One binary, two ways to run it:

- `near drive <command>` once `near-drive` is on `PATH`. near-cli-rs runs `near-<name>` for subcommands it does not
  know (like `cargo`). `near storage` is taken: near-cli keeps it as a legacy alias of `view-state`.
- `near-drive <command>` standalone.

Run `near drive --help` or `near drive <command> --help` for every flag.

## Commands

| command | what it does |
|---|---|
| `login` / `logout` | add / delete a NEAR Drive session key (a function-call key for the drive contract) via near-cli |
| `keygen --ckd \| --random` | create your encryption key: derived from the account by MPC (`--ckd`, recommended: same key on every device) or random (back it up). Without a terminal one of the two is required. Refuses a key that does not match the keys already published for the account unless `--force` |
| `key export [--out FILE]` | print your root key (hex), or write it to `FILE` (mode 0600, never overwritten). Anyone with it can read your private files |
| `key import <HEX \| - \| --file FILE> [--force]` | install a root key from a backup; checked against the published keys first. Refuses to replace a different existing key without `--force` |
| `whoami` | account, network, which key signs requests, your sharing key |
| `put <file> [path]` | upload (`-` = stdin); `--public`, `--class bulk`, `--share x25519:...`, `--no-resume` |
| `get <path> [file]` | download (to stdout without a file); `--range START-END` |
| `ls [prefix]` | list files under the prefix, recursively; `--dir` lists one level (files plus subfolders ending in `/`) |
| `rm <path>` | delete |
| `share <path> <account \| x25519:key>` | give someone the key to a file |
| `grant <prefix> --read .. --write .. --payer ..` | set who can read / write / pays for a folder (onchain rule) |
| `rules [account]` | show an account's rules |
| `publish-key` | publish your sharing key (so others can share to you by account name) and your record-signing key (readers reject what you write until it is published) onchain |
| `sync add/remove/status/run/exclude/include` | keep local folders in sync, selectively ([sync.md](sync.md)) |
| `mount <folder> [remote]` | files on demand: everything listed, downloaded when opened ([mount.md](mount.md)) |
| `up` / `down` | start / stop the background service: synced folders + local S3 endpoint ([s3.md](s3.md)) |
| `s3-proxy` | the S3 endpoint in the foreground (containers, systemd) |
| `gateways` | gateways registered onchain |

## Paths

`near://<account>/<path>` addresses a file. Paths without `near://` are in your own account:

```sh
near drive put notes.txt              # -> near://<you>/notes.txt
near drive put notes.txt docs/        # -> near://<you>/docs/notes.txt (a folder keeps the file name)
near drive get docs/notes.txt
near drive get near://bob.near/shared/report.pdf report.pdf
```

## NEAR keys come from near-cli

NEAR Drive never creates or stores NEAR keys itself.

- **Signing requests.** Requests to the gateway are signed with a key from near-cli's keychain: the OS keychain
  entries `near` writes (`near-<network>-<account>` / `<account>:<public key>`) or the legacy files under
  `~/.near-credentials/<network>/`. The CLI lists the account's keys onchain and prefers a function-call key for the
  drive contract, then a full-access key. `near drive whoami` shows which one and where it came from.
- **Session key.** `near drive login` runs `near account add-key <account> grant-function-call-access
  --contract-account-id drive.near ... autogenerate-new-keypair save-to-keychain`: near-cli generates the key, stores
  it, and signs the `AddKey` with the signer you choose (keychain, Ledger, seed phrase, ...). `logout` deletes it.
- **Transactions** (`grant`, `publish-key`, `keygen --ckd`, `login`, `logout`) are sent by
  `near contract call-function as-transaction ...`, so near-cli asks for the signer. Without a terminal it uses
  `sign-with-keychain send`; override with `--near-sign "sign-with-ledger send"` (or `NEAR_DRIVE_NEAR_SIGN`).
  Onchain writes attach a NEAR deposit for storage staking (excess refunded), so they need a full-access key or a
  Ledger; the session key cannot sign them.
- **Networks.** `--network` is a near-cli connection name (`mainnet`, `testnet`, or your own from
  `near config add-connection`); the RPC URL comes from that connection. Its `mpc_contract_account_id` must match
  NEAR Drive's pinned MPC contract for `keygen --ckd` (see below).
- `--credentials <file>` bypasses near-cli entirely (dev gateways, CI): requests and transactions are signed with that
  NEAR credentials file. Both formats work: `{"account_id", "public_key", "private_key"}`, and near-cli-rs's per-key
  files without `account_id` (the account is then `--account`, else the file or folder name). Transaction hashes are
  printed.
- Reads check every record's writer against the signing keys and rules in the drive contract (on the connection's
  RPC). Against a dev gateway with made-up accounts there is nothing to check against:
  `--insecure-skip-writer-check` (`NEAR_DRIVE_INSECURE_SKIP_WRITER_CHECK=1`) turns the check off, and lets that
  gateway forge any file you read. Dev and tests only.

## The encryption root key

The encryption root key is not a NEAR key. It lives in `~/.near-drive/keys/<account>.root` (mode 0600; the TypeScript
and Python SDKs read it there), or comes from `NEAR_DRIVE_ROOT_KEY` (hex) in services. Everything private is encrypted
to it, and your records are signed with a key derived from it, so a lost or mismatched root key means unreadable data
*and* records other readers reject.

- `keygen --ckd` derives it from the account with NEAR's MPC network: any device can derive it again ([ckd.md](ckd.md)).
  The MPC contract and CKD domain are pinned (`v1.signer` on mainnet, `v1.signer-prod.testnet` on testnet, domain 2),
  because another contract or domain derives a different key. A different `--ckd-contract` / `--ckd-domain`, or a
  near-cli connection whose `mpc_contract_account_id` points elsewhere, is refused unless `--ckd-unpinned`. Other
  networks (sandbox, localnet) have no pin: give both `--ckd-contract` and `--ckd-domain`.
- `keygen --random` creates a key that exists only on this machine. Back it up: `near drive key export --out <file>`,
  and on another device `near drive key import --file <file>`.
- **Published-key check.** `publish-key` stores the root key's public keys (X25519 for sharing, ed25519 for records)
  in the drive contract. `keygen` and `key import` compare a key with them before saving, and refuse one from a
  different root key (your existing data and records were made with that one); use `key import` with the right key,
  or `--force` and then `publish-key` to rotate (data encrypted to the old key stays unreadable to the new one).
  Commands that write (`put`, `rm`, `share`, `sync`, `mount`, `up`, `s3-proxy`) do the same check once with the cached
  or `NEAR_DRIVE_ROOT_KEY` key: a mismatch stops them before writing; keys not published yet only warn (run
  `publish-key`: until then others reject your records). With `--insecure-skip-writer-check` or no drive contract at
  the RPC, the check is skipped.

## Interactive mode

In a terminal, anything missing is asked for, with the same prompts as near-cli: `near drive` alone opens a menu;
`get` lists your files to pick from; `put` suggests a destination; `grant` asks who can read, write and pay; `keygen`
asks CKD or random; `key` offers export and import. Afterwards it prints the equivalent command without prompts. Without a terminal (or with
`--no-interactive`) missing arguments are errors.

## Sharing and access rules

```sh
# an app pays for its users' data; each user reads and writes only their own folder
near drive --account app.near grant 'near://app.near/users/{account}/' --read '{account}' --write '{account},app.near' --payer app.near
near drive rules app.near

# share by account name: bob publishes his key once, alice shares
near drive --account bob.near publish-key
near drive --account alice.near share near://alice.near/doc/x bob.near
```

`{account}` in a rule matches any account name in that path segment. Sharing gives the recipient the file's key;
the rules decide whether the gateway lets them read it.

## Large files

Uploads and downloads stream with bounded memory and transfer chunks in parallel:

```sh
near drive --chunk-mib 16 --parallel 16 put --class bulk model.safetensors models/m.safetensors
near drive get models/m.safetensors ./m.safetensors
near drive get --range 0-1048575 models/m.safetensors > header.bin
```

## Bad networks

- Every request has a timeout that grows with its size and is retried on transient failures (dropped connections,
  timeouts, 5xx, 429) with backoff, 8 attempts by default (`--retries` / `NEAR_DRIVE_RETRIES`).
- **Interrupted downloads resume:** the partial `<file>.drive-part` is kept; running the same `get` again checks the
  chunks already on disk and fetches only the rest.
- **Interrupted uploads resume:** running the same `put` again skips chunks the gateway already has (journal in
  `~/.near-drive/uploads`). If the file changed meanwhile, the upload starts over. `--no-resume` turns this off.
- A lost response never turns a successful write into an error or a duplicate version.

## Configuration

| flag | env | default |
|---|---|---|
| `--account` | `NEAR_DRIVE_ACCOUNT` | asked |
| `--network` | `NEAR_DRIVE_NETWORK` | `mainnet` |
| `--gateway` (`auto` = pick from the onchain registry) | `NEAR_DRIVE_GATEWAY` | `http://127.0.0.1:8787` |
| `--contract` | `NEAR_DRIVE_CONTRACT` | `drive.near` |
| `--home` | `NEAR_DRIVE_HOME` | `~/.near-drive` |
| `--parallel`, `--chunk-mib`, `--retries` | `NEAR_DRIVE_PARALLEL`, `NEAR_DRIVE_CHUNK_MIB`, `NEAR_DRIVE_RETRIES` | 8, 4, 8 |
| `--near-bin`, `--near-sign` | `NEAR_DRIVE_NEAR_BIN`, `NEAR_DRIVE_NEAR_SIGN` | `near`, asked |
| `--credentials` | `NEAR_DRIVE_CREDENTIALS` | near-cli keys |
| (root key) | `NEAR_DRIVE_ROOT_KEY` | `~/.near-drive/keys/<account>.root` |
