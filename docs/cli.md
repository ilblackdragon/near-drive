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
| `keygen [--ckd \| --random]` | create your encryption key: derived from the account by MPC (`--ckd`, same key on every device) or random |
| `whoami` | account, network, which key signs requests, your sharing key |
| `put <file> [path]` | upload (`-` = stdin); `--public`, `--class bulk`, `--share x25519:...`, `--no-resume` |
| `get <path> [file]` | download (to stdout without a file); `--range START-END` |
| `ls [prefix]` | list files |
| `rm <path>` | delete |
| `share <path> <account \| x25519:key>` | give someone the key to a file |
| `grant <prefix> --read .. --write .. --payer ..` | set who can read / write / pays for a folder (onchain rule) |
| `rules [account]` | show an account's rules |
| `publish-key` | publish your sharing key onchain so others can share to you by account name |
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
  `near config add-connection`); the RPC URL and the MPC contract for `keygen --ckd` come from that connection.
- `--credentials <file>` bypasses near-cli entirely (dev gateways, CI): requests and transactions are signed with that
  NEAR credentials file.

The encryption root key is not a NEAR key. It lives in `~/.near-drive/keys/<account>.root` (the TypeScript and Python
SDKs read it there). With `keygen --ckd` it can be re-derived from the account on any device
([ckd.md](ckd.md)).

## Interactive mode

In a terminal, anything missing is asked for, with the same prompts as near-cli: `near drive` alone opens a menu;
`get` lists your files to pick from; `put` suggests a destination; `grant` asks who can read, write and pay; `keygen`
asks CKD or random. Afterwards it prints the equivalent command without prompts. Without a terminal (or with
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
