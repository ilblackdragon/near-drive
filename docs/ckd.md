# Root keys via NEAR MPC Confidential Key Derivation (CKD)

Status: implemented in `crates/near-drive-ckd` and `near drive keygen --ckd`. Verified by unit tests against the reference vectors, an end-to-end test against a mock RPC/MPC, and **real testnet transactions** (2026-11-20; see "Verification status"): the key is deterministic per account, and different accounts get different keys. Research date: 2026-11-19, near/mpc at commit `483e9ff`, contract version `3.19.0` on both networks.

## Findings

| Question | Answer | Confidence |
|---|---|---|
| Contract | mainnet `v1.signer`, testnet `v1.signer-prod.testnet` | high: contract README and live `version` view = `3.19.0` |
| Method | `request_app_private_key(request: CKDRequestArgs)`, `#[payable]` | high: `crates/contract/src/api/ckd.rs` |
| Args | `{"request": {"derivation_path": String, "app_public_key": <G1> \| {"AppPublicKey": <G1>} \| {"AppPublicKeyPV": {"pk1": <G1>, "pk2": <G2>}}, "domain_id": u64}}`. `<G1>` = `"bls12381g1:" + base58(48-byte compressed)`, `<G2>` = `"bls12381g2:" + base58(96 bytes)` | high: interface crate plus its serde tests |
| CKD domains | `2` and `6` on both networks (`purpose: CKD`, `protocol: ConfidentialKeyDerivation`, threshold 11). The near/mpc docs use 2, so NEAR Drive pins 2. Why a second CKD domain (6) exists is not documented in the repo. A request on domain 6 works and returns a *different* key (verified on testnet), so the domain is pinned, not a default | high for the facts (live `state` view, testnet requests); the reason for domain 6 is unknown |
| Domain public key | view `public_key {"domain_id": 2}` returns `bls12381g2:...` | high: live view, checked by `tests/live_readonly.rs` |
| Return value | `CKDResponse {"big_y": <G1>, "big_c": <G1>}` as the tx's final `SuccessValue`. The response arrives through yield/resume after the MPC network answers (`respond_ckd`), a few blocks later. If the network doesn't answer before the yield times out, the tx fails (`fail_on_timeout`) | high: contract code |
| Deposit | ≥ 1 yoctoNEAR; any excess is refunded. The deposit's purpose is to force a full-access key (or a function-call key with an explicit allowance), because function-call keys can't attach deposits | high: contract README "Deposit requirement" |
| Gas | The contract requires at least `ckd_call_gas_attachment_requirement_tera_gas` attached: **15 TGas** on both networks per the live `config` view (README says 10, which is outdated). Measured on testnet: `request_app_private_key` burns ~12.0 TGas and the resume ~4.1 TGas, **16.6 TGas in total** including the transaction itself, i.e. **0.00164 NEAR per request**. `near-drive` attaches 50 TGas and the unused part is refunded | high: config view and real transactions |
| Latency | The response lands ~6 blocks (~3 s) after the transaction is included; 5–8 s wall-clock end to end | measured on testnet (3 requests) |
| Can a plain user account call it? | **Yes.** The contract does no TEE or attestation check on the caller. It only checks the domain purpose, gas and deposit, and takes `env::predecessor_account_id()`. The TEE "developer contract" flow in the docs is a pattern the app builds on top; the MPC contract does not enforce it. ckd-example-cli uses a plain account (`frodo.test.near`) | high: `check_request_preconditions` in `api/common.rs`; `ckd-example-cli/README.md` |
| Key binding | `app_id = sha3_256("near-mpc v0.1.0 app_id derivation:" ‖ predecessor ‖ "," ‖ derivation_path)`, and the key is `sig = msk_domain · H(pk ‖ app_id)` on G1. It is deterministic per (domain master key, predecessor, path). `app_public_key` does not affect it | high: `near-mpc-crypto-types/src/kdf.rs` plus contract doc comment; our test reproduces the upstream app_id snapshot |
| Encryption / decryption | ElGamal on G1: `(Y, C) = (y·G1, sig + y·A1)`; the client computes `sig = C − a·Y` | high: threshold-signatures CKD doc plus ckd-example-cli |
| Verification | BLS check `e(H(pk‖app_id), pk) == e(sig, G2)`, where `H` = RFC 9380 hash_to_curve G1, DST `NEAR BLS12381G1_XMD:SHA-256_SSWU_RO_`, input `pk_compressed(96) ‖ app_id(32)`. With `AppPublicKeyPV` the **contract** also checks `e(A1,G2)=e(G1,A2)` on the request and checks the encrypted output on `respond_ckd`. Corrupt responses are therefore rejected on-chain, and the client still checks locally | high: code plus reference vectors |
| Final key | The protocol leaves HKDF salt/info to the app. NEAR Drive uses `root = HKDF-SHA256(salt="near-drive", ikm=sig_compressed(48), info="near-drive/v1/root-from-ckd")` with derivation path `near-drive/v1/root` | our choice |

## Implementation

- `near_drive_ckd`, the pure crypto layer:
  - `derive_app_id` computes the app_id;
  - `EphemeralKey::generate` creates a fresh scalar `a`;
  - `CkdRequestArgs::new` builds the request, using the PV variant;
  - `decrypt_and_verify` decrypts and checks the response;
  - `root_key_from_ckd_secret` and `root_key_from_response` turn it into a `RootKey`.
- It uses `blstrs 0.7.1` with `group`/`ff`/`pairing`, the same stack near/mpc uses. We don't depend on the `threshold-signatures` crate because it isn't published and pulls in the whole MPC stack.
- `near_drive_ckd::resolve_target` pins the MPC contract and domain: `v1.signer` (mainnet) /
  `v1.signer-prod.testnet` (testnet), domain 2. A different `--ckd-contract` or `--ckd-domain`, or a near-cli connection
  whose `mpc_contract_account_id` (user-editable) points elsewhere, is refused unless `--ckd-unpinned`, because each
  derives a different root key. Custom networks (sandbox, localnet) have no pin and need both flags.
- `near_drive_ckd::near::request_root_key(&CkdNetwork, &Signer, path)` sends the transaction:
  1. view `public_key` to get the domain pk;
  2. `view_access_key` to get the nonce, refusing function-call keys because they can't attach the deposit;
  3. fetch the final block hash;
  4. build and sign a borsh FunctionCall transaction by hand;
  5. print the tx hash, call `send_tx(wait_until=EXECUTED_OPTIMISTIC)`, then poll `tx` (10 s per call) until it has a
     status (deadline 120 s; the yield/resume makes `send_tx` time out often). INVALID_TRANSACTION stops at once. If the
     node does not know the tx (UNKNOWN_TRANSACTION: dropped before inclusion), the same signed bytes are sent again
     (same hash, so it cannot execute twice). A timeout names the hash and the first `send_tx` error;
  6. decode `SuccessValue`, then decrypt and verify.

  The borsh bytes are checked byte-for-byte against `@near-js/transactions`.
- `near drive keygen --ckd [--network testnet] [--ckd-contract C --ckd-domain N [--ckd-unpinned]]` sends the request
  through near-cli (`near contract call-function as-transaction <mpc> request_app_private_key ...`; near-cli asks for
  the signer, prints the transaction ID on stderr and the `CKDResponse` on stdout), then decrypts and verifies it
  locally. The RPC comes from the near-cli connection. With `--credentials <file>` it uses the hand-built transaction
  above instead. Before saving, the key is compared with the keys already published for the account (`get_enc_key`,
  `get_sign_keys`); a mismatch is refused unless `--force`. It is written to the same
  `~/.near-drive/keys/<account>.root` cache as a random key, so nothing downstream changes. Running it again on another
  device recovers the same key.

## Caveats

- **The key belongs to the account id, not to its keys.**
  - Rotating access keys keeps the key, which is the point of CKD.
  - Anyone who controls the account, or any full-access key on it, can get the root key. A leaked full-access key therefore also leaks all encrypted NEAR Drive data, past and future. Function-call "storage session keys" **cannot** get it, because of the 1 yocto deposit. That is the intended split.
- **Account deletion and re-creation.** NEAR account ids can be re-registered after deletion: named sub-accounts by the parent, top-level names by whoever gets them, implicit accounts by whoever holds the key. The new owner gets the **same** root key and can decrypt the old owner's data if they can fetch the ciphertext. Users who delete an account should treat their NEAR Drive data as exposed to the next owner of that id. A future mitigation is to mix a per-account salt into the derivation path, published once in `drive.near`, at the cost of one extra lookup.
- **Contracts and multisig accounts** can get keys too, since the predecessor is whatever calls the contract. A contract that forwards calls for arbitrary users would get *its own* key, not theirs.
- **Trust model.** Secrecy depends on fewer than `threshold` (11) MPC nodes colluding. The nodes run in TEEs, but a threshold collusion could compute every derived key, including past ones. Unlike signing, a compromise is retroactive for confidentiality.
- **Key-set lifetime.** The key is tied to the domain's master secret. Resharing (participant changes) keeps `msk` and `pk`, so keys stay stable. If the network ever generated a new CKD domain key and retired domain 2, every root key would change. Users would have to re-derive the old key before retirement and re-wrap their KEK-wrapped DEKs. Pin `domain_id` and watch the `state`.
- **Cost per call.** 1 yoctoNEAR plus the gas burnt: 16.6 TGas = 0.00164 NEAR per request (measured on testnet). It is cheap, but it is a transaction: run it once per device and cache the result locally. The cache is a plaintext file with mode 0600, as for a random key. An OS keychain or passphrase wrapping is a TODO.
- **Latency and liveness.** It needs the MPC network to be up. Measured: the answer lands ~6 blocks (~3 s) after inclusion, 5–8 s end to end. A request can fail by timeout; check the printed tx hash, then retry with a new ephemeral key.
- **Privacy.** The request, including the account id and path, is public on-chain, so observers learn that an account uses NEAR Drive. The derived key does not leak, because only `a` can decrypt `(Y, C)`.

## Verification status

- **Verified (unit tests):**
  - app_id matches upstream snapshot vectors;
  - full decrypt and verify matches all 4 upstream CKD test vectors (`pk`, `app_pk1/2`, `hash_point`, `sig`, and `s` with the reference HKDF);
  - tampering, a wrong ephemeral key, a wrong account, a wrong path and a wrong MPC pk are all rejected;
  - the identity output is rejected;
  - the borsh tx encoding equals `@near-js/transactions`;
  - an end-to-end mock RPC test checks the signature, deposit, gas and pairing check on the request, simulates the yield timeout and `tx` poll, and gets the same key twice from different ephemeral keys.
- **Verified live, read-only:** `cargo test -p near-drive-ckd -- --ignored` reads `state`/`public_key` on mainnet and testnet and checks that domain 2 is CKD and its key is a valid G2 point.
- **Verified live, real transactions (testnet, signer contract 3.19.0, 2026-11-20):** all succeeded; the same account
  got the same key from separate requests, different accounts got different keys, and domain 6 gave a different key
  than domain 2. Gas, cost and latency above are from these:
  - `FEvhiEcAA9UAzuhTBSH8HtPnGuwdk2UNztfi2Ub3Mzg`
  - `DcUrEyhg13kZKaNBM4gxZ77zd3EhYcg5BHNaTdxZAFzW`
  - `CMLJZQXbFoCwwiyNGtZWQqFCnAAGAQURzeytVNuEmuNo`

  Function-call (session) keys cannot make the request (the deposit): with `--credentials`, `near-drive` refuses such
  a key before sending; through near-cli, pick a full-access key or Ledger as the signer. Not
  verified: mainnet.

## Sources

- near/mpc contract: `crates/contract/src/api/ckd.rs`, `api/common.rs`, `config.rs`, `README.md` ("Live deployments", "Deposit requirement", "Submitting a confidential key derivation (ckd) request") — https://github.com/near/mpc
- Interface types: `crates/near-mpc-contract-interface/src/types/ckd.rs`, `crates/near-mpc-crypto-types/src/kdf.rs` (+ snapshot)
- Math: `crates/threshold-signatures/docs/confidential_key_derivation/confidential-key-derivation.md`, `src/confidential_key_derivation.rs`, `tests/vectors/ckd_test_vectors.json` (vendored at `crates/near-drive-ckd/tests/vectors/`, MIT). In 2026, near/threshold-signatures lives inside near/mpc under `crates/threshold-signatures`; the standalone repo URL returns 404.
- Client reference: `crates/ckd-example-cli` (README and `src/ckd.rs`)
- Blog: https://blog.nearone.org/research/2026/02/23/mpc-ckd.html (TEE-app framing; t-of-n collusion model; it still lists public verifiability as "planned", but it has since shipped in the contract)
- Live views (2026-11-19): `v1.signer` / `v1.signer-prod.testnet`: `state`, `config`, `public_key`, `version`
