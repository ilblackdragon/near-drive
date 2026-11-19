/** Node-only helpers: NEAR credential files, local root keys, file upload/download. */
import { readFile, writeFile, mkdir, open } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { Client, type ClientOptions, type PutOptions } from "./client.js";
import { RootKey } from "./crypto.js";
import { parseSecretKey, publicKeyOf } from "./keys.js";
import type { PointerRecord } from "./record.js";
import type { NearUri } from "./uri.js";

export interface NearCredentials {
  account_id: string;
  public_key: string;
  private_key: string;
}

/** Load `~/.near-credentials/<network>/<account>.json` (or any file in that format). */
export async function loadCredentials(path: string): Promise<NearCredentials> {
  const c = JSON.parse(await readFile(path, "utf8")) as NearCredentials;
  if (publicKeyOf(parseSecretKey(c.private_key)) !== c.public_key) throw new Error("credentials file public_key does not match private_key");
  return c;
}

export function defaultCredentialsPath(account: string, network = "mainnet"): string {
  return join(homedir(), ".near-credentials", network, `${account}.json`);
}

/** Where `nst keygen` keeps root keys: `$NSTORAGE_HOME/keys/<account>.root` (default `~/.nstorage`). */
export function defaultRootKeyPath(account: string, home = process.env.NSTORAGE_HOME ?? join(homedir(), ".nstorage")): string {
  return join(home, "keys", `${account}.root`);
}

export async function loadRootKey(path: string): Promise<RootKey | undefined> {
  try {
    return RootKey.fromHex(await readFile(path, "utf8"));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw e;
  }
}

/** Create a new root key file (mode 0600); refuses to overwrite. */
export async function generateRootKeyFile(path: string): Promise<RootKey> {
  const k = RootKey.generate();
  await mkdir(dirname(path), { recursive: true });
  const f = await open(path, "wx", 0o600);
  try {
    await f.writeFile(k.toHex());
  } finally {
    await f.close();
  }
  return k;
}

/** Client from a credentials file plus the account's local root key (if any), like `nst`. */
export async function clientFromFiles(o: { gateway: string; credentials: string; rootKey?: string; chunkSize?: number }): Promise<Client> {
  const c = await loadCredentials(o.credentials);
  const root = await loadRootKey(o.rootKey ?? defaultRootKeyPath(c.account_id));
  const opts: ClientOptions = { gateway: o.gateway, accountId: c.account_id, signer: c.private_key, rootKey: root, chunkSize: o.chunkSize };
  return new Client(opts);
}

export async function putFile(client: Client, src: string, uri: string | NearUri, opts?: PutOptions): Promise<PointerRecord> {
  return client.put(uri, new Uint8Array(await readFile(src)), opts);
}

export async function getFile(client: Client, uri: string | NearUri, dst: string): Promise<void> {
  await writeFile(dst, await client.get(uri));
}
