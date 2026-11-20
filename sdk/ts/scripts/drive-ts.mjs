#!/usr/bin/env node
// Minimal `near-drive`-compatible CLI on top of the TS SDK (same env vars and key files).
// Used by testvectors/interop.sh. Usage: node scripts/drive-ts.mjs <cmd> [args]   (after `npm run build`)
// Reads check record writers against drive.near via NEAR_DRIVE_RPC_URL (+ NEAR_DRIVE_CONTRACT, default
// drive.near); NEAR_DRIVE_INSECURE_SKIP_WRITER_CHECK=1 disables that (local dev gateways / interop tests only).
//   whoami | put <src|-> <uri> [--public] [--content-type T] [--share x25519:..]... | get <uri> [dst] | ls <uri> | rm <uri> | share <uri> <recipient>
import { readFileSync, writeFileSync } from "node:fs";
import { WriterCheck } from "../dist/index.js";
import { clientFromFiles, defaultCredentialsPath, defaultRootKeyPath } from "../dist/node.js";

const env = process.env;
const account = env.NEAR_DRIVE_ACCOUNT;
if (!account) throw new Error("NEAR_DRIVE_ACCOUNT is required");
const [cmd, ...args] = process.argv.slice(2);
const flags = { share: [] };
const pos = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--public") flags.public = true;
  else if (args[i] === "--content-type") flags.contentType = args[++i];
  else if (args[i] === "--share") flags.share.push(args[++i]);
  else pos.push(args[i]);
}
process.on("unhandledRejection", (e) => {
  console.error(`Error: ${e?.message ?? e}`);
  process.exit(1);
});
const c = await clientFromFiles({
  gateway: env.NEAR_DRIVE_GATEWAY ?? "http://127.0.0.1:8787",
  credentials: env.NEAR_DRIVE_CREDENTIALS ?? defaultCredentialsPath(account, env.NEAR_DRIVE_NETWORK ?? env.NEAR_NETWORK ?? "mainnet"),
  rootKey: defaultRootKeyPath(account),
  rpcUrl: env.NEAR_DRIVE_RPC_URL,
  contractId: env.NEAR_DRIVE_CONTRACT,
  writerCheck: env.NEAR_DRIVE_INSECURE_SKIP_WRITER_CHECK === "1" ? WriterCheck.insecureSkipWriterCheck() : undefined,
});
if (c.accountId !== account) throw new Error(`credentials are for ${c.accountId}, not ${account}`);
switch (cmd) {
  case "whoami":
    console.log(`account: ${c.accountId}`);
    console.log(`x25519:  ${c.x25519Public() ?? "(no root key)"}`);
    console.log(`sign:    ${c.signPublicKey() ?? "(no root key)"}`);
    break;
  case "put": {
    const data = pos[0] === "-" ? readFileSync(0) : readFileSync(pos[0]);
    const r = await c.put(pos[1], new Uint8Array(data), { public: flags.public, contentType: flags.contentType, shareWith: flags.share });
    console.error(`${pos[1]} seq=${r.seq} size=${r.size} stored=${r.stored_size}`);
    break;
  }
  case "get": {
    const d = await c.get(pos[0]);
    if (pos[1]) writeFileSync(pos[1], d);
    else process.stdout.write(d);
    break;
  }
  case "ls":
    for (const e of await c.list(pos[0])) console.log(`${String(e.size).padStart(12)}  seq=${String(e.seq).padEnd(4)} ${e.writer.padEnd(24)} ${e.path}`);
    break;
  case "rm":
    await c.delete(pos[0]);
    break;
  case "share":
    console.error(`shared; seq=${(await c.share(pos[0], pos[1])).seq}`);
    break;
  default:
    throw new Error(`unknown command ${cmd}`);
}
