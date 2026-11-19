#!/usr/bin/env node
/**
 * nstorage blob bridge → Shelby.
 *
 *   nstorage-shelby-bridge            serve (default)
 *   nstorage-shelby-bridge selftest   put+get one object for real
 *
 * SHELBY_MODE=s3 (default; Private Beta S3 API):
 *   SHELBY_S3_ENDPOINT (https://s3.beta.shelby.xyz), SHELBY_S3_BUCKET,
 *   SHELBY_ACCESS_KEY_ID (SHLB…), SHELBY_SECRET_ACCESS_KEY, SHELBY_URL_TTL_S (3600)
 * SHELBY_MODE=sdk (native SDK, shelbynet):
 *   SHELBY_PRIVATE_KEY (Aptos ed25519), SHELBY_API_KEY
 * Common: SHELBY_PREFIX (nstorage/), BRIDGE_* / PACK_* (packing off by default).
 */
import { homedir } from "node:os";
import { join } from "node:path";
import { BridgeStore, commonConfigFromEnv, computeCid, startBridgeServer } from "@nstorage/bridge-common";
import { backendFromEnv } from "./config.js";

async function main() {
  const env = process.env;
  const cmd = process.argv[2] ?? "serve";
  const common = commonConfigFromEnv(env, {
    port: 7702,
    dataDir: join(homedir(), ".nstorage", "bridges", "shelby"),
    // Shelby bills actual bytes on the paid plan (the free plan counts each object as ≥10 MiB):
    // packing is opt-in via PACK_THRESHOLD_BYTES.
    packThreshold: 0,
    packTarget: 64 * 1024 * 1024,
    packMaxDelayMs: 60_000,
  });
  const log = (m: string) => console.error(`[shelby-bridge] ${m}`);
  const backend = await backendFromEnv(env);

  if (cmd === "selftest") {
    const data = new TextEncoder().encode(`nstorage shelby bridge selftest ${new Date().toISOString()}`);
    const cid = computeCid(data);
    const id = await backend.put(cid.slice(3), data);
    const back = await backend.get(id);
    const ok = computeCid(back) === cid;
    console.log(JSON.stringify({ backend: backend.name, id, roundtrip: ok, url: await backend.url?.(id) }, null, 2));
    process.exit(ok ? 0 : 1);
  }
  if (cmd !== "serve") throw new Error(`unknown command ${cmd}`);

  const store = new BridgeStore({ backend, dataDir: common.dataDir, packing: common.packing, log });
  const s = await startBridgeServer({ store, host: common.host, port: common.port, token: common.token, maxBodyBytes: common.maxBodyBytes, log });
  log(`listening on ${s.url} (backend ${backend.name}, data ${common.dataDir})`);
  const stop = async () => {
    await s.close();
    await store.flush().catch((e) => log(`flush failed, staged data kept on disk: ${e.message}`));
    await store.close();
    process.exit(0);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
