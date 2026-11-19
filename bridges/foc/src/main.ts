#!/usr/bin/env node
/**
 * nstorage blob bridge → Filecoin Onchain Cloud (PDP warm storage + FilBeam).
 *
 *   nstorage-foc-bridge            serve (default)
 *   nstorage-foc-bridge setup      quote deposit/approval; `setup --yes` executes it
 *   nstorage-foc-bridge selftest   upload+download one packed object for real
 *
 * Env: FOC_PRIVATE_KEY (0x…, required), FOC_NETWORK=calibration|mainnet
 * (default calibration; mainnet also needs FOC_ALLOW_MAINNET=1), FOC_RPC_URL,
 * FOC_WITH_CDN=1|0 (default 1), FOC_COPIES, FOC_CACHE_BYTES, plus the common
 * BRIDGE_* / PACK_* variables (see docs/backends.md).
 */
import { homedir } from "node:os";
import { join } from "node:path";
import { BridgeStore, commonConfigFromEnv, computeCid, startBridgeServer } from "@nstorage/bridge-common";
import { FocBackend } from "./backend.js";
import { SynapseFocClient } from "./synapse.js";

const MiB = 1024 * 1024;

function synapseFromEnv(env: NodeJS.ProcessEnv): SynapseFocClient {
  const pk = env.FOC_PRIVATE_KEY;
  if (!pk || !/^0x[0-9a-fA-F]{64}$/.test(pk)) throw new Error("FOC_PRIVATE_KEY (0x + 64 hex) is required");
  const network = (env.FOC_NETWORK || "calibration") as "calibration" | "mainnet";
  if (network !== "calibration" && network !== "mainnet") throw new Error(`FOC_NETWORK must be calibration or mainnet`);
  if (network === "mainnet" && env.FOC_ALLOW_MAINNET !== "1") {
    throw new Error("FOC_NETWORK=mainnet spends real USDFC/FIL; set FOC_ALLOW_MAINNET=1 to confirm");
  }
  return new SynapseFocClient({
    network,
    privateKey: pk as `0x${string}`,
    rpcUrl: env.FOC_RPC_URL || undefined,
    withCDN: env.FOC_WITH_CDN !== "0",
    copies: env.FOC_COPIES ? Number(env.FOC_COPIES) : undefined,
  });
}

const bigintJson = (v: unknown) => JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x), 2);

async function main() {
  const env = process.env;
  const cmd = process.argv[2] ?? "serve";
  const common = commonConfigFromEnv(env, {
    port: 7701,
    dataDir: join(homedir(), ".nstorage", "bridges", "foc"),
    // Every FOC piece costs a fixed on-chain fee (≈$0.011 per single-piece add, per copy),
    // so pack everything below 16 MiB into ~64 MiB pieces.
    packThreshold: 16 * MiB,
    packTarget: 64 * MiB,
    packMaxDelayMs: 10 * 60_000,
  });
  const client = synapseFromEnv(env);
  const log = (m: string) => console.error(`[foc-bridge] ${m}`);

  if (cmd === "setup") {
    const target = BigInt(common.packing?.targetBytes ?? 64 * MiB);
    const r = await client.prepare([target]);
    console.log(bigintJson({ network: client.network, payer: client.address, costs: r.costs, deposit: r.transaction?.depositAmount ?? 0n }));
    if (!r.transaction) return console.log("account is already funded and approved");
    if (process.argv[3] !== "--yes") return console.log("re-run with `setup --yes` to deposit + approve");
    const tx = await r.transaction.execute({ onHash: (h) => log(`tx ${h}`) });
    console.log(`done: ${tx.hash}`);
    return;
  }

  const backend = new FocBackend(client, { cacheBytes: Number(env.FOC_CACHE_BYTES || 256 * MiB), log });

  if (cmd === "selftest") {
    const data = new TextEncoder().encode(`nstorage foc bridge selftest ${new Date().toISOString()} `.repeat(8));
    const id = await backend.put(computeCid(data).slice(3), data);
    const back = await backend.get(id);
    const ok = computeCid(back.subarray(0, data.length)) === computeCid(data);
    console.log(bigintJson({ pieceCid: id, size: data.length, roundtrip: ok, url: await backend.url(id) }));
    process.exit(ok ? 0 : 1);
  }

  if (cmd !== "serve") throw new Error(`unknown command ${cmd}`);
  const store = new BridgeStore({ backend, dataDir: common.dataDir, packing: common.packing, log });
  const s = await startBridgeServer({ store, host: common.host, port: common.port, token: common.token, maxBodyBytes: common.maxBodyBytes, log });
  log(`listening on ${s.url} (network ${client.network}, payer ${client.address}, data ${common.dataDir})`);
  const stop = async () => {
    log("shutting down; flushing staged blobs");
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
