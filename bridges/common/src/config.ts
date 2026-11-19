import type { PackingOptions } from "./store.js";

/** Settings shared by every bridge, from environment variables. */
export interface CommonConfig {
  host: string;
  port: number;
  token?: string;
  dataDir: string;
  maxBodyBytes: number;
  packing?: PackingOptions;
}

function int(env: NodeJS.ProcessEnv, name: string, dflt: number): number {
  const v = env[name];
  if (v === undefined || v === "") return dflt;
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`${name} must be a non-negative integer, got ${v}`);
  return n;
}

/**
 * BRIDGE_HOST (127.0.0.1), BRIDGE_PORT, BRIDGE_TOKEN, BRIDGE_DATA_DIR,
 * BRIDGE_MAX_BODY_BYTES, PACK_THRESHOLD_BYTES (0 = off), PACK_TARGET_BYTES,
 * PACK_MAX_DELAY_MS. `defaults` lets each bridge choose its own packing policy.
 */
export function commonConfigFromEnv(
  env: NodeJS.ProcessEnv,
  defaults: { port: number; dataDir: string; packThreshold: number; packTarget: number; packMaxDelayMs: number },
): CommonConfig {
  const threshold = int(env, "PACK_THRESHOLD_BYTES", defaults.packThreshold);
  return {
    host: env.BRIDGE_HOST || "127.0.0.1",
    port: int(env, "BRIDGE_PORT", defaults.port),
    token: env.BRIDGE_TOKEN || undefined,
    dataDir: env.BRIDGE_DATA_DIR || defaults.dataDir,
    maxBodyBytes: int(env, "BRIDGE_MAX_BODY_BYTES", 64 * 1024 * 1024),
    packing:
      threshold > 0
        ? {
            thresholdBytes: threshold,
            targetBytes: int(env, "PACK_TARGET_BYTES", defaults.packTarget),
            maxDelayMs: int(env, "PACK_MAX_DELAY_MS", defaults.packMaxDelayMs),
          }
        : undefined,
  };
}
