import type { BlobBackend } from "@near-drive/bridge-common";
import { ShelbyS3Backend } from "./s3.js";

function need(env: NodeJS.ProcessEnv, k: string): string {
  const v = env[k];
  if (!v) throw new Error(`${k} is required`);
  return v;
}

/** Builds the Shelby backend selected by SHELBY_MODE (see main.ts for variables). */
export async function backendFromEnv(env: NodeJS.ProcessEnv): Promise<BlobBackend> {
  const mode = env.SHELBY_MODE || "s3";
  const prefix = env.SHELBY_PREFIX ?? "near-drive/";
  if (mode === "s3") {
    return new ShelbyS3Backend({
      endpoint: env.SHELBY_S3_ENDPOINT || "https://s3.beta.shelby.xyz",
      bucket: need(env, "SHELBY_S3_BUCKET"),
      accessKeyId: need(env, "SHELBY_ACCESS_KEY_ID"),
      secretAccessKey: need(env, "SHELBY_SECRET_ACCESS_KEY"),
      prefix,
      urlTtlSeconds: env.SHELBY_URL_TTL_S ? Number(env.SHELBY_URL_TTL_S) : undefined,
    });
  }
  if (mode === "sdk") {
    // Loaded lazily: the SDK is large, proprietary-licensed and only needed in this mode.
    const { ShelbySdkBackend } = await import("./sdk.js");
    return new ShelbySdkBackend({ privateKey: need(env, "SHELBY_PRIVATE_KEY"), apiKey: env.SHELBY_API_KEY, prefix });
  }
  throw new Error(`SHELBY_MODE must be s3 or sdk, got ${mode}`);
}
