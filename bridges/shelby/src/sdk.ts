import { Account, Ed25519PrivateKey, Network } from "@aptos-labs/ts-sdk";
import { ShelbyNodeClient, isBlobAlreadyExistsError, isBlobNotFoundError } from "@shelby-protocol/sdk/node";
import { BackendNotFound, type BlobBackend, type BlobUrl, type ByteRange } from "@nstorage/bridge-common";

export interface ShelbySdkConfig {
  /** Aptos Ed25519 private key (hex or AIP-80 `ed25519-priv-0x…`). Needs APT (gas) + ShelbyUSD (storage). */
  privateKey: string;
  /** Shelby / Aptos API key ("AG-…"). */
  apiKey?: string;
  /** Blob name prefix (default "nstorage/"). */
  prefix?: string;
}

/**
 * Shelby through the native TypeScript SDK (@shelby-protocol/sdk 0.11, network
 * `shelbynet` — the only named network the SDK ships). Backend id = blob name
 * under the signer's account. Blob names are ≤ 190 chars; ours are ~75.
 *
 * NOTE: the SDK is published as "Proprietary" (npm license field) and pre-1.0;
 * the S3 backend is the default.
 */
export class ShelbySdkBackend implements BlobBackend {
  readonly name = "shelby-sdk";
  readonly client: ShelbyNodeClient;
  readonly signer: Account;
  private readonly prefix: string;

  constructor(cfg: ShelbySdkConfig) {
    this.prefix = cfg.prefix ?? "nstorage/";
    this.signer = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(cfg.privateKey) });
    this.client = new ShelbyNodeClient({ network: Network.SHELBYNET, apiKey: cfg.apiKey });
  }

  async put(key: string, data: Uint8Array): Promise<string> {
    const blobName = this.prefix + key;
    try {
      await this.client.upload({ blobData: data, signer: this.signer, blobName });
    } catch (e) {
      if (!isBlobAlreadyExistsError((e as Error).message ?? "")) throw e;
    }
    return blobName;
  }

  async get(blobName: string, range?: ByteRange): Promise<Uint8Array> {
    try {
      const blob = await this.client.download({
        account: this.signer.accountAddress,
        blobName,
        range: range ? { start: range.start, end: range.end } : undefined, // SDK `end` is inclusive
      });
      return new Uint8Array(await new Response(blob.readable).arrayBuffer());
    } catch (e) {
      if (isBlobNotFoundError((e as Error).message ?? "")) throw new BackendNotFound(blobName);
      throw e;
    }
  }

  async url(blobName: string): Promise<BlobUrl | null> {
    // ShelbyRPCClient read path: {rpcBase}/v1/blobs/{account}/{name}. Needs the API key
    // as a Bearer header if the RPC enforces one, so it is not a capability URL.
    const name = blobName.split("/").map(encodeURIComponent).join("/");
    return { url: `${this.client.baseUrl}/v1/blobs/${this.signer.accountAddress.toString()}/${name}`, expires_ms: null };
  }
}
