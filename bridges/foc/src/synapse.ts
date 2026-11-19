import { Synapse, calibration, mainnet, type FilecoinChain, type PrepareResult } from "@filoz/synapse-sdk";
import { createPieceUrlFilBeam } from "@filoz/synapse-core/utils";
import { http, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { FocClient } from "./backend.js";

export interface SynapseConfig {
  /** "calibration" (default) or "mainnet". */
  network: "calibration" | "mainnet";
  privateKey: Hex;
  /** Optional RPC URL; default is the SDK's built-in fallback set. */
  rpcUrl?: string;
  /** FilBeam CDN on the data set (needed for /url and fast reads). */
  withCDN: boolean;
  /** Copies per piece across providers (SDK default 2). */
  copies?: number;
}

/** Real FOC client on top of @filoz/synapse-sdk 3.x (PDP warm storage + FilBeam). */
export class SynapseFocClient implements FocClient {
  readonly synapse: Synapse;
  readonly chain: FilecoinChain;
  readonly network: string;
  private readonly payer: `0x${string}`;

  constructor(private readonly cfg: SynapseConfig) {
    this.chain = cfg.network === "mainnet" ? mainnet : calibration;
    this.network = cfg.network;
    const account = privateKeyToAccount(cfg.privateKey);
    this.payer = account.address;
    this.synapse = Synapse.create({
      account,
      chain: this.chain,
      transport: cfg.rpcUrl ? http(cfg.rpcUrl) : undefined,
      withCDN: cfg.withCDN,
      // Data-set metadata namespace; keeps nstorage data sets apart from other apps on the same wallet.
      source: "nstorage",
    });
  }

  get address(): string {
    return this.payer;
  }

  async upload(data: Uint8Array, key: string) {
    const r = await this.synapse.storage.upload(data, {
      copies: this.cfg.copies,
      pieceMetadata: { nstorage: key.slice(0, 64) },
    });
    return { pieceCid: r.pieceCid.toString(), complete: r.complete, copies: r.copies.length };
  }

  download(pieceCid: string): Promise<Uint8Array> {
    return this.synapse.storage.download({ pieceCid, withCDN: this.cfg.withCDN });
  }

  cdnUrl(pieceCid: string): string | null {
    if (!this.cfg.withCDN || !this.chain.filbeam) return null;
    return createPieceUrlFilBeam({ cid: pieceCid, address: this.payer, retrievalDomain: this.chain.filbeam.retrievalDomain });
  }

  /** Quote (and optionally execute) the deposit + operator approval for `pieceSizes`. */
  prepare(pieceSizes: bigint[]): Promise<PrepareResult> {
    return this.synapse.storage.prepare({ pieceSizes });
  }
}
