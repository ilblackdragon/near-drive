import { BackendNotFound, ByteLru, sliceRange, type BlobBackend, type BlobUrl, type ByteRange } from "@nstorage/bridge-common";

/** FOC/PDP minimum piece payload (SIZE_CONSTANTS.MIN_UPLOAD_SIZE in synapse-core 0.11). */
export const FOC_MIN_UPLOAD = 127;

/** The slice of Synapse the bridge needs; `SynapseFocClient` implements it for real. */
export interface FocClient {
  readonly network: string;
  /** Uploads one piece; resolves once ≥1 copy is committed on-chain. */
  upload(data: Uint8Array, key: string): Promise<{ pieceCid: string; complete: boolean; copies: number }>;
  /** Downloads and CommP-verifies a whole piece. */
  download(pieceCid: string): Promise<Uint8Array>;
  /** FilBeam CDN URL (or null when CDN is off / unsupported on this chain). */
  cdnUrl(pieceCid: string): string | null;
}

export interface FocBackendOptions {
  /** Bytes of recently downloaded pieces to keep (FOC has no ranged download API). */
  cacheBytes?: number;
  /** Try `Range:` against the CDN URL before falling back to a full download. */
  rangeViaCdn?: boolean;
  fetch?: typeof fetch;
  log?: (m: string) => void;
}

/**
 * Backend id = PieceCID string (bafkzcib…). Pieces must be ≥ 127 bytes, so
 * shorter payloads are zero-padded; the bridge index records the true size
 * and every read is sliced to it.
 */
export class FocBackend implements BlobBackend {
  readonly name = "foc";
  private readonly cache: ByteLru;
  private readonly fetchFn: typeof fetch;
  private readonly log: (m: string) => void;

  constructor(
    private readonly client: FocClient,
    private readonly opts: FocBackendOptions = {},
  ) {
    this.cache = new ByteLru(opts.cacheBytes ?? 256 * 1024 * 1024);
    this.fetchFn = opts.fetch ?? fetch;
    this.log = opts.log ?? (() => {});
  }

  async put(key: string, data: Uint8Array): Promise<string> {
    let payload = data;
    if (payload.length < FOC_MIN_UPLOAD) {
      payload = new Uint8Array(FOC_MIN_UPLOAD);
      payload.set(data);
    }
    const r = await this.client.upload(payload, key);
    if (!r.complete) this.log(`piece ${r.pieceCid} for ${key}: only ${r.copies} copies committed`);
    return r.pieceCid;
  }

  async get(pieceCid: string, range?: ByteRange): Promise<Uint8Array> {
    const cached = this.cache.get(pieceCid);
    if (cached) return checkedSlice(cached, range, pieceCid);
    const url = this.client.cdnUrl(pieceCid);
    if (range && url && this.opts.rangeViaCdn !== false) {
      try {
        const res = await this.fetchFn(url, { headers: { range: `bytes=${range.start}-${range.end}` } });
        if (res.status === 206) {
          const b = new Uint8Array(await res.arrayBuffer());
          if (b.length === range.end - range.start + 1) return b;
        } else {
          await res.body?.cancel();
        }
      } catch (e) {
        this.log(`CDN range read of ${pieceCid} failed, falling back to full download: ${(e as Error).message}`);
      }
    }
    let piece: Uint8Array;
    try {
      piece = await this.client.download(pieceCid);
    } catch (e) {
      if (/not found|no provider/i.test((e as Error).message)) throw new BackendNotFound(pieceCid);
      throw e;
    }
    this.cache.set(pieceCid, piece);
    return checkedSlice(piece, range, pieceCid);
  }

  async url(pieceCid: string): Promise<BlobUrl | null> {
    const u = this.client.cdnUrl(pieceCid);
    return u ? { url: u, expires_ms: null } : null;
  }
}

function checkedSlice(piece: Uint8Array, range: ByteRange | undefined, id: string): Uint8Array {
  if (range && range.end >= piece.length) throw new Error(`range ${range.start}-${range.end} beyond piece ${id} (${piece.length} B)`);
  return sliceRange(piece, range);
}
