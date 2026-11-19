import type { ByteRange } from "./range.js";

export interface BlobUrl {
  url: string;
  /** Unix ms when the URL stops working, or null if it does not expire. */
  expires_ms: number | null;
}

/**
 * A storage backend as seen by the bridge. Backends have their own content
 * ids (FOC PieceCID, Shelby blob name, …); the bridge keeps the mapping from
 * NEAR Drive cids in its index.
 */
export interface BlobBackend {
  readonly name: string;
  /** Stores `data`; `key` is a stable, unique name hint. Returns the backend id. */
  put(key: string, data: Uint8Array): Promise<string>;
  /**
   * Reads a stored object (optionally an inclusive byte range of it). A full
   * read may include trailing padding; the store truncates to the indexed size.
   */
  get(backendId: string, range?: ByteRange): Promise<Uint8Array>;
  /** Direct retrieval URL for a stored object, if the backend has one. */
  url?(backendId: string): Promise<BlobUrl | null>;
  close?(): Promise<void>;
}

/** Thrown by backends when an object they should have is missing. */
export class BackendNotFound extends Error {}
