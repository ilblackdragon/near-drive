import { GetObjectCommand, HeadObjectCommand, PutObjectCommand, S3Client, S3ServiceException } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { BackendNotFound, type BlobBackend, type BlobUrl, type ByteRange } from "@near-drive/bridge-common";

export interface ShelbyS3Config {
  /** Default https://s3.beta.shelby.xyz (Shelby Private Beta S3 gateway). */
  endpoint: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  /** Shelby uses region "default". */
  region?: string;
  /** Key prefix inside the bucket (default "near-drive/"). */
  prefix?: string;
  /** Presigned GET lifetime for /url, seconds (Shelby allows 1 s – 7 d). */
  urlTtlSeconds?: number;
}

const isStatus = (e: unknown, ...codes: number[]) =>
  e instanceof S3ServiceException && codes.includes(e.$metadata.httpStatusCode ?? 0);

/**
 * Shelby through its S3-compatible API — the access path Shelby documents for
 * the Oct 2026 Private Beta. Backend id = object key. Writes are create-only
 * (`If-None-Match: *`), which Shelby enforces, so re-PUTs are cheap no-ops.
 */
export class ShelbyS3Backend implements BlobBackend {
  readonly name = "shelby-s3";
  readonly s3: S3Client;
  private readonly prefix: string;

  constructor(private readonly cfg: ShelbyS3Config, s3?: S3Client) {
    this.prefix = cfg.prefix ?? "near-drive/";
    this.s3 =
      s3 ??
      new S3Client({
        endpoint: cfg.endpoint,
        region: cfg.region ?? "default",
        forcePathStyle: true,
        // S3-compatible gateways often reject the SDK's default CRC trailers.
        requestChecksumCalculation: "WHEN_REQUIRED",
        responseChecksumValidation: "WHEN_REQUIRED",
        credentials: { accessKeyId: cfg.accessKeyId, secretAccessKey: cfg.secretAccessKey },
      });
  }

  async put(key: string, data: Uint8Array): Promise<string> {
    const k = this.prefix + key;
    try {
      await this.s3.send(new PutObjectCommand({ Bucket: this.cfg.bucket, Key: k, Body: data, IfNoneMatch: "*", ContentType: "application/octet-stream" }));
    } catch (e) {
      // 412: object exists. Keys are content-derived, so the bytes are the same.
      if (!isStatus(e, 412)) throw e;
    }
    return k;
  }

  async get(k: string, range?: ByteRange): Promise<Uint8Array> {
    try {
      const r = await this.s3.send(
        new GetObjectCommand({ Bucket: this.cfg.bucket, Key: k, Range: range ? `bytes=${range.start}-${range.end}` : undefined }),
      );
      if (!r.Body) throw new Error(`empty body for ${k}`);
      return await r.Body.transformToByteArray();
    } catch (e) {
      if (isStatus(e, 404)) throw new BackendNotFound(k);
      throw e;
    }
  }

  async has(k: string): Promise<boolean> {
    try {
      await this.s3.send(new HeadObjectCommand({ Bucket: this.cfg.bucket, Key: k }));
      return true;
    } catch (e) {
      if (isStatus(e, 404)) return false;
      throw e;
    }
  }

  async url(k: string): Promise<BlobUrl | null> {
    const ttl = Math.min(Math.max(this.cfg.urlTtlSeconds ?? 3600, 1), 7 * 24 * 3600);
    const url = await getSignedUrl(this.s3, new GetObjectCommand({ Bucket: this.cfg.bucket, Key: k }), { expiresIn: ttl });
    return { url, expires_ms: Date.now() + ttl * 1000 };
  }

  async close(): Promise<void> {
    this.s3.destroy();
  }
}
