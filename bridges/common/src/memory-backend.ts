import { BackendNotFound, type BlobBackend, type BlobUrl } from "./backend.js";
import { sliceRange, type ByteRange } from "./range.js";

/** In-memory backend for tests and local dev. */
export class MemoryBackend implements BlobBackend {
  readonly name = "memory";
  readonly objects = new Map<string, Uint8Array>();
  puts = 0;
  gets = 0;
  failNextPuts = 0;
  urlBase = "https://mem.invalid/";

  async put(key: string, data: Uint8Array): Promise<string> {
    if (this.failNextPuts > 0) {
      this.failNextPuts--;
      throw new Error("injected put failure");
    }
    this.puts++;
    const id = "mem:" + key;
    this.objects.set(id, new Uint8Array(data));
    return id;
  }

  async get(id: string, range?: ByteRange): Promise<Uint8Array> {
    this.gets++;
    const d = this.objects.get(id);
    if (!d) throw new BackendNotFound(id);
    return new Uint8Array(sliceRange(d, range));
  }

  async url(id: string): Promise<BlobUrl | null> {
    return this.objects.has(id) ? { url: this.urlBase + encodeURIComponent(id), expires_ms: null } : null;
  }
}
