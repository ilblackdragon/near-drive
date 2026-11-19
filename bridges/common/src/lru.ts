/** Byte-capped LRU for whole backend objects (e.g. FOC pieces, which have no range reads). */
export class ByteLru {
  private map = new Map<string, Uint8Array>();
  private bytes = 0;
  constructor(private readonly maxBytes: number) {}

  get(k: string): Uint8Array | undefined {
    const v = this.map.get(k);
    if (v) {
      this.map.delete(k);
      this.map.set(k, v);
    }
    return v;
  }

  set(k: string, v: Uint8Array): void {
    if (v.length > this.maxBytes) return;
    const old = this.map.get(k);
    if (old) {
      this.bytes -= old.length;
      this.map.delete(k);
    }
    this.map.set(k, v);
    this.bytes += v.length;
    for (const [key, val] of this.map) {
      if (this.bytes <= this.maxBytes) break;
      this.map.delete(key);
      this.bytes -= val.length;
    }
  }
}
