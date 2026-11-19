/** Inclusive byte range [start, end]. */
export interface ByteRange {
  start: number;
  end: number;
}

export type RangeResult =
  | { kind: "none" } // no / ignorable Range header → full body
  | { kind: "ok"; range: ByteRange }
  | { kind: "unsatisfiable" };

/**
 * Parses a single-range `Range: bytes=a-b | a- | -n` header against `size`.
 * Multi-range and non-bytes units are ignored (served as a full 200, which
 * RFC 9110 §14.2 permits).
 */
export function parseRange(header: string | undefined, size: number): RangeResult {
  if (!header) return { kind: "none" };
  const m = /^\s*bytes\s*=\s*(\d*)\s*-\s*(\d*)\s*$/i.exec(header);
  if (!m) return { kind: "none" };
  const [, a = "", b = ""] = m;
  if (a === "" && b === "") return { kind: "none" };
  if (a === "") {
    // suffix: last n bytes
    const n = Number(b);
    if (!Number.isSafeInteger(n) || n === 0 || size === 0) return { kind: "unsatisfiable" };
    return { kind: "ok", range: { start: Math.max(0, size - n), end: size - 1 } };
  }
  const start = Number(a);
  let end = b === "" ? size - 1 : Number(b);
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end)) return { kind: "unsatisfiable" };
  if (b !== "" && end < start) return { kind: "none" }; // invalid → ignore
  if (start >= size) return { kind: "unsatisfiable" };
  end = Math.min(end, size - 1);
  return { kind: "ok", range: { start, end } };
}

export function sliceRange(data: Uint8Array, r?: ByteRange): Uint8Array {
  return r ? data.subarray(r.start, r.end + 1) : data;
}
