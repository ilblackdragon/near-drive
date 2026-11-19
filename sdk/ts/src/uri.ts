/** `near://<namespace>/<path>` addressing (namespace = NEAR account id). */

export class UriError extends Error {}

/** NEAR account id: 2..=64 chars of [a-z0-9] separated by single `.`, `-`, `_`. */
export function validateAccountId(id: string): void {
  if (typeof id !== "string" || id.length < 2 || id.length > 64 || !/^[a-z0-9]+([._-][a-z0-9]+)*$/.test(id)) {
    throw new UriError(`invalid NEAR account id: ${id}`);
  }
}

export function isValidAccountId(id: string): boolean {
  try {
    validateAccountId(id);
    return true;
  } catch {
    return false;
  }
}

const enc = new TextEncoder();
// Rust `char::is_control` == Unicode general category Cc.
const CONTROL_OR_BACKSLASH = /[\u0000-\u001f\u007f-\u009f\\]/;

/** Object paths: 1..=1024 UTF-8 bytes, `/`-separated non-empty segments, no `.`/`..`, no control chars or `\`. */
export function validatePath(p: string, allowTrailingSlash: boolean): void {
  const err = (m: string) => new UriError(`invalid object path ${JSON.stringify(p)}: ${m}`);
  if (typeof p !== "string") throw err("not a string");
  const n = enc.encode(p).length;
  if (n === 0 || n > 1024) throw err("length must be 1..=1024");
  if (CONTROL_OR_BACKSLASH.test(p)) throw err("control characters or backslash");
  const body = allowTrailingSlash && p.endsWith("/") ? p.slice(0, -1) : p;
  if (body === "") throw err("empty");
  for (const seg of body.split("/")) {
    if (seg === "" || seg === "." || seg === "..") throw err("empty, '.' or '..' segment");
  }
}

export class NearUri {
  readonly namespace: string;
  readonly path: string;

  private constructor(namespace: string, path: string) {
    this.namespace = namespace;
    this.path = path;
  }

  /** Parse `near://ns/path`; `path` may be empty or end in `/` (a prefix). */
  static parse(s: string): NearUri {
    if (typeof s !== "string" || !s.startsWith("near://")) throw new UriError("uri must start with near://");
    const rest = s.slice(7);
    const i = rest.indexOf("/");
    const ns = i < 0 ? rest : rest.slice(0, i);
    const path = i < 0 ? "" : rest.slice(i + 1);
    validateAccountId(ns);
    if (path !== "") validatePath(path, true);
    return new NearUri(ns, path);
  }

  /** A concrete object (non-empty path, no trailing slash). */
  static object(namespace: string, path: string): NearUri {
    validateAccountId(namespace);
    validatePath(path, false);
    return new NearUri(namespace, path);
  }

  static from(u: string | NearUri): NearUri {
    return typeof u === "string" ? NearUri.parse(u) : u;
  }

  toString(): string {
    return `near://${this.namespace}/${this.path}`;
  }
}

/** Percent-encode everything except RFC 3986 unreserved characters and `/` (byte-wise, uppercase hex). */
export function encodePath(p: string): string {
  let out = "";
  for (const b of enc.encode(p)) {
    const c = String.fromCharCode(b);
    if (/[A-Za-z0-9\-._~/]/.test(c)) out += c;
    else out += "%" + b.toString(16).toUpperCase().padStart(2, "0");
  }
  return out;
}
