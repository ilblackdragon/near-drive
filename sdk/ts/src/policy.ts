/**
 * Namespace access policy, a port of `near_drive_core::policy` (the rules `drive.near` holds).
 *
 * Rules are evaluated in order; the first rule whose `prefix` pattern matches the path applies.
 * `{account}` in a prefix captures one path segment that must be a valid account id;
 * `{account}` in read/write/payer refers to that captured value. The namespace owner always has
 * full access and is the default payer.
 */
import { isValidAccountId } from "./uri.js";

export interface Rule {
  prefix: string;
  read?: string[];
  write?: string[];
  payer?: string | null;
}

export interface Access {
  read: boolean;
  write: boolean;
  payer: string;
}

/** The captured `{account}` (`""` when the pattern has none) if `path` is under `pattern`, else `null`. */
function matchPrefix(pattern: string, path: string): string | null {
  const at = pattern.indexOf("{account}");
  if (at < 0) return path.startsWith(pattern) ? "" : null;
  const pre = pattern.slice(0, at);
  const post = pattern.slice(at + "{account}".length);
  if (!path.startsWith(pre)) return null;
  const rest = path.slice(pre.length);
  const slash = rest.indexOf("/");
  const end = slash < 0 ? rest.length : slash;
  const acct = rest.slice(0, end);
  if (!isValidAccountId(acct)) return null;
  return rest.slice(end).startsWith(post) ? acct : null;
}

const subst = (s: string, bound: string) => s.split("{account}").join(bound);

export function resolve(namespace: string, rules: readonly Rule[], path: string, signer: string): Access {
  const owner = signer === namespace;
  for (const r of rules) {
    const bound = matchPrefix(r.prefix, path);
    if (bound === null) continue;
    const allowed = (list: readonly string[] | undefined) => (list ?? []).some((e) => e === "*" || subst(e, bound) === signer);
    return {
      read: owner || allowed(r.read),
      write: owner || allowed(r.write),
      payer: r.payer != null ? subst(r.payer, bound) : namespace,
    };
  }
  return { read: owner, write: owner, payer: namespace };
}

/** Type-check rules received as JSON (e.g. from `get_rules`). */
export function normalizeRules(v: unknown): Rule[] {
  if (!Array.isArray(v)) throw new Error("rules must be an array");
  const strs = (x: unknown, what: string): string[] => {
    if (x === undefined || x === null) return [];
    if (!Array.isArray(x) || x.some((e) => typeof e !== "string")) throw new Error(`rule ${what} must be an array of strings`);
    return x as string[];
  };
  return v.map((r) => {
    const o = r as Record<string, unknown>;
    if (typeof o !== "object" || o === null || typeof o.prefix !== "string") throw new Error("rule.prefix must be a string");
    if (o.payer !== undefined && o.payer !== null && typeof o.payer !== "string") throw new Error("rule.payer must be a string");
    return { prefix: o.prefix, read: strs(o.read, "read"), write: strs(o.write, "write"), payer: (o.payer as string | null | undefined) ?? null };
  });
}
