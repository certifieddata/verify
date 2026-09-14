import { readFile, writeFile, mkdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { KeyDoc, KeyEntry } from "./types.js";

/**
 * The pinned trust root.
 *
 * This is the document the issuer actually publishes, and the one every
 * certificate's own `public_key_url` points at. It is pinned here rather than
 * read out of the certificate: a URL taken from an unverified document would
 * let whoever supplied the document choose the keys it is checked against.
 *
 * `certifieddata-keys.json` — the path this used to point at — returns 404 and
 * was never deployed. Both dialects are accepted by `parseKeyDoc`, so if that
 * document is published later it will work without a code change.
 */
export const DEFAULT_KEYS_URL = "https://certifieddata.io/.well-known/signing-keys.json";
export const CACHE_PATH = join(homedir(), ".certifieddata", "keys.json");
export const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

export interface LoadKeysOptions {
  url?: string;
  keysFile?: string;
  noCache?: boolean;
  offline?: boolean;
  cachePath?: string;
}

export async function loadKeys(opts: LoadKeysOptions = {}): Promise<KeyDoc> {
  if (opts.keysFile) {
    return parseKeyDoc(await readFile(opts.keysFile, "utf8"));
  }

  const cachePath = opts.cachePath ?? CACHE_PATH;

  if (opts.offline) {
    if (opts.noCache) {
      throw new Error("offline mode requires --keys <file> when --no-cache is set");
    }
    return parseKeyDoc(await readFile(cachePath, "utf8"));
  }

  if (!opts.noCache) {
    const fresh = await readCacheIfFresh(cachePath);
    if (fresh) return fresh;
  }

  const url = opts.url ?? DEFAULT_KEYS_URL;
  let body: string;
  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    body = await res.text();
  } catch (err) {
    if (!opts.noCache) {
      const stale = await readFile(cachePath, "utf8").catch(() => null);
      if (stale) return parseKeyDoc(stale);
    }
    throw new Error(`failed to fetch keys from ${url}: ${(err as Error).message}`);
  }

  const doc = parseKeyDoc(body);
  if (!opts.noCache) await writeCache(cachePath, body);
  return doc;
}

export function findKey(doc: KeyDoc, keyId: string): KeyEntry | undefined {
  return doc.keys.find((k) => k.key_id === keyId);
}

/**
 * Two dialects are in circulation and both have to work:
 *
 *   this verifier's own shape   keys[].public_key,     algorithm "ed25519",
 *                               per-key revoked_at
 *   signing-keys.v1 (published) keys[].public_key_pem, algorithm "Ed25519",
 *                               revocation in top-level revoked[]/retired[]
 *
 * Normalizing here rather than at each call site means the difference cannot
 * turn into a wrong verdict. Two of these differences are security-relevant:
 * a mis-read `algorithm` yields UNKNOWN_KEY on a good key, and an unmapped
 * `revoked[]` would let a revoked key keep verifying.
 */
function parseKeyDoc(body: string): KeyDoc {
  const parsed = JSON.parse(body) as Record<string, unknown>;
  if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.keys)) {
    throw new Error("invalid key document: missing keys[]");
  }

  const revokedAtFor = buildRevocationIndex(parsed);

  const keys: KeyEntry[] = (parsed.keys as Record<string, unknown>[]).map((raw) => {
    const keyId = String(raw.key_id ?? "");
    const material = (raw.public_key ?? raw.public_key_pem ?? raw.public_key_raw_b64url) as
      | string
      | undefined;
    if (!keyId || typeof material !== "string" || material.length === 0) {
      throw new Error(`invalid key document: entry ${keyId || "(no key_id)"} has no public key`);
    }
    return {
      ...(raw as unknown as KeyEntry),
      key_id: keyId,
      // CRLF appears in the published PEM; node's createPublicKey is fussier
      // about that than it needs to be.
      public_key: material.replace(/\r\n/g, "\n"),
      algorithm: String(raw.algorithm ?? "").toLowerCase() as "ed25519",
      revoked_at: (raw.revoked_at as string | null | undefined) ?? revokedAtFor.get(keyId) ?? null,
    };
  });

  return { ...(parsed as unknown as KeyDoc), issuer: String(parsed.issuer ?? ""), keys };
}

/**
 * signing-keys.v1 lists revocations separately from the key entries. Entries
 * may be bare key_id strings or objects; anything else is refused rather than
 * ignored, because silently skipping a revocation record we cannot read would
 * mean treating a possibly-revoked key as good.
 */
function buildRevocationIndex(doc: Record<string, unknown>): Map<string, string> {
  const out = new Map<string, string>();
  for (const field of ["revoked", "retired"] as const) {
    const list = doc[field];
    if (list === undefined || list === null) continue;
    if (!Array.isArray(list)) {
      throw new Error(`invalid key document: ${field} must be an array`);
    }
    for (const entry of list) {
      if (typeof entry === "string") {
        out.set(entry, `listed in ${field}[]`);
        continue;
      }
      if (entry && typeof entry === "object") {
        const e = entry as Record<string, unknown>;
        const id = e.key_id ?? e.id;
        if (typeof id === "string" && id.length > 0) {
          const when = e.revoked_at ?? e.retired_at ?? e.at;
          out.set(id, typeof when === "string" ? when : `listed in ${field}[]`);
          continue;
        }
      }
      throw new Error(
        `invalid key document: unreadable entry in ${field}[] — refusing to ignore a revocation record`,
      );
    }
  }
  return out;
}

async function readCacheIfFresh(path: string): Promise<KeyDoc | null> {
  try {
    const s = await stat(path);
    if (Date.now() - s.mtimeMs > CACHE_TTL_MS) return null;
    return parseKeyDoc(await readFile(path, "utf8"));
  } catch {
    return null;
  }
}

async function writeCache(path: string, body: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, body, "utf8");
}
