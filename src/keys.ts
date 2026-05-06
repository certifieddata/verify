import { readFile, writeFile, mkdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { KeyDoc, KeyEntry } from "./types.js";

export const DEFAULT_KEYS_URL = "https://certifieddata.io/.well-known/certifieddata-keys.json";
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

function parseKeyDoc(body: string): KeyDoc {
  const parsed = JSON.parse(body) as KeyDoc;
  if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.keys)) {
    throw new Error("invalid key document: missing keys[]");
  }
  return parsed;
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
