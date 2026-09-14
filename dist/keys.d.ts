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
export declare const DEFAULT_KEYS_URL = "https://certifieddata.io/.well-known/signing-keys.json";
export declare const CACHE_PATH: string;
export declare const CACHE_TTL_MS: number;
export interface LoadKeysOptions {
    url?: string;
    keysFile?: string;
    noCache?: boolean;
    offline?: boolean;
    cachePath?: string;
}
export declare function loadKeys(opts?: LoadKeysOptions): Promise<KeyDoc>;
export declare function findKey(doc: KeyDoc, keyId: string): KeyEntry | undefined;
//# sourceMappingURL=keys.d.ts.map