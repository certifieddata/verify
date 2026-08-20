import type { KeyDoc, KeyEntry } from "./types.js";
export declare const DEFAULT_KEYS_URL = "https://certifieddata.io/.well-known/certifieddata-keys.json";
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