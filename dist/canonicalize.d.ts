export type JsonValue = null | boolean | number | string | JsonValue[] | {
    [k: string]: JsonValue;
};
export declare function canonicalize(value: unknown): string;
export declare function canonicalizeToBytes(value: unknown): Uint8Array;
//# sourceMappingURL=canonicalize.d.ts.map