export declare function sha256Hex(bytes: Uint8Array | string): string;
export declare function sha256File(path: string): Promise<string>;
export declare function formatDigest(hex: string): string;
export declare function parseDigest(value: string): {
    algo: string;
    hex: string;
};
//# sourceMappingURL=hash.d.ts.map