export type ArtifactKind = "certificate" | "receipt";
export type Resolution = {
    kind: ArtifactKind;
    via: string;
} | {
    kind: "ambiguous";
    via: string;
} | {
    kind: "not_found";
    via: string;
} | {
    kind: "transport_error";
    via: string;
};
export declare function resolveArtifactKind(target: string, opts?: {
    offline?: boolean;
    certApiBase?: string;
    receiptApiBase?: string;
}): Promise<Resolution>;
//# sourceMappingURL=resolve.d.ts.map