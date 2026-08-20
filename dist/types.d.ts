export interface Certificate {
    certification_id: string;
    timestamp: string;
    issuer: string;
    dataset_hash: string;
    algorithm: "CTGAN" | "GaussianCopula" | "DP-CTGAN" | string;
    rows: number;
    columns: number;
    schema_version: "cert.v1";
    signature: string;
    key_id: string;
    metadata?: Record<string, unknown> & {
        epsilon?: number | null;
    };
}
export interface KeyEntry {
    key_id: string;
    public_key: string;
    algorithm: "ed25519";
    created_at: string;
    revoked_at?: string | null;
    label?: string;
}
export interface KeyDoc {
    issuer: string;
    keys: KeyEntry[];
    fetched_at?: string;
}
export type Verdict = "VALID" | "INVALID" | "UNKNOWN_KEY" | "DATASET_MISMATCH" | "MALFORMED";
export type CheckResult = "pass" | "fail" | "skipped";
export interface VerifyResult {
    verdict: Verdict;
    certification_id: string | null;
    key_id: string | null;
    issuer: string | null;
    algorithm: string | null;
    signed_at: string | null;
    dataset_hash_expected: string | null;
    dataset_hash_actual: string | null;
    checks: {
        signature: CheckResult;
        key_trust: CheckResult;
        dataset_match: CheckResult;
    };
    reason: string;
    rows?: number;
    columns?: number;
    key_label?: string;
}
export declare const REQUIRED_CERT_FIELDS: ReadonlyArray<keyof Certificate>;
//# sourceMappingURL=types.d.ts.map