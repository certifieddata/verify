import type { KeyDoc, VerifyResult } from "./types.js";
export interface CertV2Issuer {
    name?: string;
    signing_key_id: string;
    signature_alg?: string;
    environment?: string;
}
export interface CertV2Payload {
    schema_version: "cert.v2";
    certificate_id: string;
    certificate_type?: string;
    issued_at: string;
    artifact_hash: string;
    hash_method?: string;
    issuer: CertV2Issuer;
    subject?: Record<string, unknown>;
    manifest?: {
        engine?: string;
        record_count?: number;
        [k: string]: unknown;
    };
    [k: string]: unknown;
}
/** The signature as production actually serves it, or as a bare base64 string. */
export type CertV2Signature = string | {
    value?: string;
    sig?: string;
    signature?: string;
    alg?: string;
    key_id?: string;
};
export interface CertV2Envelope {
    payload: CertV2Payload;
    /** base64 Ed25519, already unwrapped from whichever spelling arrived. */
    signature: string;
    signature_alg?: string;
    /** key_id as claimed by the UNSIGNED envelope. Never used to select a key. */
    envelope_key_id?: string;
}
/** True when doc is a v2 envelope or a bare v2 payload carrying a sibling signature. */
export declare function isCertV2(doc: unknown): boolean;
/**
 * Normalize either shape into an envelope.
 * Accepts {payload, signature} or a bare payload with a sibling signature.
 */
export declare function toEnvelope(doc: Record<string, unknown>): CertV2Envelope | string;
export declare function verifyCertificateV2(doc: Record<string, unknown>, trustedKeys: KeyDoc, datasetPath?: string): Promise<VerifyResult>;
//# sourceMappingURL=cert-v2.d.ts.map