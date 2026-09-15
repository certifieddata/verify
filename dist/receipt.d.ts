import type { CheckResult } from "./types.js";
export declare const DEFAULT_RECEIPT_API = "https://certifieddata.io/api/payments/verify";
export declare const DEFAULT_RECEIPT_KEY_URL = "https://certifieddata.io/.well-known/certifieddata-public-key.pem";
export type ReceiptVerdict = "VALID" | "INVALID" | "UNKNOWN_KEY" | "MALFORMED";
export interface ReceiptVerifyResult {
    artifact_type: "receipt";
    artifact_id: string | null;
    verdict: ReceiptVerdict;
    key_id: string | null;
    issuer: string | null;
    signed_at: string | null;
    checks: {
        signature: CheckResult;
        key_trust: CheckResult;
        payload_hash: CheckResult;
    };
    reason: string;
    /** The server's own booleans, informational only — never the verdict. */
    server_reported?: {
        valid?: boolean;
        signatureValid?: boolean;
        hashValid?: boolean;
    };
    settlement_state?: string | null;
    amount_cents?: number | null;
    currency?: string | null;
    /**
     * What the signature actually covers.
     *
     * A signature is only as interesting as the things it binds, and a receipt
     * that says nothing but "VALID" invites the reader to take the rest on
     * trust — which is the opposite of the point. These fields are read out of
     * the *verified* payload, so they are displayed only after the signature and
     * payload hash have both passed.
     */
    bindings?: {
        policy_id?: string | null;
        policy_hash?: string | null;
        policy_version?: string | null;
        authorization_id?: string | null;
        decision_record_id?: string | null;
        artifact_hash?: string | null;
        certificate_id?: string | null;
        transaction_id?: string | null;
        external_reference?: string | null;
        purpose?: string | null;
        agent_id?: string | null;
        rail?: string | null;
        status?: string | null;
        settled_at?: string | null;
    };
}
interface ReceiptEnvelope {
    payload: Record<string, unknown>;
    signatureB64: string | null;
    storedHash: string | null;
    serverReported?: {
        valid?: boolean;
        signatureValid?: boolean;
        hashValid?: boolean;
    };
}
export interface FetchReceiptOptions {
    apiBase?: string;
    offline?: boolean;
}
/** Accepts a receipt id, a /api/payments/verify URL, a local .json path, or "-". */
export declare function fetchReceipt(idOrPathOrUrl: string, opts?: FetchReceiptOptions): Promise<ReceiptEnvelope>;
export interface LoadReceiptKeyOptions {
    keyUrl?: string;
    keyFile?: string;
    offline?: boolean;
}
/**
 * Loads the Agent Commerce public key PEM. Fails loudly — a 503 here means
 * the issuer is misconfigured, and the CLI's answer is "cannot verify
 * independently", never "let the server vouch for itself".
 */
export declare function loadReceiptKey(opts?: LoadReceiptKeyOptions): Promise<string>;
export declare function verifyReceiptEnvelope(env: ReceiptEnvelope, publicKeyPem: string): ReceiptVerifyResult;
export {};
//# sourceMappingURL=receipt.d.ts.map