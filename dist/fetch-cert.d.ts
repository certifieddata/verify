/**
 * Resolving a bare certificate id must land on bytes that are actually
 * verifiable.
 *
 * `https://certifieddata.io/api/v1/certificates/:id` — the path this used to
 * point at — returns 404; it was never deployed.
 *
 * `https://api.certifieddata.io/api/certificates/:id` does respond, but it
 * serves a cert.v1-shaped *display projection* of a cert.v2 certificate. It
 * carries the real signature bytes while the signature covers the v2 payload,
 * not the projection, so verifying that document yields INVALID — which reads
 * as tampering when nothing has been tampered with.
 *
 * `/signed-payload` is the envelope whose signature verifies over its own
 * payload, so that is what a verifier has to ask for.
 */
export declare const DEFAULT_CERT_API = "https://api.certifieddata.io/api/certificates";
export declare const CERT_ENVELOPE_SUFFIX = "/signed-payload";
export interface FetchCertOptions {
    apiBase?: string;
    offline?: boolean;
}
/**
 * Returns the raw certificate document. Shape validation belongs to the
 * verifier, not the fetcher: the document may be a cert.v1 certificate or a
 * cert.v2 envelope, and deciding which is the caller's job.
 */
export declare function fetchCert(idOrPathOrUrl: string, opts?: FetchCertOptions): Promise<Record<string, unknown>>;
//# sourceMappingURL=fetch-cert.d.ts.map