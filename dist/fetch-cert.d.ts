import type { Certificate } from "./types.js";
export declare const DEFAULT_CERT_API = "https://certifieddata.io/api/v1/certificates";
export interface FetchCertOptions {
    apiBase?: string;
    offline?: boolean;
}
export declare function fetchCert(idOrPathOrUrl: string, opts?: FetchCertOptions): Promise<Certificate>;
//# sourceMappingURL=fetch-cert.d.ts.map