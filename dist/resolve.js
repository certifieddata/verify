// Artifact-kind resolution (verify#2).
//
// Both certificates and payment receipts can be bare UUIDs, so a UUID alone
// is not a safe discriminator. Resolution order:
//   1. Strong syntax/path hints (prefixes, endpoint URLs, local JSON shape).
//   2. For an ambiguous bare id online: probe BOTH public endpoints.
//        exactly one exists -> that kind
//        both exist         -> AMBIGUOUS (caller must pass --type)
//        neither exists     -> NOT_FOUND
//        transport failure  -> TRANSPORT (never silently "not found")
//   3. --type overrides everything.
import { readFile } from "node:fs/promises";
import { DEFAULT_CERT_API } from "./fetch-cert.js";
import { DEFAULT_RECEIPT_API } from "./receipt.js";
export async function resolveArtifactKind(target, opts = {}) {
    // 1. Prefix hints — cert-family prefixes are certificates.
    if (/^(cert_|scert_)/.test(target))
        return { kind: "certificate", via: "id-prefix" };
    // Endpoint-URL hints.
    if (/\/api\/payments\/verify\//.test(target))
        return { kind: "receipt", via: "url-path" };
    if (/\/api\/v1\/certificates\//.test(target))
        return { kind: "certificate", via: "url-path" };
    // Local file / stdin: sniff the JSON shape.
    const looksLocal = target === "-" ||
        target.endsWith(".json") ||
        target.startsWith("./") ||
        target.startsWith("/") ||
        /^[A-Za-z]:[\\/]/.test(target);
    if (looksLocal && target !== "-") {
        try {
            const parsed = JSON.parse(await readFile(target, "utf8"));
            const schema = parsed.schema_version ??
                parsed.receipt?.schema_version;
            if (schema === "payment_receipt.v1")
                return { kind: "receipt", via: "local-schema" };
            if (typeof schema === "string" && schema.startsWith("cert.")) {
                return { kind: "certificate", via: "local-schema" };
            }
            // Envelope shape without schema — a verify-endpoint dump.
            if (parsed.receipt && parsed.storedReceiptHash)
                return { kind: "receipt", via: "local-envelope" };
            return { kind: "certificate", via: "local-default" };
        }
        catch {
            return { kind: "certificate", via: "local-unreadable-default" };
        }
    }
    if (target === "-")
        return { kind: "certificate", via: "stdin-default" };
    // 2. Bare id online — probe both endpoints. Offline cannot probe.
    if (opts.offline)
        return { kind: "certificate", via: "offline-default" };
    const certUrl = `${(opts.certApiBase ?? DEFAULT_CERT_API).replace(/\/$/, "")}/${encodeURIComponent(target)}`;
    const rcptUrl = `${(opts.receiptApiBase ?? DEFAULT_RECEIPT_API).replace(/\/$/, "")}/${encodeURIComponent(target)}`;
    const probe = async (url) => {
        try {
            const res = await fetch(url, { method: "GET" });
            if (res.ok)
                return "exists";
            if (res.status === 404)
                return "missing";
            return "error"; // 5xx/403/… — a server problem is NOT evidence of absence
        }
        catch {
            return "error";
        }
    };
    const [cert, rcpt] = await Promise.all([probe(certUrl), probe(rcptUrl)]);
    if (cert === "error" || rcpt === "error") {
        // If the OTHER endpoint definitively resolved, use it; otherwise surface
        // the transport problem instead of guessing.
        if (cert === "exists" && rcpt !== "exists")
            return { kind: "certificate", via: "probe" };
        if (rcpt === "exists" && cert !== "exists")
            return { kind: "receipt", via: "probe" };
        return { kind: "transport_error", via: "probe" };
    }
    if (cert === "exists" && rcpt === "exists")
        return { kind: "ambiguous", via: "probe" };
    if (cert === "exists")
        return { kind: "certificate", via: "probe" };
    if (rcpt === "exists")
        return { kind: "receipt", via: "probe" };
    return { kind: "not_found", via: "probe" };
}
//# sourceMappingURL=resolve.js.map