// cert.v2 verification.
//
// Differences from cert.v1 that matter for verification:
//
//   1. The signature is NOT a field inside the signed document. In v1 the
//      signature lives on the certificate and is stripped before
//      canonicalization; in v2 the payload is signed as-is and the signature
//      travels beside it in an envelope. So v2 canonicalizes the WHOLE payload
//      — nothing is removed.
//   2. The signer is named at payload.issuer.signing_key_id, not cert.key_id.
//   3. The artifact digest is bare lowercase hex at payload.artifact_hash,
//      with no "sha256:" prefix.
//   4. There is no rows/columns/algorithm triple. manifest.record_count and
//      manifest.engine are the nearest equivalents and are display-only.
//
// Signed bytes are Ed25519 over RFC 8785 (JCS) of the payload. Confirmed
// empirically against the live production certificate in
// fixtures/valid-cert-v2.json: of JCS(payload), JSON.stringify(payload),
// JCS(envelope minus signature) and JCS(payload minus the self-hash), only
// JCS(payload) verifies.
//
// On the envelope's signature field: production serves it as an OBJECT, not a
// bare base64 string —
//
//     /api/certificates/:id/signed-payload  ->  {alg, key_id, value}
//     /api/certificates/:id                 ->  {alg, key_id, sig}
//
// so both spellings are accepted, as is a plain string. A verifier that only
// accepted the string form would report MALFORMED on every certificate the
// company has issued.
import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { canonicalizeToBytes } from "./canonicalize.js";
import { sha256File, formatDigest } from "./hash.js";
import { findKey } from "./keys.js";
/** True when doc is a v2 envelope or a bare v2 payload carrying a sibling signature. */
export function isCertV2(doc) {
    if (!doc || typeof doc !== "object")
        return false;
    const d = doc;
    if (d.schema_version === "cert.v2")
        return true;
    const p = d.payload;
    return !!p && typeof p === "object" && p.schema_version === "cert.v2";
}
/**
 * Pull the base64 signature out of whichever shape arrived.
 * Returns null when there is nothing usable, so the caller can say so plainly.
 */
function unwrapSignature(raw) {
    if (typeof raw === "string") {
        return raw.length > 0 ? { b64: raw } : null;
    }
    if (raw && typeof raw === "object") {
        const o = raw;
        // `value` is what /signed-payload emits; `sig` is what the base route emits.
        const b64 = [o.value, o.sig, o.signature].find((v) => typeof v === "string" && v.length > 0);
        if (typeof b64 !== "string")
            return null;
        return {
            b64,
            alg: typeof o.alg === "string" ? o.alg : undefined,
            keyId: typeof o.key_id === "string" ? o.key_id : undefined,
        };
    }
    return null;
}
/**
 * Normalize either shape into an envelope.
 * Accepts {payload, signature} or a bare payload with a sibling signature.
 */
export function toEnvelope(doc) {
    const hasNested = !!doc.payload && typeof doc.payload === "object";
    const payload = (hasNested ? doc.payload : doc);
    const unwrapped = unwrapSignature(doc.signature);
    if (!unwrapped) {
        return "cert.v2 requires a detached signature alongside the payload; none was present";
    }
    if (payload.schema_version !== "cert.v2") {
        return `unsupported schema_version: ${String(payload.schema_version)}`;
    }
    return {
        payload,
        signature: unwrapped.b64,
        signature_alg: unwrapped.alg ?? (typeof doc.signature_alg === "string" ? doc.signature_alg : undefined),
        envelope_key_id: unwrapped.keyId ?? (typeof doc.signing_key_id === "string" ? doc.signing_key_id : undefined),
    };
}
export async function verifyCertificateV2(doc, trustedKeys, datasetPath) {
    const result = blankV2Result();
    const env = toEnvelope(doc);
    if (typeof env === "string")
        return finish(result, "MALFORMED", env);
    const { payload, signature } = env;
    const shapeError = validateV2Shape(payload);
    if (shapeError)
        return finish(result, "MALFORMED", shapeError);
    result.certification_id = payload.certificate_id;
    result.issuer = payload.issuer?.name ?? null;
    result.signed_at = payload.issued_at;
    result.algorithm = payload.manifest?.engine ?? payload.certificate_type ?? null;
    result.dataset_hash_expected = formatDigest(payload.artifact_hash.toLowerCase());
    if (typeof payload.manifest?.record_count === "number") {
        result.rows = payload.manifest.record_count;
    }
    // Key selection reads the SIGNED payload only. The envelope is not covered by
    // the signature, so trusting its key_id would let anyone redirect which key
    // is used to check the bytes — and then present a document that "verifies".
    const keyId = payload.issuer.signing_key_id;
    if (!keyId)
        return finish(result, "MALFORMED", "missing issuer.signing_key_id");
    result.key_id = keyId;
    // A disagreement between the signed payload and the envelope means the
    // document is internally inconsistent. Refuse rather than silently
    // preferring one, so the condition is visible instead of papered over.
    if (env.envelope_key_id && env.envelope_key_id !== keyId) {
        return finish(result, "MALFORMED", `envelope names key_id ${env.envelope_key_id} but the signed payload names ${keyId}`);
    }
    const key = findKey(trustedKeys, keyId);
    if (!key || key.revoked_at || !isEd25519(key.algorithm)) {
        result.checks.key_trust = "fail";
        const reason = !key
            ? `key_id ${keyId} not in trusted keys`
            : key.revoked_at
                ? `key_id ${keyId} was revoked at ${key.revoked_at}`
                : `key ${keyId} is not ed25519`;
        return finish(result, "UNKNOWN_KEY", reason);
    }
    result.checks.key_trust = "pass";
    result.key_label = key.label;
    const sigBytes = decodeSignature(signature);
    if (!sigBytes) {
        return finish(result, "MALFORMED", "signature is not 64 bytes of base64-encoded Ed25519");
    }
    // v2 signs the entire payload — nothing is stripped.
    const canonicalBytes = canonicalizeToBytes(payload);
    const publicKey = createPublicKey({ key: pemFromRawEd25519(key.public_key), format: "pem" });
    const sigOk = cryptoVerify(null, canonicalBytes, publicKey, sigBytes);
    result.checks.signature = sigOk ? "pass" : "fail";
    if (!sigOk) {
        return finish(result, "INVALID", "ed25519 signature does not verify against canonicalized cert.v2 payload");
    }
    if (datasetPath) {
        const actualHex = await sha256File(datasetPath);
        result.dataset_hash_actual = formatDigest(actualHex);
        if (actualHex !== payload.artifact_hash.toLowerCase()) {
            result.checks.dataset_match = "fail";
            return finish(result, "DATASET_MISMATCH", `artifact hash mismatch (expected sha256:${payload.artifact_hash.toLowerCase()}, got ${result.dataset_hash_actual})`);
        }
        result.checks.dataset_match = "pass";
    }
    return finish(result, "VALID", "signature verified and key is trusted");
}
/**
 * Compared case-insensitively on purpose. The published keys document spells
 * this "Ed25519"; this verifier's own fixtures spell it "ed25519". Treating
 * that as an untrusted key would report UNKNOWN_KEY — a security verdict — for
 * a cosmetic difference, which teaches users to disbelieve the tool.
 */
function isEd25519(algorithm) {
    return typeof algorithm === "string" && algorithm.toLowerCase() === "ed25519";
}
function validateV2Shape(p) {
    if (!p || typeof p !== "object")
        return "cert.v2 payload is not an object";
    for (const f of ["certificate_id", "issued_at", "artifact_hash", "issuer"]) {
        if (p[f] === undefined || p[f] === null)
            return `missing required field: ${f}`;
    }
    if (!p.issuer || typeof p.issuer !== "object")
        return "issuer must be an object";
    if (typeof p.artifact_hash !== "string" || !/^[0-9a-f]{64}$/i.test(p.artifact_hash)) {
        return "artifact_hash must be 64 hex characters";
    }
    if (p.hash_method && !/^sha-?256$/i.test(p.hash_method)) {
        return `unsupported hash_method: ${p.hash_method}`;
    }
    return null;
}
function decodeSignature(b64) {
    try {
        const buf = Buffer.from(b64, "base64");
        if (buf.length !== 64)
            return null;
        return buf;
    }
    catch {
        return null;
    }
}
function pemFromRawEd25519(material) {
    if (material.includes("BEGIN PUBLIC KEY"))
        return material;
    const raw = Buffer.from(material, "base64");
    if (raw.length !== 32)
        throw new Error(`expected 32-byte ed25519 key, got ${raw.length}`);
    const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
    const der = Buffer.concat([spkiPrefix, raw]).toString("base64");
    return `-----BEGIN PUBLIC KEY-----\n${der.match(/.{1,64}/g).join("\n")}\n-----END PUBLIC KEY-----\n`;
}
function blankV2Result() {
    return {
        verdict: "MALFORMED",
        certification_id: null,
        key_id: null,
        issuer: null,
        algorithm: null,
        signed_at: null,
        dataset_hash_expected: null,
        dataset_hash_actual: null,
        checks: { signature: "skipped", key_trust: "skipped", dataset_match: "skipped" },
        reason: "",
    };
}
function finish(r, verdict, reason) {
    r.verdict = verdict;
    r.reason = reason;
    return r;
}
//# sourceMappingURL=cert-v2.js.map