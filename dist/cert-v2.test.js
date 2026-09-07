import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { isCertV2, toEnvelope, verifyCertificateV2 } from "./cert-v2.js";
const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "..", "fixtures");
/** Fresh copy each time — several tests mutate the document. */
async function loadEnvelope() {
    return JSON.parse(await readFile(join(fixtures, "valid-cert-v2.json"), "utf8"));
}
async function prodKeys() {
    return JSON.parse(await readFile(join(fixtures, "prod-keys.json"), "utf8"));
}
// ── detection ────────────────────────────────────────────────────────────────
test("isCertV2 detects the production envelope", async () => {
    const env = await loadEnvelope();
    // Production's OUTER schema_version is "certifieddata.manifest.v1"; only the
    // payload says cert.v2. Detection that looked only at the top level would
    // miss every real certificate.
    assert.equal(env.schema_version, "certifieddata.manifest.v1");
    assert.equal(isCertV2(env), true);
});
test("isCertV2 rejects v1 and non-objects", () => {
    assert.equal(isCertV2({ schema_version: "cert.v1" }), false);
    assert.equal(isCertV2(null), false);
    assert.equal(isCertV2("cert.v2"), false);
});
// ── the real certificate ─────────────────────────────────────────────────────
test("verifies a real production cert.v2 certificate", async () => {
    const res = await verifyCertificateV2(await loadEnvelope(), await prodKeys());
    assert.equal(res.verdict, "VALID");
    assert.equal(res.checks.signature, "pass");
    assert.equal(res.checks.key_trust, "pass");
    assert.equal(res.key_id, "ed25519-prod-2025-02");
    assert.equal(res.certification_id, "d6da041f-a70c-4945-93b7-dff1e42a00d0");
});
// ── signature spellings ──────────────────────────────────────────────────────
//
// These are the regression tests for the bug that made the first cut of this
// feature useless: production serves `signature` as an OBJECT, and an
// implementation that required a base64 string reported MALFORMED on all 577
// issued certificates.
test('accepts the {alg, key_id, value} signature object that /signed-payload serves', async () => {
    const env = await loadEnvelope();
    assert.equal(typeof env.signature, "object", "fixture should carry the production object form");
    assert.ok(env.signature.value);
    const res = await verifyCertificateV2(env, await prodKeys());
    assert.equal(res.verdict, "VALID");
});
test('accepts the {alg, key_id, sig} signature object that /api/certificates/:id serves', async () => {
    const env = await loadEnvelope();
    const sig = env.signature;
    env.signature = { alg: sig.alg, key_id: sig.key_id, sig: sig.value };
    const res = await verifyCertificateV2(env, await prodKeys());
    assert.equal(res.verdict, "VALID");
});
test("accepts a bare base64 signature string", async () => {
    const env = await loadEnvelope();
    env.signature = env.signature.value;
    const res = await verifyCertificateV2(env, await prodKeys());
    assert.equal(res.verdict, "VALID");
});
test("refuses a v2 payload with no detached signature", async () => {
    const env = await loadEnvelope();
    delete env.signature;
    const res = await verifyCertificateV2(env, await prodKeys());
    assert.equal(res.verdict, "MALFORMED");
    assert.match(res.reason, /detached signature/);
});
test("refuses a signature object carrying no usable value", async () => {
    const env = await loadEnvelope();
    env.signature = { alg: "Ed25519", key_id: "ed25519-prod-2025-02" };
    const res = await verifyCertificateV2(env, await prodKeys());
    assert.equal(res.verdict, "MALFORMED");
    assert.match(res.reason, /detached signature/);
});
test("refuses a signature that is not 64 bytes", async () => {
    const env = await loadEnvelope();
    env.signature = Buffer.from("too short").toString("base64");
    const res = await verifyCertificateV2(env, await prodKeys());
    assert.equal(res.verdict, "MALFORMED");
    assert.match(res.reason, /64 bytes/);
});
// ── key selection is a security boundary ─────────────────────────────────────
test("selects the key named in the SIGNED payload, not the envelope", async () => {
    const env = await loadEnvelope();
    const sig = env.signature;
    // The envelope is not covered by the signature. If key selection trusted it,
    // an attacker could point verification at a key of their choosing.
    env.signature = { ...sig, key_id: "attacker-supplied-key" };
    const res = await verifyCertificateV2(env, await prodKeys());
    assert.equal(res.verdict, "MALFORMED");
    assert.match(res.reason, /envelope names key_id attacker-supplied-key/);
    assert.equal(res.checks.signature, "skipped");
});
test("tolerates the envelope omitting key_id entirely", async () => {
    const env = await loadEnvelope();
    const sig = env.signature;
    env.signature = { alg: sig.alg, value: sig.value };
    const res = await verifyCertificateV2(env, await prodKeys());
    assert.equal(res.verdict, "VALID");
});
// ── trust and revocation ─────────────────────────────────────────────────────
test("rejects an unknown signing key", async () => {
    const keys = { issuer: "CertifiedData.io", keys: [] };
    const res = await verifyCertificateV2(await loadEnvelope(), keys);
    assert.equal(res.verdict, "UNKNOWN_KEY");
    assert.equal(res.checks.signature, "skipped");
});
test("rejects a revoked signing key", async () => {
    const keys = await prodKeys();
    keys.keys[0].revoked_at = "2026-09-01T00:00:00Z";
    const res = await verifyCertificateV2(await loadEnvelope(), keys);
    assert.equal(res.verdict, "UNKNOWN_KEY");
    assert.match(res.reason, /revoked/);
});
test('accepts algorithm "Ed25519" as well as "ed25519"', async () => {
    const keys = await prodKeys();
    // This is how the issuer's own published keys document spells it. Returning
    // UNKNOWN_KEY on the capital E would be a security verdict for a cosmetic
    // difference.
    keys.keys[0].algorithm = "Ed25519";
    const res = await verifyCertificateV2(await loadEnvelope(), keys);
    assert.equal(res.verdict, "VALID");
});
test("rejects a key that is not ed25519 at all", async () => {
    const keys = await prodKeys();
    keys.keys[0].algorithm = "rsa";
    const res = await verifyCertificateV2(await loadEnvelope(), keys);
    assert.equal(res.verdict, "UNKNOWN_KEY");
    assert.match(res.reason, /not ed25519/);
});
// ── tamper detection ─────────────────────────────────────────────────────────
test("rejects a tampered v2 payload", async () => {
    const env = await loadEnvelope();
    env.payload.artifact_hash = "0".repeat(64);
    const res = await verifyCertificateV2(env, await prodKeys());
    assert.equal(res.verdict, "INVALID");
    assert.equal(res.checks.signature, "fail");
});
test("rejects a payload with a field appended", async () => {
    const env = await loadEnvelope();
    env.payload.injected = "not in the signed bytes";
    const res = await verifyCertificateV2(env, await prodKeys());
    assert.equal(res.verdict, "INVALID");
    assert.equal(res.checks.signature, "fail");
});
test("rejects a payload with a field removed", async () => {
    const env = await loadEnvelope();
    delete env.payload.certification_scope;
    const res = await verifyCertificateV2(env, await prodKeys());
    assert.equal(res.verdict, "INVALID");
});
// ── shape validation ─────────────────────────────────────────────────────────
test("reports a missing required field rather than failing the signature", async () => {
    const env = await loadEnvelope();
    delete env.payload.certificate_id;
    const res = await verifyCertificateV2(env, await prodKeys());
    assert.equal(res.verdict, "MALFORMED");
    assert.match(res.reason, /certificate_id/);
});
test("rejects a non-hex artifact_hash", async () => {
    const env = await loadEnvelope();
    env.payload.artifact_hash = "sha256:not-hex";
    const res = await verifyCertificateV2(env, await prodKeys());
    assert.equal(res.verdict, "MALFORMED");
    assert.match(res.reason, /64 hex/);
});
test("toEnvelope explains an unsupported schema rather than throwing", () => {
    const out = toEnvelope({ payload: { schema_version: "cert.v3" }, signature: "x".repeat(88) });
    assert.equal(typeof out, "string");
    assert.match(out, /unsupported schema_version: cert.v3/);
});
// ── dataset binding ──────────────────────────────────────────────────────────
test("--dataset mismatch is reported, not silently passed", async () => {
    const res = await verifyCertificateV2(await loadEnvelope(), await prodKeys(), join(fixtures, "prod-keys.json"));
    assert.equal(res.verdict, "DATASET_MISMATCH");
    assert.equal(res.checks.signature, "pass");
    assert.equal(res.checks.dataset_match, "fail");
});
//# sourceMappingURL=cert-v2.test.js.map