// Receipt verification tests (verify#2 acceptance criteria).
//
// Real Ed25519 with a throwaway keypair, real RFC 8785 canonical bytes:
//   - a well-formed signed receipt verifies
//   - tampering with ANY signed field fails verification
//   - the server's booleans never influence the verdict
//   - stored-hash mismatch fails even when the signature would pass
//   - missing signature / wrong schema are MALFORMED, not INVALID
import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { canonicalizeToBytes } from "./canonicalize.js";
import { verifyReceiptEnvelope } from "./receipt.js";
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const BASE_PAYLOAD = {
    receipt_id: "46b93444-9ce0-49de-94e4-7a3c41ac8430",
    schema_version: "payment_receipt.v1",
    timestamp: "2026-08-20T03:03:23.461Z",
    issuer: "CertifiedData.io",
    agent_id: "demo0000-0000-0000-0000-000000000002",
    agent_name: "CertifiedData Demo Agent",
    rail: "stripe",
    currency: "usd",
    amount: 2900,
    status: "succeeded",
    settlement_state: "simulated_sandbox",
    purpose: "verify#2 test fixture",
    policy_id: "demo0000-0000-0000-0000-000000000003",
    policy_hash: "sha256:c220cd2760d84c4a58c59596cf5eb12662ce7f21d6196282be9fe9de31b7b7d7",
    artifact_hash: "sha256:75961ef7be87c6a3039544f64e1687e76637f26f2d6c0d5dd4d978e1495a5d66",
    transaction_id: "23b69400-e730-4340-ba4f-aadfc580b702",
};
function signedEnvelope(payload = BASE_PAYLOAD) {
    const bytes = canonicalizeToBytes(payload);
    const signatureB64 = cryptoSign(null, bytes, privateKey).toString("base64");
    const storedHash = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
    return { payload, signatureB64, storedHash };
}
test("a well-formed signed receipt verifies locally", () => {
    const r = verifyReceiptEnvelope(signedEnvelope(), publicKeyPem);
    assert.equal(r.verdict, "VALID");
    assert.equal(r.checks.signature, "pass");
    assert.equal(r.checks.key_trust, "pass");
    assert.equal(r.checks.payload_hash, "pass");
    assert.equal(r.artifact_type, "receipt");
    assert.equal(r.artifact_id, BASE_PAYLOAD.receipt_id);
});
// Acceptance: tampering with ANY signed receipt field fails verification.
const TAMPER_FIELDS = [
    ["amount", 29],
    ["policy_hash", "sha256:" + "0".repeat(64)],
    ["artifact_hash", "sha256:" + "f".repeat(64)],
    ["agent_id", "attacker-agent"],
    ["purpose", "forged purpose"],
    ["status", "succeeded_but_forged"],
    ["settlement_state", "settled"],
    ["timestamp", "2020-01-01T00:00:00.000Z"],
    ["receipt_id", "00000000-0000-0000-0000-000000000000"],
];
for (const [field, forged] of TAMPER_FIELDS) {
    test(`tampering with ${field} invalidates the receipt`, () => {
        const env = signedEnvelope();
        const tampered = { ...env, payload: { ...env.payload, [field]: forged } };
        const r = verifyReceiptEnvelope(tampered, publicKeyPem);
        assert.equal(r.verdict, "INVALID", `${field} tamper must fail`);
        assert.equal(r.checks.signature, "fail");
    });
}
test("server booleans are informational only — verdict is computed locally", () => {
    const env = signedEnvelope();
    const tampered = {
        ...env,
        payload: { ...env.payload, amount: 1 },
        // A lying server says everything is fine.
        serverReported: { valid: true, signatureValid: true, hashValid: true },
    };
    const r = verifyReceiptEnvelope(tampered, publicKeyPem);
    assert.equal(r.verdict, "INVALID");
    assert.deepEqual(r.server_reported, { valid: true, signatureValid: true, hashValid: true });
});
test("stored-hash mismatch fails even with a valid signature", () => {
    const env = signedEnvelope();
    const r = verifyReceiptEnvelope({ ...env, storedHash: "sha256:" + "9".repeat(64) }, publicKeyPem);
    assert.equal(r.verdict, "INVALID");
    assert.equal(r.checks.signature, "pass");
    assert.equal(r.checks.payload_hash, "fail");
});
test("missing signature is MALFORMED, not INVALID", () => {
    const env = signedEnvelope();
    const r = verifyReceiptEnvelope({ ...env, signatureB64: null }, publicKeyPem);
    assert.equal(r.verdict, "MALFORMED");
    assert.equal(r.checks.signature, "skipped");
});
test("wrong schema_version is MALFORMED", () => {
    const env = signedEnvelope({ ...BASE_PAYLOAD, schema_version: "payment_receipt.v2" });
    const r = verifyReceiptEnvelope(env, publicKeyPem);
    assert.equal(r.verdict, "MALFORMED");
});
test("a non-ed25519 published key is UNKNOWN_KEY, never a pass", () => {
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const rsaPem = rsa.publicKey.export({ type: "spki", format: "pem" }).toString();
    const r = verifyReceiptEnvelope(signedEnvelope(), rsaPem);
    assert.equal(r.verdict, "UNKNOWN_KEY");
    assert.equal(r.checks.key_trust, "fail");
});
// ── What the signature binds ─────────────────────────────────────────────────
//
// A receipt that reports nothing but "VALID" asks the reader to take the
// substance on trust, which is the opposite of the point. These assert that the
// identifiers and digests inside the signed payload are surfaced to the caller.
test("a verified receipt exposes the bindings the signature covers", () => {
    const r = verifyReceiptEnvelope(signedEnvelope(), publicKeyPem);
    assert.equal(r.verdict, "VALID");
    const b = r.bindings;
    assert.equal(b.policy_id, BASE_PAYLOAD.policy_id);
    assert.equal(b.policy_hash, BASE_PAYLOAD.policy_hash);
    assert.equal(b.artifact_hash, BASE_PAYLOAD.artifact_hash);
    assert.equal(b.transaction_id, BASE_PAYLOAD.transaction_id);
    assert.equal(b.agent_id, BASE_PAYLOAD.agent_id);
    assert.equal(b.rail, "stripe");
    assert.equal(b.status, "succeeded");
});
test("amount is read whether production sends a number or a string", () => {
    // Production emits `amount` as a STRING ("99"). The previous
    // `typeof p.amount === "number"` test silently dropped it, so every real
    // receipt verified with no amount displayed at all.
    const asNumber = verifyReceiptEnvelope(signedEnvelope(), publicKeyPem);
    assert.equal(asNumber.amount_cents, 2900);
    const asText = verifyReceiptEnvelope(signedEnvelope({ ...BASE_PAYLOAD, amount: "99" }), publicKeyPem);
    assert.equal(asText.verdict, "VALID");
    assert.equal(asText.amount_cents, 99);
});
test("a non-numeric amount is dropped rather than coerced to something wrong", () => {
    const r = verifyReceiptEnvelope(signedEnvelope({ ...BASE_PAYLOAD, amount: "not-a-number" }), publicKeyPem);
    assert.equal(r.amount_cents, null);
});
test("absent bindings are null rather than invented", () => {
    const sparse = { ...BASE_PAYLOAD };
    delete sparse.policy_hash;
    delete sparse.artifact_hash;
    const r = verifyReceiptEnvelope(signedEnvelope(sparse), publicKeyPem);
    assert.equal(r.verdict, "VALID");
    assert.equal(r.bindings.policy_hash, null);
    assert.equal(r.bindings.artifact_hash, null);
    // The ones that are present still come through.
    assert.equal(r.bindings.policy_id, BASE_PAYLOAD.policy_id);
});
test("bindings come from the payload that was actually verified", () => {
    // Tamper after signing: the verdict must fail, so nothing is reported as
    // bound by a signature that does not cover it.
    const env = signedEnvelope();
    env.payload.policy_hash = "sha256:" + "0".repeat(64);
    const r = verifyReceiptEnvelope(env, publicKeyPem);
    assert.equal(r.verdict, "INVALID");
    assert.equal(r.checks.signature, "fail");
});
//# sourceMappingURL=receipt.test.js.map