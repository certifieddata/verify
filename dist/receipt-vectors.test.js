/**
 * Receipt signature test vectors.
 *
 * These existed for webhook-signature, idempotency, provenance and events, but
 * not for receipts — so an outside implementer had nothing to check their
 * attempt against, and the canonicalization was never pinned to a concrete
 * expected hash anywhere in the repo.
 *
 * The tampered vector is the one that matters. An implementation that reports
 * VALID for it is not verifying anything: it has an Ed25519 signature that is
 * genuine, over a payload that has been altered.
 *
 * Fixtures are captured from production receipt
 * 2492a060-8fbc-40ae-beab-7258aefb0608 — a $0.99 certificate-linked dataset
 * purchase on the live rail.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { canonicalizeToBytes } from "./canonicalize.js";
const FIXTURES = join(import.meta.dirname ?? __dirname, "..", "fixtures");
function envelope(name) {
    return JSON.parse(readFileSync(join(FIXTURES, name), "utf8"));
}
const EXPECTED_HASH = "sha256:2e14cf92c38d5d0cf2b577c4736404fad1c1092c3c4ef87e3b4efeb3923dde22";
// ── canonicalization is pinned to a concrete expected hash ──
test("JCS(receipt) hashes to the published storedReceiptHash", () => {
    const env = envelope("valid-receipt.json");
    const bytes = canonicalizeToBytes(env.receipt);
    const hash = "sha256:" + createHash("sha256").update(bytes).digest("hex");
    assert.equal(hash, EXPECTED_HASH);
    assert.equal(hash, env.storedReceiptHash);
});
test("the canonical payload excludes signature and the appended crypto fields", () => {
    // Documented in RECEIPT-VERIFICATION.md §2. If any of these ever appear
    // inside `receipt`, the hash above stops reproducing and every external
    // verifier breaks at once.
    const env = envelope("valid-receipt.json");
    for (const k of ["signature", "sha256_hash", "ed25519_sig"]) {
        assert.ok(!Object.keys(env.receipt).includes(k));
    }
});
test("key ordering is what makes it canonical, not insertion order", () => {
    // Re-serialise with keys deliberately reversed; the digest must not move.
    const env = envelope("valid-receipt.json");
    const reversed = {};
    for (const k of Object.keys(env.receipt).reverse())
        reversed[k] = env.receipt[k];
    const a = createHash("sha256").update(canonicalizeToBytes(env.receipt)).digest("hex");
    const b = createHash("sha256").update(canonicalizeToBytes(reversed)).digest("hex");
    assert.equal(b, a);
});
// ── the tampered vector must not verify ──
test("altering amount changes the canonical hash", () => {
    const good = envelope("valid-receipt.json");
    const bad = envelope("tampered-receipt.json");
    // The signature is byte-identical — only the payload differs.
    assert.equal(bad.signature, good.signature);
    assert.notEqual(bad.receipt.amount, good.receipt.amount);
    const hash = "sha256:" + createHash("sha256")
        .update(canonicalizeToBytes(bad.receipt))
        .digest("hex");
    assert.notEqual(hash, EXPECTED_HASH);
});
// ── the live receipt carries the bindings the category depends on ──
const r = envelope("valid-receipt.json").receipt;
test("binds the artifact — the half authorization-only proofs scope out", () => {
    assert.match(r.artifact_hash, /^sha256:[0-9a-f]{64}$/);
    assert.ok(r.certificate_id);
});
test("binds the governing policy", () => {
    assert.match(r.policy_hash, /^sha256:[0-9a-f]{64}$/);
    assert.ok(r.policy_version);
});
test("states settlement rather than implying it", () => {
    assert.equal(r.settlement_state, "succeeded_live");
    assert.ok(r.settled_at);
});
test("keeps typed reference fields distinct and correctly prefixed", () => {
    // Receipt c2e70d98 held one PaymentIntent id in four fields, one of them a
    // charge field. Distinct, correctly-prefixed values are the fix.
    assert.match(r.external_payment_intent_id, /^pi_/);
    assert.match(r.external_charge_id, /^ch_/);
    assert.notEqual(r.external_charge_id, r.external_payment_intent_id);
    assert.equal(r.external_reference_type, "stripe_payment_intent");
});
test("carries no U+FFFD anywhere", () => {
    assert.ok(!JSON.stringify(r).includes("�"));
});
test("declares no integrity caveats", () => {
    // Absence means the pre-signature gate found nothing to declare.
    assert.equal(r.integrity_notes ?? null, null);
});
//# sourceMappingURL=receipt-vectors.test.js.map