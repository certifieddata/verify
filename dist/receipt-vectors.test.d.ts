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
export {};
//# sourceMappingURL=receipt-vectors.test.d.ts.map