# Test fixtures

These files are committed so reviewers can verify the verifier without
trusting a pre-built artifact. They are produced by `generate.mjs`,
which:

1. Generates a fresh Ed25519 keypair via `node:crypto`.
2. Hashes a tiny CSV dataset.
3. Signs a `cert.v1` certificate over its JCS canonicalization (with
   the `signature` field omitted).
4. Writes the corresponding `keys.json`, plus three failure-case
   certs: tampered, unknown-key, malformed.

Regenerate with:

```bash
npm run fixtures
```

After regeneration, all three CLI tests should still pass — the test
script depends only on the structural shape of the fixtures, not the
specific key material.

## Files

| File | Purpose | Expected verdict |
|---|---|---|
| `valid-cert.json` | Cleanly-signed demo cert | `VALID` |
| `tampered-cert.json` | `rows` mutated post-signature | `INVALID` |
| `unknown-key-cert.json` | Signed by a key not in `keys.json` | `UNKNOWN_KEY` |
| `malformed-cert.json` | `signature` field removed | `MALFORMED` |
| `keys.json` | Trusted-keys document for the test issuer | — |
| `valid-dataset.csv` | The dataset hashed into `valid-cert.json` | — |
