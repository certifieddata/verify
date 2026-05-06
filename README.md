# @certifieddata/verify

[![npm](https://img.shields.io/npm/v/@certifieddata/verify.svg)](https://www.npmjs.com/package/@certifieddata/verify)
[![CI](https://github.com/certifieddata/verify/actions/workflows/ci.yml/badge.svg)](https://github.com/certifieddata/verify/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/node/v/@certifieddata/verify.svg)](package.json)

> Verify CertifiedData.io certificates from the command line. Audit-friendly, zero crypto dependencies.

## Install + verify in three lines

```bash
npm install -g @certifieddata/verify
certifieddata-verify ce_01HXYZ123abc... --dataset path/to/data.csv
# → ✓ VALID  certification_id ce_01HXYZ123abc...
```

## What this verifies

- **The signature.** `cert.signature` is an Ed25519 signature over the RFC 8785 JCS canonicalization of the rest of the certificate. We re-canonicalize, re-verify, and refuse to claim a cert is valid unless the signature checks out.
- **The signer.** `cert.key_id` must appear in the issuer's published [`.well-known` keys document](https://certifieddata.io/.well-known/certifieddata-keys.json) and must not be revoked.
- **The dataset (optional).** When `--dataset <path>` is supplied, we stream-hash the file and refuse to claim a match unless its SHA-256 is bit-identical to `cert.dataset_hash`.

## Why audit-friendly

The whole verification routine lives in [`src/verify.ts`](src/verify.ts) — under 100 lines, no clever indirection, no third-party crypto. We use `node:crypto` directly:

```ts
const ok = crypto.verify('ed25519', canonicalBytes, publicKey, signatureBytes);
```

If you can read TypeScript, you can audit our verifier in five minutes.

## Exit codes

| Code | Verdict | Meaning |
|------|---------|---------|
| 0 | `VALID` | Signature verified and key is trusted (and dataset matches if `--dataset` was passed) |
| 1 | `INVALID` / `DATASET_MISMATCH` | Signature does not verify, or recomputed dataset hash differs |
| 2 | `UNKNOWN_KEY` | `key_id` is not in the trusted keys document, or has been revoked |
| 3 | `MALFORMED` | Certificate JSON is missing required fields, has bad base64, etc. |
| 4 | `NETWORK` | Could not reach the API or `.well-known` endpoint and no fresh cache is available |
| 64 | `USAGE` | Bad command-line flags |

## `--json` schema

```json
{
  "verdict": "VALID | INVALID | UNKNOWN_KEY | DATASET_MISMATCH | MALFORMED",
  "certification_id": "ce_...",
  "key_id": "ck_...",
  "issuer": "CertifiedData.io",
  "algorithm": "CTGAN",
  "signed_at": "2026-03-18T20:31:45Z",
  "dataset_hash_expected": "sha256:...",
  "dataset_hash_actual": "sha256:... | null",
  "checks": {
    "signature": "pass | fail | skipped",
    "key_trust": "pass | fail | skipped",
    "dataset_match": "pass | fail | skipped"
  },
  "reason": "human-readable explanation"
}
```

## Use in CI

```yaml
- name: Verify training-data certificate
  run: |
    npm install -g @certifieddata/verify
    certifieddata-verify "${{ env.TRAINING_CERT_ID }}" --dataset data/training.csv --json \
      | tee verify-result.json
- uses: actions/upload-artifact@v4
  with: { name: cert-verification, path: verify-result.json }
```

The non-zero exit codes fail the job automatically — a CI run will not pass if your training data has drifted from the cert.

## Offline / air-gapped audit

```bash
# Pre-stage a copy of the issuer's keys document, then verify with no network.
curl -O https://certifieddata.io/.well-known/certifieddata-keys.json
certifieddata-verify ./received-cert.json --keys ./certifieddata-keys.json --offline
```

`--offline` refuses to make any network call. Combined with `--keys`, it produces a fully reproducible audit you can replay months later.

## How CertifiedData certificates work

CertifiedData.io issues `cert.v1` documents that bind together:

1. A **dataset hash** — `sha256(file_bytes)` for binary data (CSV, Parquet) or `sha256(JCS(payload))` for structured data.
2. **Provenance** — the algorithm used, row/column counts, the issuance timestamp, and an opaque `certification_id`.
3. A **signer** — `key_id`, with the public key fetched from the issuer's `.well-known` endpoint.

The signature is computed over the RFC 8785 JCS canonicalization of the certificate **with the `signature` field omitted** — this is the only sane way to sign a JSON document and have it round-trip through arbitrary JSON parsers.

We use Ed25519 because it is fast, deterministic, has small keys (32 bytes) and small signatures (64 bytes), and is built into Node's `crypto` module. We never sign the field that contains the signature, and we never claim a verdict beyond what the cert actually says — for example, we will not call a CTGAN cert "differentially private" unless the metadata explicitly carries a non-null `epsilon` and the algorithm is `DP-CTGAN`.

## Reporting vulnerabilities

See [SECURITY.md](SECURITY.md). Please do not open a public issue for cryptographic findings — email `security@certifieddata.io` and we will respond within 48 hours.

## Related projects

- [`@certifieddata/pii-scan`](https://github.com/certifieddata/pii-scan) — scan datasets for PII before certifying them
- [`certifieddata/reference-impl`](https://github.com/certifieddata/reference-impl) — a 50-line EU AI Act Article 12 reference application that uses this CLI

## License

MIT — see [LICENSE](LICENSE).
