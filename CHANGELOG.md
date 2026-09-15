# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-09-15

### Added

- Verified receipts now report **what the signature binds**, not just that it is
  valid. A receipt that says nothing but `VALID` asks the reader to take the
  substance on trust, which is the opposite of the point of an independent
  verifier. The output now lists the amount, settlement state and time, rail,
  purpose, agent, policy id and policy hash, authorization id, decision record
  id, artifact hash, certificate id, transaction id and payment reference —
  each read from the payload that just passed both the signature and
  payload-hash checks, so nothing is shown as covered by a signature that does
  not cover it.
- `bindings` on `ReceiptVerifyResult`, so library consumers get the same fields
  programmatically rather than re-parsing the payload.

### Fixed

- **The amount was silently dropped on every real receipt.** Production emits
  `amount` as a string (`"99"`); the code tested `typeof p.amount === "number"`
  and so reported no amount at all. Both forms are now accepted, and a
  non-numeric value is dropped rather than coerced into something wrong.

## [0.1.0] - 2026-09-07

### Added

- Initial public release of `@certifieddata/verify`.
- `certifieddata-verify` and `cd-verify` binaries.
- RFC 8785 JCS canonicalizer (`canonicalize.ts`).
- Ed25519 signature verification using `node:crypto` only — zero third-party crypto dependencies.
- `cert.v1` schema support.
- `cert.v2` schema support (`cert-v2.ts`) — the schema production has issued
  since 2026-02. v2 differs from v1 in three ways that matter: the signature is
  detached rather than a field inside the signed document (so the whole payload
  is canonicalized, with nothing stripped), the signer is named at
  `payload.issuer.signing_key_id`, and the artifact digest is bare hex at
  `payload.artifact_hash`. Signed bytes are Ed25519 over JCS of the payload,
  confirmed empirically against the live production certificate committed as
  `fixtures/valid-cert-v2.json`.
- Payment receipt verification against the published Agent Commerce key.
- `--dataset`, `--json`, `--offline`, `--keys`, `--no-cache` flags.
- Trusted-keys document fetched from the issuer's `.well-known` signing-keys
  document, with TTL cache at `~/.certifieddata/keys.json`.
- Six exit codes documented in the README and `--help`.
- 93 tests across canonicalize, verify, cert-v2, receipt, exit-code and CLI suites.

### Fixed

- **The certificate path could not verify any production certificate.** Two
  independent causes, both addressed here:
  - Every issued certificate is `cert.v2`; the verifier implemented only
    `cert.v1` and rejected v2 as `MALFORMED` on a missing `certification_id`
    (v2 names it `certificate_id`).
  - The pinned keys URL was `/.well-known/certifieddata-keys.json`, which
    returns 404 and was never deployed, so verification exited `NETWORK` before
    reaching the signature. It now points at
    `/.well-known/signing-keys.json` — the document the issuer actually
    publishes and that every certificate's own `public_key_url` references.
- Resolving a bare certificate id now fetches `…/signed-payload` rather than
  the plain `…/api/certificates/<id>` projection. The projection carries the
  real signature bytes but the signature covers the v2 payload, not the
  projection, so verifying it reported `INVALID` on untampered certificates.
- The keys-document parser accepts both published dialects
  (`public_key` / `public_key_pem`, per-key `revoked_at` / top-level
  `revoked[]` and `retired[]`, CRLF in PEM bodies) and compares `algorithm`
  case-insensitively. Previously an `algorithm` of `"Ed25519"` — the spelling
  the issuer publishes — yielded `UNKNOWN_KEY`, a security verdict, for a
  difference of one capital letter. A revocation entry that cannot be parsed is
  now an error rather than being skipped, so an unreadable revocation record can
  never be mistaken for a good key.
- Human output no longer prints `0 rows × 0 cols` for `cert.v2`, which has no
  column count.
