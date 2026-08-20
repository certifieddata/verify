# Receipt verification — normative specification

This document specifies how to verify a CertifiedData Agent Commerce payment
receipt **without trusting CertifiedData**. It exists because the platform docs
referred to "SHA-256 of the canonical receipt payload" in several places without
ever defining *canonical*, leaving an outside implementer unable to reproduce
the hash and with no vectors to check an attempt against.

Everything here is exercised by `src/receipt.test.ts` against the fixtures in
`fixtures/`, and the worked example below is a real live receipt.

---

## 1. The trust boundary

A receipt is verifiable from two inputs:

| Input | Where from | Trust required |
|---|---|---|
| The receipt envelope | `GET /api/payments/verify/{id}` | none — tampering is detected by the signature |
| The Ed25519 public key | `GET /.well-known/certifieddata-public-key.pem` | that this key belongs to CertifiedData |

The endpoint also returns `valid`, `hashValid` and `signatureValid`. **These are
the server's opinion about its own signature and are not evidence.** A verifier
must ignore them and compute its own verdict. They are useful only as a
cross-check: if your verdict disagrees with the server's, one of you has a bug.

If the public key cannot be fetched, that is a distinct outcome (`UNKNOWN_KEY`
/ `NETWORK`). It must never degrade into accepting the server's booleans.

---

## 2. The canonical payload

The signed object is the value of the envelope's `receipt` field, exactly as
returned, with **no** fields added or removed.

Three fields are commonly mistaken for part of it:

- `signature` — sits at the envelope level, not inside `receipt`. It cannot be
  part of the payload it signs.
- `sha256_hash`, `ed25519_sig` — appended by `POST /v1/transactions/{id}/capture`
  to its inline receipt object for convenience. They are **not** part of the
  canonical payload. If you are verifying a capture response rather than the
  verify endpoint, remove them first. The verify endpoint does not include them.

Producer-side note: the platform applies a `stripUndefined()` pass before
canonicalizing. This has no effect on a consumer, because JSON has no
`undefined` — a key is either present or absent. It is documented only so the
two implementations can be compared line by line.

---

## 3. Canonicalization: RFC 8785 (JCS)

**Serialize the canonical payload per [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785),
the JSON Canonicalization Scheme**, then encode as UTF-8.

This settles an ambiguity that existed in the public docs. It is RFC 8785 JCS —
*not* `json-stable-stringify`. They agree on key ordering for simple documents
and disagree on string escaping and number formatting, so they can produce
different bytes and therefore different hashes.

The rules that matter for receipt payloads:

- Object keys sorted ascending by **UTF-16 code unit** sequence.
- Array order preserved.
- No insignificant whitespace.
- Strings use the minimal RFC 8259 §7 escapes (`"`, `\`, `\b`, `\f`, `\n`,
  `\r`, `\t`), and `\u00XX` for other control characters `U+0000`–`U+001F`.
  Non-ASCII characters are emitted literally, not `\u`-escaped.
- Numbers use the ECMAScript `Number::toString` algorithm — what
  `JSON.stringify` already emits for finite numbers. `NaN` and `±Infinity` must
  not appear.

`src/canonicalize.ts` is a dependency-free implementation, written by hand so a
reviewer can confirm there is no surprising behavior.

---

## 4. The two checks

Let `C` be the canonical UTF-8 bytes from §3.

**Hash.** `sha256(C)`, hex-encoded, prefixed `sha256:`, must equal the
envelope's `storedReceiptHash`.

**Signature.** The envelope's `signature` is base64. Decoded it is exactly 64
bytes. It is an Ed25519 signature over `C` — over the canonical bytes directly,
with no pre-hashing (Ed25519 hashes internally; do not pass the digest).

Verify against the SPKI public key from the PEM. A receipt is `VALID` only if
both checks pass.

---

## 5. Worked example — a real live receipt

Receipt `2492a060-8fbc-40ae-beab-7258aefb0608`, a $0.99 certificate-linked
dataset purchase on the live rail, captured 2026-08-20:

```
signing key         ed25519-prod-2025-02
canonicalization    RFC8785-JCS
storedReceiptHash   sha256:2e14cf92c38d5d0cf2b577c4736404fad1c1092c3c4ef87e3b4efeb3923dde22
settlement_state    succeeded_live
artifact_hash       sha256:bd48985485c9a3e19838e29795bb89ddedd7f7e5c706b57c190cc6c46119a660
certificate_id      fb914a90-b1b3-4355-8147-cc0194160e23
```

The `artifact_hash` is the SHA-256 of the delivered ZIP, and it is also the
digest inside certificate `fb914a90-…`. A buyer can therefore chain:
downloaded bytes → hash → certificate → receipt, with no step requiring
CertifiedData's word.

Note the key id: **`ed25519-prod-2025-02`**. Some older documentation shows
`cd_root_2026`, which is not the key live receipts are signed with.

### Reproduce it

```bash
npx @certifieddata/verify 2492a060-8fbc-40ae-beab-7258aefb0608 --type receipt
```

Expected:

```
✓ VALID  receipt 2492a060-8fbc-40ae-beab-7258aefb0608
  signature    pass
  payload hash pass
  settlement   succeeded_live
  The verdict above was computed locally — not taken from the server.
```

---

## 6. Test vectors

In `fixtures/`:

| File | Expected verdict | What it exercises |
|---|---|---|
| `valid-receipt.json` | `VALID` | the happy path, captured from production |
| `tampered-receipt.json` | `INVALID` | `receipt.amount` altered, signature untouched — proves the signature actually covers the payload |
| `malformed-receipt.json` | `MALFORMED` | signature is not a 64-byte Ed25519 value |

With the repo checked out:

```bash
npx github:certifieddata/verify fixtures/valid-receipt.json    --type receipt   # VALID
npx github:certifieddata/verify fixtures/tampered-receipt.json --type receipt   # INVALID
```

Without checking anything out — pipe the fixture in on stdin:

```bash
curl -s https://raw.githubusercontent.com/certifieddata/verify/main/fixtures/tampered-receipt.json \
  | npx github:certifieddata/verify - --type receipt
# → ✗ INVALID  ed25519 signature does not verify against the RFC 8785 canonical payload
```

The tampered vector is the important one: an implementation that reports `VALID`
for it is not verifying anything.

### Accepted inputs

| Form | Receipts | Certificates |
|---|---|---|
| bare UUID | yes — fetched from the public verify endpoint | yes |
| local file path | yes | yes |
| `-` (stdin) | yes | yes |
| `https://…` URL | **no** — treated as a file path | yes |

URL input is certificate-only today. For a remote receipt, use the UUID form or
pipe it in on stdin.

---

## 7. Minimal implementation

Roughly 90 lines, Node built-ins only, for implementers who would rather not
take a dependency — including on this package:

```js
const BASE = "https://certifieddata.io";

function jcs(v) {
  if (v === null || typeof v === "boolean" || typeof v === "number") return JSON.stringify(v);
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
}

const env = await (await fetch(`${BASE}/api/payments/verify/${id}`)).json();
const bytes = Buffer.from(jcs(env.receipt), "utf8");

const hash = "sha256:" + Buffer.from(
  await crypto.subtle.digest("SHA-256", bytes)).toString("hex");
const hashOk = hash === env.storedReceiptHash;

const pem = (await (await fetch(`${BASE}/.well-known/certifieddata-public-key.pem`)).text()).trim();
const der = Buffer.from(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
const key = await crypto.subtle.importKey("spki", der, { name: "Ed25519" }, false, ["verify"]);
const sigOk = await crypto.subtle.verify(
  "Ed25519", key, Buffer.from(env.signature, "base64"), bytes);

console.log(hashOk && sigOk ? "VALID" : "INVALID");
```

The string-escaping shortcut above (`JSON.stringify` for strings) is JCS-correct
for the ASCII content receipts carry today. Use `src/canonicalize.ts` for a
fully general implementation.

---

## 8. What a receipt does and does not prove

**Proves.** A specific agent was authorized under a named policy
(`policy_hash`, `policy_version`) to spend a specific amount on a specific
rail; that the charge reached a terminal settlement state
(`settlement_state`, `settled_at`, `external_payment_intent_id`,
`external_charge_id`); and, when `artifact_hash` is present, precisely which
artifact the payment was for.

**Does not prove.** That the artifact was delivered, or that the buyer received
it. Delivery is a separate signed record.

**`integrity_notes`.** When present, the issuer is stating that a binding this
receipt would normally carry is absent, and why. Its absence means the
pre-signature gate found nothing to declare — not that no check ran. Receipts
signed before the gate existed carry neither notes nor the bindings, and are
annotated by separate append-only records rather than edited: receipts are
immutable, and corrections are new records.
