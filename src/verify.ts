// Core verification path. Read top-to-bottom — there is no clever indirection.
//   1. Validate certificate shape.
//   2. Look up cert.key_id in the trusted keys document; reject if missing/revoked.
//   3. Build the canonical payload (cert minus signature) per RFC 8785 JCS.
//   4. crypto.verify('ed25519', canonicalBytes, publicKey, signatureBytes).
//   5. If a dataset path was supplied, recompute SHA-256 and compare to dataset_hash.

import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { canonicalizeToBytes } from "./canonicalize.js";
import { sha256File, formatDigest, parseDigest } from "./hash.js";
import { findKey } from "./keys.js";
import { REQUIRED_CERT_FIELDS } from "./types.js";
import type { Certificate, KeyDoc, VerifyResult } from "./types.js";

export async function verifyCertificate(
  cert: Certificate,
  trustedKeys: KeyDoc,
  datasetPath?: string,
): Promise<VerifyResult> {
  const result = blankResult(cert);

  const shapeError = validateShape(cert);
  if (shapeError) return finish(result, "MALFORMED", shapeError);

  result.certification_id = cert.certification_id;
  result.key_id = cert.key_id;
  result.issuer = cert.issuer;
  result.algorithm = cert.algorithm;
  result.signed_at = cert.timestamp;
  result.dataset_hash_expected = cert.dataset_hash;
  result.rows = cert.rows;
  result.columns = cert.columns;

  const key = findKey(trustedKeys, cert.key_id);
  if (!key || key.revoked_at || key.algorithm !== "ed25519") {
    result.checks.key_trust = "fail";
    const reason = !key
      ? `key_id ${cert.key_id} not in trusted keys`
      : key.revoked_at
        ? `key_id ${cert.key_id} was revoked at ${key.revoked_at}`
        : `key ${cert.key_id} is not ed25519`;
    return finish(result, "UNKNOWN_KEY", reason);
  }
  result.checks.key_trust = "pass";
  result.key_label = key.label;

  const { signature: _sig, ...withoutSig } = cert;
  const canonicalBytes = canonicalizeToBytes(withoutSig);
  const sigBytes = decodeSignature(cert.signature);
  if (!sigBytes) return finish(result, "MALFORMED", "signature is not valid base64");
  const publicKey = createPublicKey({ key: pemFromRawEd25519(key.public_key), format: "pem" });
  const sigOk = cryptoVerify(null, canonicalBytes, publicKey, sigBytes);
  result.checks.signature = sigOk ? "pass" : "fail";
  if (!sigOk) return finish(result, "INVALID", "ed25519 signature does not verify against canonicalized payload");

  if (datasetPath) {
    const actualHex = await sha256File(datasetPath);
    const actual = formatDigest(actualHex);
    result.dataset_hash_actual = actual;
    const expected = parseDigest(cert.dataset_hash);
    if (expected.algo !== "sha256" || expected.hex !== actualHex) {
      result.checks.dataset_match = "fail";
      return finish(result, "DATASET_MISMATCH", `dataset hash mismatch (expected ${cert.dataset_hash}, got ${actual})`);
    }
    result.checks.dataset_match = "pass";
  }

  return finish(result, "VALID", "signature verified and key is trusted");
}

function validateShape(c: Certificate): string | null {
  if (!c || typeof c !== "object") return "certificate is not an object";
  for (const f of REQUIRED_CERT_FIELDS) if (c[f] === undefined || c[f] === null) return `missing required field: ${f}`;
  if (c.schema_version !== "cert.v1") return `unsupported schema_version: ${c.schema_version}`;
  if (!/^sha256:[0-9a-f]{64}$/i.test(c.dataset_hash)) return "dataset_hash must be sha256:<64-hex>";
  if (typeof c.rows !== "number" || typeof c.columns !== "number") return "rows and columns must be numbers";
  return null;
}

function decodeSignature(b64: string): Buffer | null {
  try {
    const buf = Buffer.from(b64, "base64");
    if (buf.length !== 64) return null;
    return buf;
  } catch { return null; }
}

function pemFromRawEd25519(material: string): string {
  if (material.includes("BEGIN PUBLIC KEY")) return material;
  // Wrap a base64 raw 32-byte Ed25519 public key in the standard SPKI prefix.
  const raw = Buffer.from(material, "base64");
  if (raw.length !== 32) throw new Error(`expected 32-byte ed25519 key, got ${raw.length}`);
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const der = Buffer.concat([spkiPrefix, raw]).toString("base64");
  return `-----BEGIN PUBLIC KEY-----\n${der.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----\n`;
}

function blankResult(cert: Partial<Certificate>): VerifyResult {
  return {
    verdict: "MALFORMED",
    certification_id: (cert.certification_id as string) ?? null,
    key_id: (cert.key_id as string) ?? null,
    issuer: (cert.issuer as string) ?? null,
    algorithm: (cert.algorithm as string) ?? null,
    signed_at: (cert.timestamp as string) ?? null,
    dataset_hash_expected: (cert.dataset_hash as string) ?? null,
    dataset_hash_actual: null,
    checks: { signature: "skipped", key_trust: "skipped", dataset_match: "skipped" },
    reason: "",
  };
}

function finish(r: VerifyResult, verdict: VerifyResult["verdict"], reason: string): VerifyResult {
  r.verdict = verdict;
  r.reason = reason;
  return r;
}
