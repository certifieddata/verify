// Regenerates fixtures/*.json from a fresh Ed25519 keypair so reviewers can verify
// the verifier against real signatures rather than hand-edited blobs.
//
// Usage: node fixtures/generate.mjs
//
// This script is intentionally self-contained — it does not import from src/ so it
// can run before the package builds.

import { generateKeyPairSync, sign, createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

// --- minimal JCS canonicalizer (mirrors src/canonicalize.ts) ---
function canonicalize(v) {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "string") return jsString(v);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new RangeError("non-finite number");
    return Object.is(v, -0) ? "0" : JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
  if (typeof v === "object") {
    const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
    return "{" + keys.map((k) => jsString(k) + ":" + canonicalize(v[k])).join(",") + "}";
  }
  throw new TypeError("unsupported value");
}
function jsString(s) {
  let o = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) o += '\\"';
    else if (c === 0x5c) o += "\\\\";
    else if (c === 0x08) o += "\\b";
    else if (c === 0x09) o += "\\t";
    else if (c === 0x0a) o += "\\n";
    else if (c === 0x0c) o += "\\f";
    else if (c === 0x0d) o += "\\r";
    else if (c < 0x20) o += "\\u" + c.toString(16).padStart(4, "0");
    else o += s[i];
  }
  return o + '"';
}

// --- key generation ---
function rawEd25519PublicKey(publicKey) {
  // Strip the 12-byte SPKI prefix to get the raw 32-byte key, then base64-encode.
  const der = publicKey.export({ type: "spki", format: "der" });
  return Buffer.from(der.subarray(der.length - 32)).toString("base64");
}

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const keyId = "ck_2026_test_01";

// --- dataset fixture ---
const datasetCsv = "name,age,balance\nAlice,30,1000\nBob,25,2500\nCharlie,40,500\n";
writeFileSync(join(here, "valid-dataset.csv"), datasetCsv);
const datasetHex = createHash("sha256").update(datasetCsv).digest("hex");
const datasetHash = `sha256:${datasetHex}`;

// --- valid certificate ---
function signCert(unsigned) {
  const bytes = Buffer.from(canonicalize(unsigned), "utf8");
  const sig = sign(null, bytes, privateKey);
  return { ...unsigned, signature: sig.toString("base64") };
}

const validUnsigned = {
  certification_id: "ce_01HXYZTEST00000000000000",
  timestamp: "2026-03-18T20:31:45Z",
  issuer: "CertifiedData.io",
  dataset_hash: datasetHash,
  algorithm: "CTGAN",
  rows: 3,
  columns: 3,
  schema_version: "cert.v1",
  key_id: keyId,
  metadata: { description: "demo synthetic dataset for verifier fixtures" },
};

const valid = signCert(validUnsigned);
writeFileSync(join(here, "valid-cert.json"), JSON.stringify(valid, null, 2) + "\n");

// --- tampered certificate (signature does not verify) ---
const tampered = { ...valid, rows: 999999 };
writeFileSync(join(here, "tampered-cert.json"), JSON.stringify(tampered, null, 2) + "\n");

// --- unknown-key certificate (signed by a different key) ---
const otherKp = generateKeyPairSync("ed25519");
const unknownSigBytes = sign(null, Buffer.from(canonicalize({ ...validUnsigned, certification_id: "ce_unknown_key_demo" }), "utf8"), otherKp.privateKey);
const unknown = {
  ...validUnsigned,
  certification_id: "ce_unknown_key_demo",
  key_id: "ck_NOT_IN_TRUSTED_LIST",
  signature: unknownSigBytes.toString("base64"),
};
writeFileSync(join(here, "unknown-key-cert.json"), JSON.stringify(unknown, null, 2) + "\n");

// --- malformed certificate (missing field) ---
const malformed = { ...valid };
delete malformed.signature;
writeFileSync(join(here, "malformed-cert.json"), JSON.stringify(malformed, null, 2) + "\n");

// --- keys document ---
const keysDoc = {
  issuer: "CertifiedData.io",
  keys: [
    {
      key_id: keyId,
      public_key: rawEd25519PublicKey(publicKey),
      algorithm: "ed25519",
      created_at: "2026-01-01T00:00:00Z",
      label: "test-fixture",
    },
  ],
};
writeFileSync(join(here, "keys.json"), JSON.stringify(keysDoc, null, 2) + "\n");

console.log("fixtures regenerated:");
console.log("  keys.json                  ->", keyId);
console.log("  valid-cert.json            -> dataset_hash", datasetHash);
console.log("  tampered-cert.json         -> rows mutated to 999999");
console.log("  unknown-key-cert.json      -> key_id ck_NOT_IN_TRUSTED_LIST");
console.log("  malformed-cert.json        -> signature field removed");
console.log("  valid-dataset.csv          -> 3 rows × 3 columns");
