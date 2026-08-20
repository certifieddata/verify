// Agent Commerce receipt verification (verify#2).
//
// Same philosophy as verify.ts, one more artifact type:
//   1. Fetch the receipt payload + signature from the public verify endpoint
//      (or read a local JSON file / stdin).
//   2. Fetch the Agent Commerce public key PEM from .well-known — a DIFFERENT
//      trust root from the certificate keys document, on purpose.
//   3. RFC 8785 JCS-canonicalize the payload (signature excluded — the
//      platform stores the payload without it) and verify Ed25519 locally.
//   4. Recompute SHA-256 over the same canonical bytes and compare to the
//      stored receipt hash when one is exposed.
//
// The server's valid / signatureValid booleans are surfaced as INFORMATIONAL
// metadata only — they never determine the verdict. If the public key cannot
// be fetched, that is a distinct non-success outcome, never a silent
// fallback to the server's opinion.

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { readFile } from "node:fs/promises";
import { canonicalizeToBytes } from "./canonicalize.js";
import type { CheckResult } from "./types.js";

export const DEFAULT_RECEIPT_API = "https://certifieddata.io/api/payments/verify";
export const DEFAULT_RECEIPT_KEY_URL =
  "https://certifieddata.io/.well-known/certifieddata-public-key.pem";

export type ReceiptVerdict = "VALID" | "INVALID" | "UNKNOWN_KEY" | "MALFORMED";

export interface ReceiptVerifyResult {
  artifact_type: "receipt";
  artifact_id: string | null;
  verdict: ReceiptVerdict;
  key_id: string | null;
  issuer: string | null;
  signed_at: string | null;
  checks: {
    signature: CheckResult;
    key_trust: CheckResult;
    payload_hash: CheckResult;
  };
  reason: string;
  /** The server's own booleans, informational only — never the verdict. */
  server_reported?: { valid?: boolean; signatureValid?: boolean; hashValid?: boolean };
  settlement_state?: string | null;
  amount_cents?: number | null;
  currency?: string | null;
}

interface ReceiptEnvelope {
  payload: Record<string, unknown>;
  signatureB64: string | null;
  storedHash: string | null;
  serverReported?: { valid?: boolean; signatureValid?: boolean; hashValid?: boolean };
}

export interface FetchReceiptOptions {
  apiBase?: string;
  offline?: boolean;
}

/** Accepts a receipt id, a /api/payments/verify URL, a local .json path, or "-". */
export async function fetchReceipt(
  idOrPathOrUrl: string,
  opts: FetchReceiptOptions = {},
): Promise<ReceiptEnvelope> {
  if (idOrPathOrUrl === "-") return parseEnvelope(await readStdin());
  if (
    idOrPathOrUrl.endsWith(".json") ||
    idOrPathOrUrl.startsWith("./") ||
    idOrPathOrUrl.startsWith("/") ||
    /^[A-Za-z]:[\\/]/.test(idOrPathOrUrl)
  ) {
    return parseEnvelope(await readFile(idOrPathOrUrl, "utf8"));
  }
  if (opts.offline) {
    throw new Error("cannot resolve a receipt id in --offline mode (pass a local file)");
  }
  const url = /^https?:\/\//.test(idOrPathOrUrl)
    ? idOrPathOrUrl
    : `${(opts.apiBase ?? DEFAULT_RECEIPT_API).replace(/\/$/, "")}/${encodeURIComponent(idOrPathOrUrl)}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status} fetching ${url}`);
  return parseEnvelope(await res.text());
}

function parseEnvelope(body: string): ReceiptEnvelope {
  const parsed = JSON.parse(body) as Record<string, unknown>;
  // Server envelope: { receipt: {...}, signature, storedReceiptHash, valid... }
  if (parsed.receipt && typeof parsed.receipt === "object") {
    return {
      payload: parsed.receipt as Record<string, unknown>,
      signatureB64: typeof parsed.signature === "string" ? parsed.signature : null,
      storedHash:
        typeof parsed.storedReceiptHash === "string" ? parsed.storedReceiptHash : null,
      serverReported: {
        valid: typeof parsed.valid === "boolean" ? parsed.valid : undefined,
        signatureValid:
          typeof parsed.signatureValid === "boolean" ? parsed.signatureValid : undefined,
        hashValid: typeof parsed.hashValid === "boolean" ? parsed.hashValid : undefined,
      },
    };
  }
  // Bare payload with an embedded signature (local file usage).
  if (parsed.schema_version === "payment_receipt.v1") {
    const { signature, ...payload } = parsed as { signature?: string } & Record<string, unknown>;
    return { payload, signatureB64: signature ?? null, storedHash: null };
  }
  throw new Error("input is neither a verify-endpoint envelope nor a payment_receipt.v1 payload");
}

export interface LoadReceiptKeyOptions {
  keyUrl?: string;
  keyFile?: string;
  offline?: boolean;
}

/**
 * Loads the Agent Commerce public key PEM. Fails loudly — a 503 here means
 * the issuer is misconfigured, and the CLI's answer is "cannot verify
 * independently", never "let the server vouch for itself".
 */
export async function loadReceiptKey(opts: LoadReceiptKeyOptions = {}): Promise<string> {
  if (opts.keyFile) return readFile(opts.keyFile, "utf8");
  if (opts.offline) {
    throw new Error("offline receipt verification requires --key <pem-file>");
  }
  const url = opts.keyUrl ?? DEFAULT_RECEIPT_KEY_URL;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(
      `public key unavailable (HTTP ${res.status} from ${url}) — cannot verify independently`,
    );
  }
  const pem = await res.text();
  if (!pem.includes("BEGIN PUBLIC KEY")) {
    throw new Error(`response from ${url} is not a PEM public key`);
  }
  return pem;
}

export function verifyReceiptEnvelope(
  env: ReceiptEnvelope,
  publicKeyPem: string,
): ReceiptVerifyResult {
  const p = env.payload as Record<string, unknown>;
  const result: ReceiptVerifyResult = {
    artifact_type: "receipt",
    artifact_id: typeof p.receipt_id === "string" ? p.receipt_id : null,
    verdict: "MALFORMED",
    key_id: null,
    issuer: typeof p.issuer === "string" ? p.issuer : null,
    signed_at: typeof p.timestamp === "string" ? p.timestamp : null,
    checks: { signature: "skipped", key_trust: "skipped", payload_hash: "skipped" },
    reason: "",
    server_reported: env.serverReported,
    settlement_state: typeof p.settlement_state === "string" ? p.settlement_state : null,
    amount_cents: typeof p.amount === "number" ? p.amount : null,
    currency: typeof p.currency === "string" ? p.currency : null,
  };

  if (p.schema_version !== "payment_receipt.v1") {
    result.reason = `unsupported schema_version: ${String(p.schema_version)}`;
    return result;
  }
  if (!env.signatureB64) {
    result.reason =
      "no signature present — the verify endpoint predates signature exposure, or the local file omitted it";
    return result;
  }

  let publicKey;
  try {
    publicKey = createPublicKey({ key: publicKeyPem, format: "pem" });
    if (publicKey.asymmetricKeyType !== "ed25519") {
      result.checks.key_trust = "fail";
      result.verdict = "UNKNOWN_KEY";
      result.reason = `published key is ${publicKey.asymmetricKeyType}, expected ed25519`;
      return result;
    }
  } catch (e) {
    result.checks.key_trust = "fail";
    result.verdict = "UNKNOWN_KEY";
    result.reason = `cannot parse published public key: ${(e as Error).message}`;
    return result;
  }
  result.checks.key_trust = "pass";

  let sigBytes: Buffer;
  try {
    sigBytes = Buffer.from(env.signatureB64, "base64");
    if (sigBytes.length !== 64) throw new Error(`expected 64 bytes, got ${sigBytes.length}`);
  } catch (e) {
    result.reason = `signature is not valid base64 ed25519: ${(e as Error).message}`;
    return result;
  }

  // The platform signs canonicalize(payload) where payload never contained a
  // signature field; strip defensively for local files.
  const { signature: _drop, ...withoutSig } = env.payload as { signature?: string } & Record<string, unknown>;
  const canonicalBytes = canonicalizeToBytes(withoutSig);

  const sigOk = cryptoVerify(null, canonicalBytes, publicKey, sigBytes);
  result.checks.signature = sigOk ? "pass" : "fail";
  if (!sigOk) {
    result.verdict = "INVALID";
    result.reason = "ed25519 signature does not verify against the RFC 8785 canonical payload";
    return result;
  }

  if (env.storedHash) {
    const recomputed = `sha256:${createHash("sha256").update(canonicalBytes).digest("hex")}`;
    const match = recomputed === env.storedHash;
    result.checks.payload_hash = match ? "pass" : "fail";
    if (!match) {
      result.verdict = "INVALID";
      result.reason = `stored receipt hash ${env.storedHash} does not match locally recomputed ${recomputed}`;
      return result;
    }
  }

  // Key id is reported from the envelope's metadata when present; trust came
  // from the .well-known fetch, not from this label.
  const keyIdMeta = (env as { keyId?: unknown }).keyId;
  result.key_id = typeof keyIdMeta === "string" ? keyIdMeta : result.key_id;
  result.verdict = "VALID";
  result.reason = "ed25519 signature verified locally against the published Agent Commerce key";
  return result;
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : (chunk as Buffer));
  }
  return Buffer.concat(chunks).toString("utf8");
}
