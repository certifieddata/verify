import { readFile } from "node:fs/promises";

/**
 * Resolving a bare certificate id must land on bytes that are actually
 * verifiable.
 *
 * `https://certifieddata.io/api/v1/certificates/:id` — the path this used to
 * point at — returns 404; it was never deployed.
 *
 * `https://api.certifieddata.io/api/certificates/:id` does respond, but it
 * serves a cert.v1-shaped *display projection* of a cert.v2 certificate. It
 * carries the real signature bytes while the signature covers the v2 payload,
 * not the projection, so verifying that document yields INVALID — which reads
 * as tampering when nothing has been tampered with.
 *
 * `/signed-payload` is the envelope whose signature verifies over its own
 * payload, so that is what a verifier has to ask for.
 */
export const DEFAULT_CERT_API = "https://api.certifieddata.io/api/certificates";
export const CERT_ENVELOPE_SUFFIX = "/signed-payload";

export interface FetchCertOptions {
  apiBase?: string;
  offline?: boolean;
}

/**
 * Returns the raw certificate document. Shape validation belongs to the
 * verifier, not the fetcher: the document may be a cert.v1 certificate or a
 * cert.v2 envelope, and deciding which is the caller's job.
 */
export async function fetchCert(
  idOrPathOrUrl: string,
  opts: FetchCertOptions = {},
): Promise<Record<string, unknown>> {
  if (idOrPathOrUrl === "-") {
    return parseCertJson(await readStdin());
  }
  if (
    idOrPathOrUrl.endsWith(".json") ||
    idOrPathOrUrl.startsWith("./") ||
    idOrPathOrUrl.startsWith("/")
  ) {
    return parseCertJson(await readFile(idOrPathOrUrl, "utf8"));
  }
  if (/^https?:\/\//.test(idOrPathOrUrl)) {
    if (opts.offline) throw new Error("cannot fetch URL in --offline mode");
    return parseCertJson(await fetchText(idOrPathOrUrl));
  }
  if (opts.offline) {
    throw new Error("cannot resolve certification id in --offline mode (pass a local file)");
  }
  const base = opts.apiBase ?? DEFAULT_CERT_API;
  const url = `${base.replace(/\/$/, "")}/${encodeURIComponent(idOrPathOrUrl)}${CERT_ENVELOPE_SUFFIX}`;
  return parseCertJson(await fetchText(url));
}

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status} fetching ${url}`);
  return res.text();
}

function parseCertJson(body: string): Record<string, unknown> {
  return JSON.parse(body) as Record<string, unknown>;
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : (chunk as Buffer));
  }
  return Buffer.concat(chunks).toString("utf8");
}
