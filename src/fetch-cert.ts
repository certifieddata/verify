import { readFile } from "node:fs/promises";
import type { Certificate } from "./types.js";

export const DEFAULT_CERT_API = "https://certifieddata.io/api/v1/certificates";

export interface FetchCertOptions {
  apiBase?: string;
  offline?: boolean;
}

export async function fetchCert(idOrPathOrUrl: string, opts: FetchCertOptions = {}): Promise<Certificate> {
  if (idOrPathOrUrl === "-") {
    return parseCertJson(await readStdin());
  }
  if (idOrPathOrUrl.endsWith(".json") || idOrPathOrUrl.startsWith("./") || idOrPathOrUrl.startsWith("/")) {
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
  const url = `${base.replace(/\/$/, "")}/${encodeURIComponent(idOrPathOrUrl)}`;
  return parseCertJson(await fetchText(url));
}

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status} fetching ${url}`);
  return res.text();
}

function parseCertJson(body: string): Certificate {
  return JSON.parse(body) as Certificate;
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}
