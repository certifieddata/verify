import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";

export function sha256Hex(bytes: Uint8Array | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export async function sha256File(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const h = createHash("sha256");
    const s = createReadStream(path);
    s.on("error", reject);
    s.on("data", (chunk) => h.update(chunk));
    s.on("end", () => resolve(h.digest("hex")));
  });
}

export function formatDigest(hex: string): string {
  return `sha256:${hex}`;
}

export function parseDigest(value: string): { algo: string; hex: string } {
  const m = /^([a-z0-9-]+):([0-9a-f]+)$/i.exec(value);
  if (!m) throw new Error(`malformed digest: ${value}`);
  return { algo: m[1].toLowerCase(), hex: m[2].toLowerCase() };
}
