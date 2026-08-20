import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
export function sha256Hex(bytes) {
    return createHash("sha256").update(bytes).digest("hex");
}
export async function sha256File(path) {
    return new Promise((resolve, reject) => {
        const h = createHash("sha256");
        const s = createReadStream(path);
        s.on("error", reject);
        s.on("data", (chunk) => h.update(chunk));
        s.on("end", () => resolve(h.digest("hex")));
    });
}
export function formatDigest(hex) {
    return `sha256:${hex}`;
}
export function parseDigest(value) {
    const m = /^([a-z0-9-]+):([0-9a-f]+)$/i.exec(value);
    if (!m)
        throw new Error(`malformed digest: ${value}`);
    return { algo: m[1].toLowerCase(), hex: m[2].toLowerCase() };
}
//# sourceMappingURL=hash.js.map