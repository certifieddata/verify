import { readFile } from "node:fs/promises";
export const DEFAULT_CERT_API = "https://certifieddata.io/api/v1/certificates";
export async function fetchCert(idOrPathOrUrl, opts = {}) {
    if (idOrPathOrUrl === "-") {
        return parseCertJson(await readStdin());
    }
    if (idOrPathOrUrl.endsWith(".json") || idOrPathOrUrl.startsWith("./") || idOrPathOrUrl.startsWith("/")) {
        return parseCertJson(await readFile(idOrPathOrUrl, "utf8"));
    }
    if (/^https?:\/\//.test(idOrPathOrUrl)) {
        if (opts.offline)
            throw new Error("cannot fetch URL in --offline mode");
        return parseCertJson(await fetchText(idOrPathOrUrl));
    }
    if (opts.offline) {
        throw new Error("cannot resolve certification id in --offline mode (pass a local file)");
    }
    const base = opts.apiBase ?? DEFAULT_CERT_API;
    const url = `${base.replace(/\/$/, "")}/${encodeURIComponent(idOrPathOrUrl)}`;
    return parseCertJson(await fetchText(url));
}
async function fetchText(url) {
    const res = await fetch(url);
    if (!res.ok)
        throw new Error(`HTTP ${res.status} fetching ${url}`);
    return res.text();
}
function parseCertJson(body) {
    return JSON.parse(body);
}
async function readStdin() {
    const chunks = [];
    for await (const chunk of process.stdin) {
        chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
    }
    return Buffer.concat(chunks).toString("utf8");
}
//# sourceMappingURL=fetch-cert.js.map