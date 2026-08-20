#!/usr/bin/env node
import { pathToFileURL } from "node:url";
import { fetchCert } from "./fetch-cert.js";
import { loadKeys } from "./keys.js";
import { verifyCertificate } from "./verify.js";
import { fetchReceipt, loadReceiptKey, verifyReceiptEnvelope } from "./receipt.js";
import { resolveArtifactKind } from "./resolve.js";
const HELP = `certifieddata-verify <id|path|url|-> [options]

Verify a CertifiedData.io certificate or Agent Commerce payment receipt.

The artifact is fetched from CertifiedData, but the verdict is not: the
Ed25519 signature is verified locally against the published public key.

Inputs:
  <id>              certification UUID (resolved against the public API)
  <path.json>       local certificate file
  <https://...>     direct URL to a certificate JSON
  -                 read certificate JSON from stdin

Options:
  --dataset <path>  recompute SHA-256 of dataset file and compare to cert.dataset_hash
  --type <t>        force artifact kind: certificate | receipt (bare UUIDs
                    are probed against both public endpoints; if both exist
                    the CLI refuses to guess and requires --type)
  --keys <path>     certificates: local keys document instead of .well-known
  --key <pem>       receipts: local Agent Commerce public-key PEM
  --offline         do not touch the network (requires --keys or a fresh cache)
  --no-cache        bypass ~/.certifieddata/keys.json cache
  --json            machine-readable output
  --version         print version
  --help            this message

Exit codes:
  0  VALID    1  INVALID    2  UNKNOWN_KEY    3  MALFORMED
  4  NETWORK  64 USAGE`;
const EXIT = {
    VALID: 0, INVALID: 1, UNKNOWN_KEY: 2, MALFORMED: 3, NETWORK: 4, USAGE: 64,
};
const COLOR = process.stdout.isTTY && !process.env.NO_COLOR;
const c = {
    green: (s) => COLOR ? `\x1b[32m${s}\x1b[0m` : s,
    red: (s) => COLOR ? `\x1b[31m${s}\x1b[0m` : s,
    yellow: (s) => COLOR ? `\x1b[33m${s}\x1b[0m` : s,
    dim: (s) => COLOR ? `\x1b[2m${s}\x1b[0m` : s,
};
export async function main(argv) {
    let args;
    try {
        args = parseArgs(argv);
    }
    catch (e) {
        process.stderr.write(`error: ${e.message}\n${HELP}\n`);
        return EXIT.USAGE;
    }
    if (args.help) {
        process.stdout.write(HELP + "\n");
        return EXIT.VALID;
    }
    if (args.version) {
        process.stdout.write(await readVersion() + "\n");
        return EXIT.VALID;
    }
    if (args.positional.length !== 1) {
        process.stderr.write(`error: expected exactly one certificate argument\n${HELP}\n`);
        return EXIT.USAGE;
    }
    const target = args.positional[0];
    // ── Artifact-kind resolution (verify#2) ────────────────────────────────
    let kind;
    if (args.type) {
        kind = args.type;
    }
    else {
        const resolved = await resolveArtifactKind(target, { offline: args.offline });
        if (resolved.kind === "ambiguous") {
            process.stderr.write(`${c.yellow("? AMBIGUOUS")}  ${target} exists as BOTH a certificate and a receipt.\n` +
                `  Re-run with --type certificate or --type receipt.\n`);
            return EXIT.USAGE;
        }
        if (resolved.kind === "not_found") {
            process.stderr.write(`${c.red("✗ NOT_FOUND")}  ${target} is neither a known certificate nor a known receipt.\n`);
            return EXIT.MALFORMED;
        }
        if (resolved.kind === "transport_error") {
            process.stderr.write(`${c.red("✗ NETWORK")}  could not determine artifact kind for ${target} — an endpoint failed.\n` +
                `  A server failure is not evidence of absence. Retry, or pass --type explicitly.\n`);
            return EXIT.NETWORK;
        }
        kind = resolved.kind;
    }
    // ── Receipt path ───────────────────────────────────────────────────────
    if (kind === "receipt") {
        let rres;
        try {
            const env = await fetchReceipt(target, { offline: args.offline });
            const pem = await loadReceiptKey({ keyFile: args.key, offline: args.offline });
            rres = verifyReceiptEnvelope(env, pem);
        }
        catch (err) {
            const reason = err.message;
            const keyUnavailable = /public key unavailable|requires --key/i.test(reason);
            const isNetwork = /HTTP \d|ENOTFOUND|ECONN|getaddrinfo|fetch/i.test(reason);
            if (args.json) {
                process.stdout.write(JSON.stringify({ artifact_type: "receipt", artifact_id: null, verdict: keyUnavailable ? "UNKNOWN_KEY" : "MALFORMED", reason }) + "\n");
            }
            else {
                const tag = keyUnavailable ? c.yellow("? KEY_UNAVAILABLE") : c.red("✗ ERROR");
                process.stderr.write(`${tag}  ${reason}\n`);
                if (keyUnavailable) {
                    process.stderr.write(`  ${c.dim("Independent verification is impossible without the published key —")}\n`);
                    process.stderr.write(`  ${c.dim("the server's own verdict is NOT accepted as a substitute.")}\n`);
                }
            }
            return keyUnavailable ? EXIT.UNKNOWN_KEY : isNetwork ? EXIT.NETWORK : EXIT.MALFORMED;
        }
        if (args.json) {
            process.stdout.write(JSON.stringify(rres) + "\n");
        }
        else {
            printReceiptHuman(rres);
        }
        switch (rres.verdict) {
            case "VALID": return EXIT.VALID;
            case "INVALID": return EXIT.INVALID;
            case "UNKNOWN_KEY": return EXIT.UNKNOWN_KEY;
            case "MALFORMED": return EXIT.MALFORMED;
        }
    }
    // ── Certificate path (unchanged behavior) ──────────────────────────────
    let result;
    try {
        const cert = await fetchCert(target, { offline: args.offline });
        const keys = await loadKeys({ keysFile: args.keys, offline: args.offline, noCache: args.noCache });
        result = await verifyCertificate(cert, keys, args.dataset);
    }
    catch (err) {
        const reason = err.message;
        const isNetwork = /failed to fetch|HTTP \d|ENOTFOUND|ECONN|getaddrinfo/i.test(reason);
        if (args.json) {
            process.stdout.write(JSON.stringify(networkErrorResult(reason)) + "\n");
        }
        else {
            process.stderr.write(`${c.red("✗ ERROR")}  ${reason}\n`);
        }
        return isNetwork ? EXIT.NETWORK : EXIT.MALFORMED;
    }
    if (args.json) {
        process.stdout.write(JSON.stringify(result) + "\n");
    }
    else {
        printHuman(result);
    }
    return verdictToExit(result);
}
function parseArgs(argv) {
    const out = { positional: [], json: false, offline: false, noCache: false, help: false, version: false };
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        switch (a) {
            case "--help":
            case "-h":
                out.help = true;
                break;
            case "--version":
            case "-v":
                out.version = true;
                break;
            case "--json":
                out.json = true;
                break;
            case "--offline":
                out.offline = true;
                break;
            case "--no-cache":
                out.noCache = true;
                break;
            case "--dataset":
                out.dataset = requireValue(argv, ++i, a);
                break;
            case "--keys":
                out.keys = requireValue(argv, ++i, a);
                break;
            case "--key":
                out.key = requireValue(argv, ++i, a);
                break;
            case "--type": {
                const v = requireValue(argv, ++i, a);
                if (v !== "certificate" && v !== "receipt")
                    throw new Error("--type must be certificate or receipt");
                out.type = v;
                break;
            }
            default:
                if (a.startsWith("--"))
                    throw new Error(`unknown option: ${a}`);
                out.positional.push(a);
        }
    }
    return out;
}
function requireValue(argv, i, flag) {
    const v = argv[i];
    if (v === undefined)
        throw new Error(`${flag} requires a value`);
    return v;
}
function verdictToExit(r) {
    switch (r.verdict) {
        case "VALID": return EXIT.VALID;
        case "INVALID":
        case "DATASET_MISMATCH": return EXIT.INVALID;
        case "UNKNOWN_KEY": return EXIT.UNKNOWN_KEY;
        case "MALFORMED": return EXIT.MALFORMED;
    }
}
function printHuman(r) {
    const id = r.certification_id ?? "(unknown)";
    switch (r.verdict) {
        case "VALID": {
            process.stdout.write(`${c.green("✓ VALID")}  certification_id ${id}\n`);
            const label = r.key_label ? `${r.key_id}  (${r.issuer}, ${r.key_label})` : `${r.key_id}  (${r.issuer})`;
            process.stdout.write(`  ${c.dim("signed by")}  ${label}\n`);
            const rows = (r.rows ?? 0).toLocaleString("en-US");
            const cols = (r.columns ?? 0).toLocaleString("en-US");
            process.stdout.write(`  ${c.dim("algorithm")}  ${r.algorithm}  ·  ${rows} rows × ${cols} cols  ·  signed ${r.signed_at}\n`);
            if (r.checks.dataset_match === "pass") {
                process.stdout.write(`  ${c.dim("dataset")}    ${r.dataset_hash_actual} ${c.green("matches")}\n`);
            }
            break;
        }
        case "INVALID":
            process.stdout.write(`${c.red("✗ INVALID")}  certification_id ${id}\n  ${r.reason}\n`);
            break;
        case "DATASET_MISMATCH":
            process.stdout.write(`${c.red("✗ DATASET_MISMATCH")}  certification_id ${id}\n`);
            process.stdout.write(`  expected ${r.dataset_hash_expected}\n  actual   ${r.dataset_hash_actual}\n`);
            break;
        case "UNKNOWN_KEY":
            process.stdout.write(`${c.yellow("? UNKNOWN_KEY")}  certification_id ${id}\n  ${r.reason}\n`);
            break;
        case "MALFORMED":
            process.stdout.write(`${c.red("✗ MALFORMED")}  ${r.reason}\n`);
            break;
    }
}
function printReceiptHuman(r) {
    const id = r.artifact_id ?? "(unknown)";
    switch (r.verdict) {
        case "VALID": {
            process.stdout.write(`${c.green("✓ VALID")}  receipt ${id}\n`);
            process.stdout.write(`  ${c.dim("signed by")}    ${r.key_id ?? "(published Agent Commerce key)"} (${r.issuer ?? "CertifiedData.io"})\n`);
            process.stdout.write(`  ${c.dim("signature")}    ${r.checks.signature}\n`);
            process.stdout.write(`  ${c.dim("payload hash")} ${r.checks.payload_hash}\n`);
            process.stdout.write(`  ${c.dim("public key")}   /.well-known/certifieddata-public-key.pem\n`);
            if (r.settlement_state) {
                process.stdout.write(`  ${c.dim("settlement")}   ${r.settlement_state}\n`);
            }
            process.stdout.write(`  ${c.dim("The verdict above was computed locally — not taken from the server.")}\n`);
            break;
        }
        case "INVALID":
            process.stdout.write(`${c.red("✗ INVALID")}  receipt ${id}\n  ${r.reason}\n`);
            break;
        case "UNKNOWN_KEY":
            process.stdout.write(`${c.yellow("? UNKNOWN_KEY")}  receipt ${id}\n  ${r.reason}\n`);
            break;
        case "MALFORMED":
            process.stdout.write(`${c.red("✗ MALFORMED")}  ${r.reason}\n`);
            break;
    }
}
function networkErrorResult(reason) {
    return {
        verdict: "MALFORMED",
        certification_id: null, key_id: null, issuer: null, algorithm: null, signed_at: null,
        dataset_hash_expected: null, dataset_hash_actual: null,
        checks: { signature: "skipped", key_trust: "skipped", dataset_match: "skipped" },
        reason,
    };
}
async function readVersion() {
    try {
        const { readFile } = await import("node:fs/promises");
        const { fileURLToPath } = await import("node:url");
        const { dirname, join } = await import("node:path");
        const here = dirname(fileURLToPath(import.meta.url));
        const pkg = JSON.parse(await readFile(join(here, "..", "package.json"), "utf8"));
        return `@certifieddata/verify ${pkg.version}`;
    }
    catch {
        return "@certifieddata/verify (unknown version)";
    }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    main(process.argv.slice(2)).then((code) => process.exit(code));
}
//# sourceMappingURL=cli.js.map