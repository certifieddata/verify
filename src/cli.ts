#!/usr/bin/env node
import { fetchCert } from "./fetch-cert.js";
import { loadKeys } from "./keys.js";
import { verifyCertificate } from "./verify.js";
import type { VerifyResult } from "./types.js";

interface CliArgs {
  positional: string[];
  dataset?: string;
  keys?: string;
  json: boolean;
  offline: boolean;
  noCache: boolean;
  help: boolean;
  version: boolean;
}

const HELP = `certifieddata-verify <id|path|url|-> [options]

Verify a CertifiedData.io certificate.

Inputs:
  <id>              certification UUID (resolved against the public API)
  <path.json>       local certificate file
  <https://...>     direct URL to a certificate JSON
  -                 read certificate JSON from stdin

Options:
  --dataset <path>  recompute SHA-256 of dataset file and compare to cert.dataset_hash
  --keys <path>     use a local keys document instead of fetching .well-known
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
} as const;

const COLOR = process.stdout.isTTY && !process.env.NO_COLOR;
const c = {
  green: (s: string) => COLOR ? `\x1b[32m${s}\x1b[0m` : s,
  red:   (s: string) => COLOR ? `\x1b[31m${s}\x1b[0m` : s,
  yellow:(s: string) => COLOR ? `\x1b[33m${s}\x1b[0m` : s,
  dim:   (s: string) => COLOR ? `\x1b[2m${s}\x1b[0m` : s,
};

export async function main(argv: string[]): Promise<number> {
  let args: CliArgs;
  try { args = parseArgs(argv); } catch (e) {
    process.stderr.write(`error: ${(e as Error).message}\n${HELP}\n`);
    return EXIT.USAGE;
  }

  if (args.help) { process.stdout.write(HELP + "\n"); return EXIT.VALID; }
  if (args.version) { process.stdout.write(await readVersion() + "\n"); return EXIT.VALID; }

  if (args.positional.length !== 1) {
    process.stderr.write(`error: expected exactly one certificate argument\n${HELP}\n`);
    return EXIT.USAGE;
  }

  const target = args.positional[0];
  let result: VerifyResult;
  try {
    const cert = await fetchCert(target, { offline: args.offline });
    const keys = await loadKeys({ keysFile: args.keys, offline: args.offline, noCache: args.noCache });
    result = await verifyCertificate(cert, keys, args.dataset);
  } catch (err) {
    const reason = (err as Error).message;
    const isNetwork = /failed to fetch|HTTP \d|ENOTFOUND|ECONN|getaddrinfo/i.test(reason);
    if (args.json) {
      process.stdout.write(JSON.stringify(networkErrorResult(reason)) + "\n");
    } else {
      process.stderr.write(`${c.red("✗ ERROR")}  ${reason}\n`);
    }
    return isNetwork ? EXIT.NETWORK : EXIT.MALFORMED;
  }

  if (args.json) {
    process.stdout.write(JSON.stringify(result) + "\n");
  } else {
    printHuman(result);
  }
  return verdictToExit(result);
}

function parseArgs(argv: string[]): CliArgs {
  const out: CliArgs = { positional: [], json: false, offline: false, noCache: false, help: false, version: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--help": case "-h": out.help = true; break;
      case "--version": case "-v": out.version = true; break;
      case "--json": out.json = true; break;
      case "--offline": out.offline = true; break;
      case "--no-cache": out.noCache = true; break;
      case "--dataset": out.dataset = requireValue(argv, ++i, a); break;
      case "--keys": out.keys = requireValue(argv, ++i, a); break;
      default:
        if (a.startsWith("--")) throw new Error(`unknown option: ${a}`);
        out.positional.push(a);
    }
  }
  return out;
}

function requireValue(argv: string[], i: number, flag: string): string {
  const v = argv[i];
  if (v === undefined) throw new Error(`${flag} requires a value`);
  return v;
}

function verdictToExit(r: VerifyResult): number {
  switch (r.verdict) {
    case "VALID": return EXIT.VALID;
    case "INVALID": case "DATASET_MISMATCH": return EXIT.INVALID;
    case "UNKNOWN_KEY": return EXIT.UNKNOWN_KEY;
    case "MALFORMED": return EXIT.MALFORMED;
  }
}

function printHuman(r: VerifyResult): void {
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

function networkErrorResult(reason: string): VerifyResult {
  return {
    verdict: "MALFORMED",
    certification_id: null, key_id: null, issuer: null, algorithm: null, signed_at: null,
    dataset_hash_expected: null, dataset_hash_actual: null,
    checks: { signature: "skipped", key_trust: "skipped", dataset_match: "skipped" },
    reason,
  };
}

async function readVersion(): Promise<string> {
  try {
    const { readFile } = await import("node:fs/promises");
    const { fileURLToPath } = await import("node:url");
    const { dirname, join } = await import("node:path");
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(await readFile(join(here, "..", "package.json"), "utf8"));
    return `@certifieddata/verify ${pkg.version}`;
  } catch { return "@certifieddata/verify (unknown version)"; }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).then((code) => process.exit(code));
}
