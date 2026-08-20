/**
 * Exit-code contract for the receipt path.
 *
 * README documents 0 VALID / 1 INVALID / 2 UNKNOWN_KEY / 3 MALFORMED /
 * 4 NETWORK / 64 USAGE, and CI consumers are the one audience that reads the
 * exit code rather than the text.
 *
 * The entry point used to call process.exit(code), which tears the process down
 * immediately. On Windows, if a libuv async handle was mid-close — which it is
 * on any path that did fs or network I/O — Node aborted with:
 *
 *   Assertion failed: !(handle->flags & UV_HANDLE_CLOSING), file src\win\async.c, line 76
 *
 * The verdict had already been printed, so output looked correct while the
 * shell saw 127. Every documented code was wrong on those paths and nothing
 * caught it, because the existing CLI tests exercise the certificate path with
 * --offline and never hit the race.
 *
 * These tests exercise the RECEIPT path specifically, including one that reads
 * a local file and still fetches the public key — the exact combination that
 * aborted.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const cliPath = join(here, "cli.js");
const fixturesDir = join(here, "..", "fixtures");

interface Run { stdout: string; stderr: string; code: number; }

function run(args: string[]): Promise<Run> {
  return new Promise((resolve) => {
    const env = { ...process.env, NO_COLOR: "1" };
    const child = spawn(process.execPath, [cliPath, ...args], { env });
    let stdout = ""; let stderr = "";
    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));
    child.on("close", (code) => resolve({ stdout, stderr, code: code ?? -1 }));
  });
}

/** The process must exit cleanly, never abort. */
function assertNoAbort(r: Run, label: string) {
  assert.ok(
    !/(Assertion failed|UV_HANDLE_CLOSING)/.test(r.stderr + r.stdout),
    `${label}: process aborted instead of exiting — ${r.stderr.trim()}`,
  );
  assert.notEqual(r.code, 127, `${label}: exit 127 means the process died abnormally`);
}

test("receipt VALID from a local file exits 0, not 127", async () => {
  // Reads a file AND fetches the PEM — the combination that aborted.
  const r = await run([join(fixturesDir, "valid-receipt.json"), "--type", "receipt"]);
  assertNoAbort(r, "valid");
  assert.match(r.stdout, /VALID/);
  assert.equal(r.code, 0, `stderr: ${r.stderr}`);
});

test("receipt INVALID exits 1", async () => {
  const r = await run([join(fixturesDir, "tampered-receipt.json"), "--type", "receipt"]);
  assertNoAbort(r, "tampered");
  assert.match(r.stdout, /INVALID/);
  assert.equal(r.code, 1, `stderr: ${r.stderr}`);
});

test("receipt MALFORMED exits 3", async () => {
  const r = await run([join(fixturesDir, "malformed-receipt.json"), "--type", "receipt"]);
  assertNoAbort(r, "malformed");
  assert.match(r.stdout, /MALFORMED/);
  assert.equal(r.code, 3, `stderr: ${r.stderr}`);
});

test("--version exits 0 and prints a version", async () => {
  const r = await run(["--version"]);
  assertNoAbort(r, "version");
  assert.equal(r.code, 0);
  assert.match(r.stdout, /@certifieddata\/verify/);
});

test("--help exits 0", async () => {
  const r = await run(["--help"]);
  assertNoAbort(r, "help");
  assert.equal(r.code, 0);
});

test("no arguments is a usage error, exit 64", async () => {
  const r = await run([]);
  assertNoAbort(r, "no args");
  assert.equal(r.code, 64);
});
