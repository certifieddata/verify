import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
const here = dirname(fileURLToPath(import.meta.url));
const cliPath = join(here, "cli.js");
const fixturesDir = join(here, "..", "fixtures");
const keysPath = join(fixturesDir, "keys.json");
function run(args, input) {
    return new Promise((resolve) => {
        const env = { ...process.env, NO_COLOR: "1" };
        const child = spawn(process.execPath, [cliPath, ...args], { env });
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", (d) => (stdout += d.toString()));
        child.stderr.on("data", (d) => (stderr += d.toString()));
        if (input !== undefined) {
            child.stdin.write(input);
            child.stdin.end();
        }
        child.on("close", (code) => resolve({ stdout, stderr, code: code ?? -1 }));
    });
}
test("VALID — exits 0 against a clean cert + dataset", async () => {
    const r = await run([
        join(fixturesDir, "valid-cert.json"),
        "--keys", keysPath,
        "--offline",
        "--dataset", join(fixturesDir, "valid-dataset.csv"),
    ]);
    assert.equal(r.code, 0, `stderr: ${r.stderr}`);
    assert.match(r.stdout, /VALID/);
});
test("INVALID — exits 1 against a tampered cert", async () => {
    const r = await run([
        join(fixturesDir, "tampered-cert.json"),
        "--keys", keysPath,
        "--offline",
    ]);
    assert.equal(r.code, 1);
    assert.match(r.stdout, /INVALID/);
});
test("UNKNOWN_KEY — exits 2 when key_id is not in trusted set", async () => {
    const r = await run([
        join(fixturesDir, "unknown-key-cert.json"),
        "--keys", keysPath,
        "--offline",
    ]);
    assert.equal(r.code, 2);
    assert.match(r.stdout, /UNKNOWN_KEY/);
});
test("MALFORMED — exits 3 when required fields are missing", async () => {
    const r = await run([
        join(fixturesDir, "malformed-cert.json"),
        "--keys", keysPath,
        "--offline",
    ]);
    assert.equal(r.code, 3);
    assert.match(r.stdout, /MALFORMED/);
});
test("DATASET_MISMATCH — exits 1 with a clear reason", async () => {
    const r = await run([
        join(fixturesDir, "valid-cert.json"),
        "--keys", keysPath,
        "--offline",
        "--dataset", keysPath, // wrong file -> wrong hash
    ]);
    assert.equal(r.code, 1);
    assert.match(r.stdout, /DATASET_MISMATCH/);
});
test("--json — emits a structured result with all expected fields", async () => {
    const r = await run([
        join(fixturesDir, "valid-cert.json"),
        "--keys", keysPath,
        "--offline",
        "--json",
    ]);
    assert.equal(r.code, 0);
    const parsed = JSON.parse(r.stdout);
    assert.equal(parsed.verdict, "VALID");
    assert.equal(parsed.issuer, "CertifiedData.io");
    assert.equal(parsed.checks.signature, "pass");
    assert.equal(parsed.checks.key_trust, "pass");
    assert.equal(parsed.checks.dataset_match, "skipped");
    assert.ok(typeof parsed.certification_id === "string");
});
test("--json on tampered cert returns verdict INVALID with signature=fail", async () => {
    const r = await run([
        join(fixturesDir, "tampered-cert.json"),
        "--keys", keysPath,
        "--offline",
        "--json",
    ]);
    assert.equal(r.code, 1);
    const parsed = JSON.parse(r.stdout);
    assert.equal(parsed.verdict, "INVALID");
    assert.equal(parsed.checks.signature, "fail");
});
test("--help — exits 0 and prints usage", async () => {
    const r = await run(["--help"]);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /certifieddata-verify/);
    assert.match(r.stdout, /Exit codes/);
});
test("--version — exits 0 and prints package version", async () => {
    const r = await run(["--version"]);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /@certifieddata\/verify/);
});
test("USAGE — exits 64 on unknown flag", async () => {
    const r = await run(["--made-up-flag"]);
    assert.equal(r.code, 64);
    assert.match(r.stderr, /unknown option/);
});
test("USAGE — exits 64 when no positional argument is given", async () => {
    const r = await run(["--keys", keysPath, "--offline"]);
    assert.equal(r.code, 64);
});
test("stdin input via '-' — exits 0 against a piped valid cert", async () => {
    const { readFile } = await import("node:fs/promises");
    const certBody = await readFile(join(fixturesDir, "valid-cert.json"), "utf8");
    const r = await run(["-", "--keys", keysPath, "--offline"], certBody);
    assert.equal(r.code, 0, `stderr: ${r.stderr}`);
    assert.match(r.stdout, /VALID/);
});
test("checks pass/fail/skipped for each verdict in --json mode", async () => {
    const cases = [
        ["valid-cert.json", "VALID", { signature: "pass", key_trust: "pass", dataset_match: "skipped" }],
        ["tampered-cert.json", "INVALID", { signature: "fail", key_trust: "pass", dataset_match: "skipped" }],
        ["unknown-key-cert.json", "UNKNOWN_KEY", { signature: "skipped", key_trust: "fail", dataset_match: "skipped" }],
    ];
    for (const [file, expected, checks] of cases) {
        const r = await run([join(fixturesDir, file), "--keys", keysPath, "--offline", "--json"]);
        const parsed = JSON.parse(r.stdout);
        assert.equal(parsed.verdict, expected, `case ${file}`);
        for (const [k, v] of Object.entries(checks)) {
            assert.equal(parsed.checks[k], v, `${file}.checks.${k}`);
        }
    }
});
//# sourceMappingURL=cli.test.js.map