/**
 * Invocation through the installed bin — the path every real user takes.
 *
 * This test exists because the CLI silently did nothing when run as a bin, and
 * every other test in this repo missed it. They all spawn `node dist/cli.js`,
 * the resolved real path, which is the one invocation form no consumer uses.
 *
 * The bug:
 *
 *   if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
 *
 * Through a bin, process.argv[1] is the symlink npm created
 * (node_modules/.bin/verify) while import.meta.url is the resolved real path.
 * They never match, so main() was never called — the process started, printed
 * nothing, and exited 0.
 *
 *   ./node_modules/.bin/verify 00000000-0000-0000-0000-000000000000
 *   → (no output)  EXIT=0
 *
 * A nonsense receipt id returning success is the worst failure a verifier can
 * have. Not a crash, not a false negative — silent assent. `verify $ID && deploy`
 * passed for a receipt nobody checked.
 *
 * It was invisible on Windows, where npm writes .cmd shims that pass the real
 * path as argv[1], so the comparison matched. On Linux and macOS npm writes a
 * true symlink and it never did.
 *
 * ASSERTING THE OUTPUT IS NOT EMPTY MATTERS AS MUCH AS THE EXIT CODE. The
 * failure mode was a correct-looking exit code with nothing behind it, so a test
 * that only checked codes would have passed while the tool did nothing.
 *
 * The offline cases below are the load-bearing ones: `--version` and the no-args
 * usage error both produce output and a specific code with no network, and both
 * would have caught this.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, readdirSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..");
const isWindows = process.platform === "win32";
let sandbox = null;
let binPath = null;
before(() => {
    try {
        sandbox = mkdtempSync(join(tmpdir(), "cdverify-bin-"));
        // Pack and install exactly what a consumer receives, rather than linking the
        // working tree — npm link produces different bin plumbing.
        const tarball = execFileSync("npm", ["pack", "--silent", "--pack-destination", sandbox], {
            cwd: repoRoot,
            encoding: "utf8",
            shell: isWindows,
        })
            .trim()
            .split("\n")
            .pop();
        execFileSync("npm", ["init", "-y"], { cwd: sandbox, stdio: "ignore", shell: isWindows });
        execFileSync("npm", ["install", join(sandbox, tarball)], {
            cwd: sandbox,
            stdio: "ignore",
            shell: isWindows,
        });
        const binDir = join(sandbox, "node_modules", ".bin");
        const candidate = join(binDir, isWindows ? "verify.cmd" : "verify");
        binPath = existsSync(candidate) ? candidate : null;
        if (!binPath) {
            throw new Error(`bin 'verify' not present after install. Contents: ${readdirSync(binDir).join(", ")}`);
        }
    }
    catch (e) {
        // Leave binPath null; every test below fails loudly rather than silently
        // skipping, because a silent skip is the same class of problem as the bug.
        // eslint-disable-next-line no-console
        console.error(`[bin-invocation] setup failed: ${e.message}`);
    }
});
after(() => {
    if (sandbox)
        rmSync(sandbox, { recursive: true, force: true });
});
function runBin(args) {
    assert.ok(binPath, "bin was not installed — setup failed, see stderr above");
    const r = spawnSync(binPath, args, {
        encoding: "utf8",
        env: { ...process.env, NO_COLOR: "1" },
        shell: isWindows,
    });
    return {
        stdout: r.stdout ?? "",
        stderr: r.stderr ?? "",
        code: r.status ?? -1,
        combined: (r.stdout ?? "") + (r.stderr ?? ""),
    };
}
// ── Offline: these alone would have caught the bug ──────────────────────────
test("bin --version produces output and exits 0", () => {
    const r = runBin(["--version"]);
    // The silent-no-op produced exit 0 too, so the OUTPUT is the real assertion.
    assert.notEqual(r.combined.trim(), "", "bin produced no output at all — it did not run");
    assert.match(r.stdout, /@certifieddata\/verify/);
    assert.equal(r.code, 0);
});
test("bin with no arguments is a usage error, exit 64 with output", () => {
    // The decisive offline case: under the bug this exited 0 in silence. Correct
    // behavior is a non-zero usage code AND an explanation.
    const r = runBin([]);
    assert.notEqual(r.combined.trim(), "", "bin produced no output at all — it did not run");
    assert.equal(r.code, 64, `expected USAGE=64, got ${r.code}. combined: ${r.combined}`);
});
test("bin --help produces the help text and exits 0", () => {
    const r = runBin(["--help"]);
    assert.match(r.stdout, /Exit codes:/);
    assert.equal(r.code, 0);
});
// ── The mechanism itself, on every platform ─────────────────────────────────
//
// The npm-install tests above cannot catch this bug on Windows: npm writes .cmd
// shims there that pass the RESOLVED path as argv[1], so a broken guard still
// matches and the tests pass. That platform difference is precisely why the bug
// shipped, and a guard that only works on some CI legs is half a guard.
//
// So reproduce the condition directly: invoke cli.js through a symlinked
// directory. Node resolves symlinks for import.meta.url but argv[1] keeps the
// link path, which is exactly the divergence npm's bin symlink creates.
// Verified by hand: against the old guard this yields EXIT=0 and ZERO bytes;
// against the fix, EXIT=3 and a NOT_FOUND message.
test("invoking through a symlinked path still runs — no silent no-op", () => {
    const dir = mkdtempSync(join(tmpdir(), "cdverify-link-"));
    try {
        const link = join(dir, "linked-dist");
        try {
            // "junction" is the only form Windows allows without elevation; it is
            // ignored on POSIX, where a normal directory symlink is created.
            symlinkSync(join(here), link, "junction");
        }
        catch (e) {
            assert.fail(`could not create a symlink to exercise the bin path: ${e.message}. ` +
                `This test must not be skipped — it is the only cross-platform guard against ` +
                `the CLI silently doing nothing when invoked as a bin.`);
        }
        const r = spawnSync(process.execPath, [join(link, "cli.js"), "00000000-0000-0000-0000-000000000000"], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });
        const combined = (r.stdout ?? "") + (r.stderr ?? "");
        assert.notEqual(combined.trim(), "", "invoked through a symlink the CLI produced NO output — main() never ran, " +
            "which is the fail-open bug this test exists to catch");
        assert.notEqual(r.status, 0, "a nonsense id returned SUCCESS through a symlinked path — failing open");
    }
    finally {
        rmSync(dir, { recursive: true, force: true });
    }
});
// ── Bare-name invocation through the shell ──────────────────────────────────
//
// npx invokes the selected bin as a BARE NAME through the platform shell. On
// Windows, cmd.exe built-ins shadow bare names before PATH is consulted — and
// `verify` IS a cmd.exe built-in (it toggles disk write verification). So
// `npx github:certifieddata/verify …` silently dies on Windows: cmd's built-in
// swallows the name, prints "An incorrect parameter was entered for the
// command." to a console nobody sees, and exits 1 with no output.
//
// Every other test here spawns the shim by PATH, which built-ins cannot
// shadow — which is exactly why six green CI legs, including two on Windows,
// shipped this. This test does what npx does: bare name, through the shell,
// with .bin on PATH.
//
// `verify` itself is unfixable on Windows (you cannot beat a cmd built-in), so
// the documented cross-platform command uses `cd-verify`, and THIS test pins
// that guarantee. The `verify` alias stays for POSIX convenience only.
test("documented bin `cd-verify` works as a bare name through the shell", () => {
    assert.ok(binPath, "bin was not installed — setup failed");
    const binDir = dirname(binPath);
    const r = spawnSync("cd-verify", ["--version"], {
        encoding: "utf8",
        shell: true, // bare name + shell = the npx invocation shape
        env: {
            ...process.env,
            NO_COLOR: "1",
            PATH: `${binDir}${isWindows ? ";" : ":"}${process.env.PATH ?? ""}`,
            Path: `${binDir};${process.env.Path ?? process.env.PATH ?? ""}`,
        },
    });
    const combined = (r.stdout ?? "") + (r.stderr ?? "");
    assert.notEqual(combined.trim(), "", "cd-verify produced no output as a bare shell name — the documented command is broken");
    assert.match(r.stdout ?? "", /@certifieddata\/verify/);
    assert.equal(r.status, 0, `combined: ${combined}`);
});
// ── Network: the case the reviewer reproduced ───────────────────────────────
test("bin fails closed on a nonsense id — never exit 0", async () => {
    const r = runBin(["00000000-0000-0000-0000-000000000000"]);
    if (/NETWORK|ENOTFOUND|ECONN|fetch failed/i.test(r.combined)) {
        // A network failure must still not be success. Assert that much and stop.
        assert.notEqual(r.code, 0, "network failure must not report success");
        return;
    }
    assert.notEqual(r.combined.trim(), "", "bin produced no output at all — it did not run");
    assert.notEqual(r.code, 0, "a nonsense receipt id returned SUCCESS through the bin — the verifier is failing open");
    assert.equal(r.code, 3, `expected MALFORMED=3, got ${r.code}. combined: ${r.combined}`);
});
//# sourceMappingURL=bin-invocation.test.js.map