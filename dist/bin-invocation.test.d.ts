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
export {};
//# sourceMappingURL=bin-invocation.test.d.ts.map