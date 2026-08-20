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
export {};
//# sourceMappingURL=exit-codes.test.d.ts.map