# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

### Added

- Initial public release of `@certifieddata/verify`.
- `certifieddata-verify` and `cd-verify` binaries.
- RFC 8785 JCS canonicalizer (`canonicalize.ts`).
- Ed25519 signature verification using `node:crypto` only — zero third-party crypto dependencies.
- `cert.v1` schema support.
- `--dataset`, `--json`, `--offline`, `--keys`, `--no-cache` flags.
- Trusted-keys document fetched from `https://certifieddata.io/.well-known/certifieddata-keys.json` with TTL cache at `~/.certifieddata/keys.json`.
- Six exit codes documented in the README and `--help`.
- 34 tests across canonicalize, verify, and CLI suites.
