# Security policy

## Reporting a vulnerability

Please report security issues privately to **security@certifieddata.io**.

- Please do not open a public GitHub issue for cryptographic findings until a fix is released.
- We aim to acknowledge reports within **48 hours**, ship a fix or workaround within **7 days** for high-severity findings, and request a CVE for any cryptographic finding.
- We will credit you in the release notes unless you ask us not to.

## Scope

In scope:

- Bypass of signature verification in `verifyCertificate` (false `VALID` verdict on a cert that should not verify).
- Incorrect handling of revoked keys, malformed payloads, or non-canonical JSON that produces an exploitable mismatch between signed and verified bytes.
- Any path where the CLI returns exit code 0 for a certificate that does not actually verify.
- Cache poisoning of `~/.certifieddata/keys.json` that could elevate an untrusted key to "trusted".

Out of scope:

- Issues in upstream Node.js `node:crypto` — please report those to the Node.js project.
- DoS on a single host (e.g. very large fixtures making `sha256File` slow).
- Anything depending on a compromised local environment that already has write access to your home directory.

## Supported versions

Until 1.0.0, we support the latest minor release on the `0.x` line. After 1.0.0, we will support the two most recent minor versions.

This package follows [semantic versioning](https://semver.org/). Any breaking change to the verification path or to the `cert.v1` shape is a major version bump.
