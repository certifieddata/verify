import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyCertificate } from "./verify.js";
import type { Certificate, KeyDoc } from "./types.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, "..", "fixtures");

async function loadJson<T>(name: string): Promise<T> {
  return JSON.parse(await readFile(join(fixturesDir, name), "utf8")) as T;
}

test("verifies a clean cert against trusted keys", async () => {
  const cert = await loadJson<Certificate>("valid-cert.json");
  const keys = await loadJson<KeyDoc>("keys.json");
  const r = await verifyCertificate(cert, keys);
  assert.equal(r.verdict, "VALID", r.reason);
  assert.equal(r.checks.signature, "pass");
  assert.equal(r.checks.key_trust, "pass");
  assert.equal(r.checks.dataset_match, "skipped");
});

test("rejects a cert whose payload was mutated after signing", async () => {
  const cert = await loadJson<Certificate>("tampered-cert.json");
  const keys = await loadJson<KeyDoc>("keys.json");
  const r = await verifyCertificate(cert, keys);
  assert.equal(r.verdict, "INVALID");
  assert.equal(r.checks.signature, "fail");
  assert.equal(r.checks.key_trust, "pass");
});

test("returns UNKNOWN_KEY when the cert references an unlisted key", async () => {
  const cert = await loadJson<Certificate>("unknown-key-cert.json");
  const keys = await loadJson<KeyDoc>("keys.json");
  const r = await verifyCertificate(cert, keys);
  assert.equal(r.verdict, "UNKNOWN_KEY");
  assert.equal(r.checks.key_trust, "fail");
  assert.equal(r.checks.signature, "skipped");
});

test("returns MALFORMED for missing required fields", async () => {
  const cert = await loadJson<Certificate>("malformed-cert.json");
  const keys = await loadJson<KeyDoc>("keys.json");
  const r = await verifyCertificate(cert, keys);
  assert.equal(r.verdict, "MALFORMED");
  assert.match(r.reason, /missing required field: signature/);
});

test("returns DATASET_MISMATCH when the dataset hash does not match", async () => {
  const cert = await loadJson<Certificate>("valid-cert.json");
  const keys = await loadJson<KeyDoc>("keys.json");
  const wrongDataset = join(fixturesDir, "keys.json"); // hash will differ
  const r = await verifyCertificate(cert, keys, wrongDataset);
  assert.equal(r.verdict, "DATASET_MISMATCH");
  assert.equal(r.checks.dataset_match, "fail");
  assert.notEqual(r.dataset_hash_actual, r.dataset_hash_expected);
});

test("returns VALID when the supplied dataset matches", async () => {
  const cert = await loadJson<Certificate>("valid-cert.json");
  const keys = await loadJson<KeyDoc>("keys.json");
  const dataset = join(fixturesDir, "valid-dataset.csv");
  const r = await verifyCertificate(cert, keys, dataset);
  assert.equal(r.verdict, "VALID");
  assert.equal(r.checks.dataset_match, "pass");
});

test("rejects a revoked key", async () => {
  const cert = await loadJson<Certificate>("valid-cert.json");
  const keys = await loadJson<KeyDoc>("keys.json");
  keys.keys[0].revoked_at = "2026-04-01T00:00:00Z";
  const r = await verifyCertificate(cert, keys);
  assert.equal(r.verdict, "UNKNOWN_KEY");
  assert.match(r.reason, /revoked/);
});
