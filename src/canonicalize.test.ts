import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalize, canonicalizeToBytes } from "./canonicalize.js";

test("primitives", () => {
  assert.equal(canonicalize(null), "null");
  assert.equal(canonicalize(true), "true");
  assert.equal(canonicalize(false), "false");
  assert.equal(canonicalize(0), "0");
  assert.equal(canonicalize(-0), "0");
  assert.equal(canonicalize(1), "1");
  assert.equal(canonicalize(1.5), "1.5");
});

test("strings — minimal RFC 8259 escapes", () => {
  assert.equal(canonicalize(""), '""');
  assert.equal(canonicalize("hello"), '"hello"');
  assert.equal(canonicalize('a"b'), '"a\\"b"');
  assert.equal(canonicalize("a\\b"), '"a\\\\b"');
  assert.equal(canonicalize("a\nb"), '"a\\nb"');
  assert.equal(canonicalize("a\tb"), '"a\\tb"');
  assert.equal(canonicalize("a\rb"), '"a\\rb"');
  assert.equal(canonicalize("\b\f"), '"\\b\\f"');
  // Other control chars use \u00XX.
  assert.equal(canonicalize(""), '"\\u0001"');
  assert.equal(canonicalize(""), '"\\u001f"');
  // Non-ASCII characters pass through unescaped (UTF-8 in the byte form).
  assert.equal(canonicalize("ä"), '"ä"');
});

test("arrays — preserve order", () => {
  assert.equal(canonicalize([]), "[]");
  assert.equal(canonicalize([1, 2, 3]), "[1,2,3]");
  assert.equal(canonicalize(["b", "a"]), '["b","a"]');
});

test("objects — keys sorted by UTF-16 code units", () => {
  assert.equal(canonicalize({}), "{}");
  assert.equal(canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}');
  // RFC 8785 §3.2.3 sorting example (code-unit order, NOT Unicode codepoint order).
  // The keys "ä" (ä) and "\" (\) and "€" (€) sort by UTF-16 units.
  const input = { "€": "Euro", "ä": "a-umlaut", a: "ascii" };
  // Code-unit values: 0x61 (a), 0xe4 (ä), 0x20ac (€).
  assert.equal(canonicalize(input), '"a":"ascii","ä":"a-umlaut","€":"Euro"'.replace(/^/, "{") + "}");
});

test("RFC 8785 §3.2.3 sample (sorting nested objects)", () => {
  // Adapted from RFC 8785 example: keys including non-ASCII chars and surrogate pairs
  // must compare as UTF-16 code-unit sequences.
  const input = {
    peach: "This sorting order",
    péché: "is wrong according to French",
    pêche: "but canonicalization MUST",
    sin:   "ignore locale",
  };
  // Sort by UTF-16 code units of the keys.
  // peach (p,e,a,c,h)        — 0x70 0x65 ...
  // péché (p,é=0xe9,c,h,é)
  // pêche (p,ê=0xea,c,h,e)
  // sin   (s=0x73, ...)
  // Order by first differing unit: peach < péché < pêche < sin.
  const out = canonicalize(input);
  assert.match(out, /^\{"peach":/);
  // Confirm the four keys appear in the expected order.
  const order = ["peach", "péché", "pêche", "sin"];
  let idx = -1;
  for (const k of order) {
    const next = out.indexOf(`"${k}":`);
    assert.ok(next > idx, `expected ${k} after position ${idx}, got ${next}`);
    idx = next;
  }
});

test("nested objects + arrays", () => {
  const input = { z: [3, 2, 1], a: { y: 1, x: 2 } };
  assert.equal(canonicalize(input), '{"a":{"x":2,"y":1},"z":[3,2,1]}');
});

test("undefined keys are dropped", () => {
  // RFC 8785 inputs come from JSON; JS undefined has no JSON encoding, so we drop.
  const input = { a: 1, b: undefined, c: 3 } as Record<string, unknown>;
  assert.equal(canonicalize(input), '{"a":1,"c":3}');
});

test("non-finite numbers throw", () => {
  assert.throws(() => canonicalize(NaN), RangeError);
  assert.throws(() => canonicalize(Infinity), RangeError);
  assert.throws(() => canonicalize(-Infinity), RangeError);
});

test("canonicalizeToBytes round-trips through UTF-8", () => {
  const bytes = canonicalizeToBytes({ a: "ä" });
  assert.equal(new TextDecoder().decode(bytes), '{"a":"ä"}');
});

test("idempotent: canonicalize(JSON.parse(canonicalize(x))) === canonicalize(x)", () => {
  const x = { z: 1, a: { c: [1, 2], b: "x" } };
  const once = canonicalize(x);
  const twice = canonicalize(JSON.parse(once));
  assert.equal(once, twice);
});

test("number formatting matches JSON.stringify for finite numbers", () => {
  for (const n of [0, 1, -1, 1.5, -1.5, 1e20, 1e-7, 0.1 + 0.2]) {
    assert.equal(canonicalize(n), JSON.stringify(n));
  }
});

test("removes only the named field — signature stripping pattern", () => {
  const cert = { a: 1, signature: "AAA", z: 9 };
  const { signature: _s, ...rest } = cert;
  assert.equal(canonicalize(rest), '{"a":1,"z":9}');
});

test("array of objects sorts each object's keys independently", () => {
  const input = [{ b: 1, a: 2 }, { d: 4, c: 3 }];
  assert.equal(canonicalize(input), '[{"a":2,"b":1},{"c":3,"d":4}]');
});

test("empty key string", () => {
  assert.equal(canonicalize({ "": "x", a: "y" }), '{"":"x","a":"y"}');
});
