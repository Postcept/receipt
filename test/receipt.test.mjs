// Verification tests against real vectors: the Postcept API (Python) signs each
// receipt, this reference implementation (JS) must agree byte-for-byte. The vectors
// are committed under ./vectors and were produced with a fixed key, so they're
// stable and anyone can regenerate or inspect them. Run against the built output.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { verifyReceipt, canonicalize } from "../dist/index.js";

const load = (name) => JSON.parse(readFileSync(new URL(`./vectors/${name}`, import.meta.url)));
const v2 = load("receipt-v2.json");
const v1 = load("receipt-v1-legacy.json");

// Any 32 bytes is a syntactically valid key, so this exercises the real failure path
// (a good signature checked against the wrong key), not a parse error.
const WRONG_KEY = Buffer.from(new Uint8Array(32).fill(9)).toString("base64");

const tampered = (mutate) => {
  const r = structuredClone(v2.receipt);
  mutate(r);
  return r;
};

test("verifies a real v2 receipt signed by the API", async () => {
  assert.equal(await verifyReceipt(v2.receipt, v2.public_key), true);
});

test("verifies a legacy v1 receipt body", async () => {
  assert.equal(await verifyReceipt(v1.receipt, v1.public_key), true);
});

test("rejects a changed result", async () => {
  assert.equal(
    await verifyReceipt(
      tampered((r) => (r.result = "incomplete")),
      v2.public_key
    ),
    false
  );
});

test("rejects an edited postcondition value", async () => {
  const r = tampered((r) => (r.postconditions[1].actual = "9900 usd"));
  assert.equal(await verifyReceipt(r, v2.public_key), false);
});

test("rejects a sandbox receipt re-flagged as live", async () => {
  // v2 signs `test`, so a sandbox receipt can't be passed off as a real one.
  assert.equal(
    await verifyReceipt(
      tampered((r) => (r.test = true)),
      v2.public_key
    ),
    false
  );
});

test("rejects a swapped tenant", async () => {
  assert.equal(
    await verifyReceipt(
      tampered((r) => (r.org_id = "org_attacker")),
      v2.public_key
    ),
    false
  );
});

test("rejects a garbled signature", async () => {
  const r = tampered((r) => (r.signature = r.signature.slice(0, -4) + "AAAA"));
  assert.equal(await verifyReceipt(r, v2.public_key), false);
});

test("rejects the wrong public key", async () => {
  assert.equal(await verifyReceipt(v2.receipt, WRONG_KEY), false);
});

test("returns false rather than throwing on malformed input", async () => {
  assert.equal(await verifyReceipt({}, v2.public_key), false);
  assert.equal(await verifyReceipt(v2.receipt, "not base64"), false);
});

test("canonicalize sorts keys, drops whitespace, escapes non-ASCII", () => {
  assert.equal(canonicalize({ b: 1, a: [3, 2] }), '{"a":[3,2],"b":1}');
  assert.equal(canonicalize({ é: "•" }), '{"\\u00e9":"\\u2022"}');
});
