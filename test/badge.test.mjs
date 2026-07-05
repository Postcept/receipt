// Badge verification against a real API-signed vector.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { verifyBadge } from "../dist/index.js";

const v = JSON.parse(readFileSync(new URL("./vectors/badge.json", import.meta.url)));
const WRONG_KEY = Buffer.from(new Uint8Array(32).fill(9)).toString("base64");
const tampered = (mutate) => {
  const b = structuredClone(v.badge);
  mutate(b);
  return b;
};

test("verifies a real audit badge", async () => {
  assert.equal(await verifyBadge(v.badge, v.public_key), true);
});

test("rejects a bumped rate", async () => {
  assert.equal(
    await verifyBadge(
      tampered((b) => (b.verified_completion_rate = 0.999)),
      v.public_key
    ),
    false
  );
});

test("rejects a changed sample size", async () => {
  assert.equal(
    await verifyBadge(
      tampered((b) => (b.sampled = 5)),
      v.public_key
    ),
    false
  );
});

test("rejects the wrong key", async () => {
  assert.equal(await verifyBadge(v.badge, WRONG_KEY), false);
});
