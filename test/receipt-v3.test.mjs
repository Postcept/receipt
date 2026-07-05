import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { verifyReceipt, verifyObservation, receiptSigningBody } from "../dist/index.js";

// Signed by the Postcept API's Python implementation. The TS verifier must agree
// byte-for-byte on the v3 signing body AND on both signature roles.
const vector = JSON.parse(
  readFileSync(new URL("./vectors/receipt-v3.json", import.meta.url), "utf8")
);

test("verifies the v3 evaluation role (Postcept signature)", async () => {
  assert.equal(await verifyReceipt(vector.receipt, vector.postcept_public_key), true);
});

test("verifies the v3 observation role (relay signature + envelope digest)", async () => {
  assert.equal(
    await verifyObservation(vector.receipt, vector.envelope_signing_body, vector.relay_public_key),
    true
  );
});

test("the two roles do not cross", async () => {
  assert.equal(await verifyReceipt(vector.receipt, vector.relay_public_key), false);
  assert.equal(
    await verifyObservation(vector.receipt, vector.envelope_signing_body, vector.postcept_public_key),
    false
  );
});

test("tampering a v3 protected field breaks the evaluation signature", async () => {
  const tampered = { ...vector.receipt, lifecycle: "unobserved" };
  assert.equal(await verifyReceipt(tampered, vector.postcept_public_key), false);
});

test("a forged envelope fails the observation role (digest mismatch)", async () => {
  const forged = structuredClone(vector.envelope_signing_body);
  forged.facts.amount_cents = 999999;
  assert.equal(await verifyObservation(vector.receipt, forged, vector.relay_public_key), false);
});
