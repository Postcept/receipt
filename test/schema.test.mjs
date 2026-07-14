import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import Ajv from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

// The published JSON Schema and the verifier must describe the same object. Nothing
// enforced that before, which is how the schema's version enum was left at ["1","2"]
// while the verifier had already shipped v3: every dual-signed receipt would have
// failed shape validation for anyone who checked it against the published schema.
// These tests make that drift impossible.

const schema = JSON.parse(
  readFileSync(new URL("../schema/receipt.schema.json", import.meta.url), "utf8")
);
const vector = (name) =>
  JSON.parse(readFileSync(new URL(`./vectors/${name}.json`, import.meta.url), "utf8"));

const ajv = addFormats(new Ajv({ allErrors: true, strict: false }));
const validate = ajv.compile(schema);

function check(receipt) {
  const ok = validate(receipt);
  return { ok, errors: ok ? [] : validate.errors.map((e) => `${e.instancePath} ${e.message}`) };
}

test("every committed receipt vector validates against the published schema", () => {
  for (const name of ["receipt-v1-legacy", "receipt-v2", "receipt-v3"]) {
    const { ok, errors } = check(vector(name).receipt);
    assert.ok(ok, `${name} failed schema validation: ${errors.join(", ")}`);
  }
});

test("the schema accepts every signing-body version the verifier supports", () => {
  // If a new version ships in code, it must ship in the schema in the same change.
  assert.deepEqual(schema.properties.version.enum, ["1", "2", "3"]);
});

test("a v3 receipt's observation role is fully described by the schema", () => {
  const r = vector("receipt-v3").receipt;
  assert.equal(r.version, "3");
  // The dual-signature fields must be present on the vector and known to the schema.
  for (const field of [
    "observation_relay_id",
    "observation_key_id",
    "observation_digest",
    "observation_signature",
  ]) {
    assert.ok(field in r, `vector is missing ${field}`);
    assert.ok(field in schema.properties, `schema does not describe ${field}`);
  }
  assert.ok(check(r).ok);
});

test("the schema describes every field the receipt actually carries", () => {
  // Catches the reverse drift: a field added to the receipt but never to the schema.
  const described = new Set(Object.keys(schema.properties));
  for (const name of ["receipt-v1-legacy", "receipt-v2", "receipt-v3"]) {
    for (const key of Object.keys(vector(name).receipt)) {
      assert.ok(described.has(key), `schema does not describe "${key}" (seen in ${name})`);
    }
  }
});

test("a malformed receipt is rejected", () => {
  const bad = { ...vector("receipt-v2").receipt, result: "definitely_not_a_result" };
  assert.equal(check(bad).ok, false);

  const missingSignature = { ...vector("receipt-v2").receipt };
  delete missingSignature.signature;
  assert.equal(check(missingSignature).ok, false);
});
