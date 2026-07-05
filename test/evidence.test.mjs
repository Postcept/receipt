// Evidence-export verification: the signed manifest, plus that its content digest
// still matches the receipts in the bundle. Real API-produced vector.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  verifyEvidenceManifest,
  verifyEvidenceExport,
  evidenceContentDigest,
} from "../dist/index.js";

const v = JSON.parse(readFileSync(new URL("./vectors/evidence.json", import.meta.url)));
const WRONG_KEY = Buffer.from(new Uint8Array(32).fill(9)).toString("base64");

test("verifies the manifest signature", async () => {
  assert.equal(await verifyEvidenceManifest(v.export.manifest, v.public_key), true);
});

test("verifies the full export", async () => {
  assert.equal(await verifyEvidenceExport(v.export, v.public_key), true);
});

test("recomputes the content digest of the bundle", async () => {
  assert.equal(
    await evidenceContentDigest(v.export.verifications),
    v.export.manifest.content_digest
  );
});

test("rejects an export with a receipt slipped in", async () => {
  const ex = structuredClone(v.export);
  ex.verifications.push({ receipt: { id: "pcpt_rcpt_x", signature: "Zm9v" } });
  // The digest no longer matches what the manifest signed.
  assert.equal(await verifyEvidenceExport(ex, v.public_key), false);
});

test("rejects a tampered verification count", async () => {
  const ex = structuredClone(v.export);
  ex.manifest.verification_count = 99;
  assert.equal(await verifyEvidenceManifest(ex.manifest, v.public_key), false);
});

test("rejects the wrong key", async () => {
  assert.equal(await verifyEvidenceManifest(v.export.manifest, WRONG_KEY), false);
});
