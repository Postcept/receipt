// Transparency-log verification: a Merkle inclusion proof and the signed tree head,
// against a real API-produced vector. The target leaf is the receipt-v2 fixture, so
// verifyReceiptInLog ties the receipt to its place in the log.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  verifyInclusion,
  verifySignedTreeHead,
  verifyReceiptInLog,
  verifyConsistency,
} from "../dist/index.js";

const v = JSON.parse(readFileSync(new URL("./vectors/transparency.json", import.meta.url)));
const c = JSON.parse(readFileSync(new URL("./vectors/consistency.json", import.meta.url)));
const receiptV = JSON.parse(readFileSync(new URL("./vectors/receipt-v2.json", import.meta.url)));
const WRONG_KEY = Buffer.from(new Uint8Array(32).fill(9)).toString("base64");

test("verifies the Merkle inclusion proof", async () => {
  assert.equal(await verifyInclusion(v.proof), true);
});

test("verifies the signed tree head", async () => {
  assert.equal(await verifySignedTreeHead(v.proof.sth, v.public_key), true);
});

test("ties the receipt to its place in the log", async () => {
  assert.equal(await verifyReceiptInLog(v.proof, v.public_key, receiptV.receipt), true);
});

test("rejects a tampered audit path", async () => {
  const p = structuredClone(v.proof);
  p.audit_path[0] = (p.audit_path[0][0] === "0" ? "1" : "0") + p.audit_path[0].slice(1);
  assert.equal(await verifyInclusion(p), false);
});

test("rejects a tree head signed by the wrong key", async () => {
  assert.equal(await verifySignedTreeHead(v.proof.sth, WRONG_KEY), false);
});

test("rejects a receipt whose leaf doesn't match the proof", async () => {
  const other = structuredClone(receiptV.receipt);
  other.signature = "AAAA" + other.signature.slice(4);
  assert.equal(await verifyReceiptInLog(v.proof, v.public_key, other), false);
});

// --- consistency proofs: the log only ever appended (grew 2 -> 7) ---

test("verifies the log is an append-only extension", async () => {
  assert.equal(await verifyConsistency(c.consistency), true);
});

test("the remembered earlier head is the one the proof binds first to", () => {
  assert.equal(c.early_sth.root_hash, c.consistency.first_root);
});

test("verifies the later signed tree head", async () => {
  assert.equal(await verifySignedTreeHead(c.consistency.sth, c.public_key), true);
});

test("rejects a tampered consistency-proof node", async () => {
  const p = structuredClone(c.consistency);
  p.proof[0] = (p.proof[0][0] === "0" ? "1" : "0") + p.proof[0].slice(1);
  assert.equal(await verifyConsistency(p), false);
});

test("rejects a forged earlier root", async () => {
  const p = structuredClone(c.consistency);
  p.first_root = (p.first_root[0] === "0" ? "1" : "0") + p.first_root.slice(1);
  assert.equal(await verifyConsistency(p), false);
});
