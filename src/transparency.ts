// Independent verification of the public transparency log: a Merkle inclusion proof
// plus the signed tree head, following RFC 6962. Matches the API's transparency log
// byte for byte.
import * as ed from "@noble/ed25519";
import {
  base64ToBytes,
  bytesToHex,
  canonicalize,
  concatBytes,
  hexToBytes,
  sha256,
  TIMESTAMP_SPELLINGS,
} from "./canonical.js";
import type { Receipt } from "./receipt.js";

export interface SignedTreeHead {
  tree_size: number;
  root_hash: string;
  timestamp: string;
  algorithm?: string;
  signing_key_id?: string;
  signature: string;
}

export interface InclusionProof {
  receipt_id: string;
  leaf_index: number;
  leaf_hash: string;
  tree_size: number;
  audit_path: string[];
  sth: SignedTreeHead;
}

export interface ConsistencyProof {
  first_size: number;
  second_size: number;
  first_root: string;
  second_root: string;
  proof: string[];
  sth: SignedTreeHead;
}

const STH_TYPE = "postcept-sth";

const nodeHash = (left: Uint8Array, right: Uint8Array) =>
  sha256(concatBytes(new Uint8Array([0x01]), left, right));

function largestPowerOfTwoBelow(n: number): number {
  let k = 1;
  while (k << 1 < n) k <<= 1;
  return k;
}

/** Recompute the Merkle root from a leaf and its audit path (mirrors the API). */
async function rootFromPath(
  index: number,
  size: number,
  leaf: Uint8Array,
  path: Uint8Array[]
): Promise<Uint8Array> {
  if (size === 1) return leaf;
  const k = largestPowerOfTwoBelow(size);
  const sibling = path[path.length - 1];
  const rest = path.slice(0, -1);
  if (index < k) return nodeHash(await rootFromPath(index, k, leaf, rest), sibling);
  return nodeHash(sibling, await rootFromPath(index - k, size - k, leaf, rest));
}

/** The RFC 6962 leaf hash for a receipt (hex), reconstructible from the receipt. */
export async function receiptLeafHash(receipt: Receipt): Promise<string> {
  const enc = new TextEncoder();
  const data = concatBytes(
    enc.encode(receipt.id),
    new Uint8Array([0x0a]),
    enc.encode(receipt.signature)
  );
  return bytesToHex(await sha256(concatBytes(new Uint8Array([0x00]), data)));
}

/** Verify a Merkle inclusion proof against its signed root. */
export async function verifyInclusion(proof: InclusionProof): Promise<boolean> {
  try {
    if (!(proof.leaf_index >= 0 && proof.leaf_index < proof.tree_size)) return false;
    const leaf = hexToBytes(proof.leaf_hash);
    const path = proof.audit_path.map(hexToBytes);
    const root = await rootFromPath(proof.leaf_index, proof.tree_size, leaf, path);
    return bytesToHex(root) === proof.sth.root_hash;
  } catch {
    return false;
  }
}

const isPowerOfTwo = (n: number) => (n & (n - 1)) === 0;

/**
 * Verify an RFC 6962 consistency proof. It shows the log at `second_size` is an
 * append-only extension of the log at `first_size`, with nothing removed,
 * reordered, or back-dated. Confirms the proof connects `first_root` to
 * `second_root`, and that `second_root` matches the signed head. Check the head's
 * signature separately with verifySignedTreeHead, and compare `first_root` against
 * the earlier head you saved.
 *
 * The walk is the RFC 9162 §2.1.4.2 verification algorithm. The awaits fold sibling
 * hashes in sequence, so they cannot run in parallel.
 */
/* eslint-disable no-await-in-loop */
export async function verifyConsistency(proof: ConsistencyProof): Promise<boolean> {
  try {
    const first = proof.first_size;
    const second = proof.second_size;
    if (bytesToHex(hexToBytes(proof.second_root)) !== proof.sth.root_hash) return false;
    if (first < 0 || first > second) return false;
    if (first === second) return proof.proof.length === 0 && proof.first_root === proof.second_root;
    if (first === 0) return proof.proof.length === 0;

    const nodes = proof.proof.map(hexToBytes);
    // A power-of-two prefix has no left-hand sibling in the path, so its own root is
    // the seed the walk starts from.
    if (isPowerOfTwo(first)) nodes.unshift(hexToBytes(proof.first_root));
    if (nodes.length === 0) return false;

    let fn = first - 1;
    let sn = second - 1;
    while (fn & 1) {
      fn >>= 1;
      sn >>= 1;
    }
    let fr = nodes[0];
    let sr = nodes[0];
    for (let i = 1; i < nodes.length; i += 1) {
      const c = nodes[i];
      if (sn === 0) return false;
      if (fn & 1 || fn === sn) {
        fr = await nodeHash(c, fr);
        sr = await nodeHash(c, sr);
        while ((fn & 1) === 0 && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
      } else {
        sr = await nodeHash(sr, c);
      }
      fn >>= 1;
      sn >>= 1;
    }
    return sn === 0 && bytesToHex(fr) === proof.first_root && bytesToHex(sr) === proof.second_root;
  } catch {
    return false;
  }
}
/* eslint-enable no-await-in-loop */

/** Verify the signed tree head's Ed25519 signature against the published key. */
export async function verifySignedTreeHead(
  sth: SignedTreeHead,
  publicKeyB64: string
): Promise<boolean> {
  try {
    const sig = base64ToBytes(sth.signature);
    const pub = base64ToBytes(publicKeyB64);
    for (const ts of TIMESTAMP_SPELLINGS) {
      const body = {
        type: STH_TYPE,
        tree_size: sth.tree_size,
        root_hash: sth.root_hash,
        timestamp: ts(sth.timestamp),
      };
      const msg = new TextEncoder().encode(canonicalize(body));
      // eslint-disable-next-line no-await-in-loop
      if (await ed.verifyAsync(sig, msg, pub)) return true;
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Fully verify a receipt's place in the log: the inclusion proof reconstructs the
 * signed root, the tree head's signature is valid, and (if the receipt is given)
 * the proof's leaf hash matches the receipt.
 */
export async function verifyReceiptInLog(
  proof: InclusionProof,
  publicKeyB64: string,
  receipt?: Receipt
): Promise<boolean> {
  if (receipt && (await receiptLeafHash(receipt)) !== proof.leaf_hash) return false;
  if (!(await verifyInclusion(proof))) return false;
  return verifySignedTreeHead(proof.sth, publicKeyB64);
}
