// The signed receipt object and its verification. Reference implementation of the
// open standard in SPEC.md.
import * as ed from "@noble/ed25519";
import { base64ToBytes, canonicalize, sha256Hex, TIMESTAMP_SPELLINGS } from "./canonical.js";

export interface Postcondition {
  name: string;
  category?: string | null;
  status: string;
  expected?: string | null;
  actual?: string | null;
}

export interface Receipt {
  id: string;
  org_id?: string | null;
  operation_id: string;
  agent_id: string;
  action: string;
  connectors_checked: string[];
  postconditions: Postcondition[];
  result: string;
  issued_at: string;
  valid_as_of?: string | null;
  test?: boolean;
  /** Signing-body version. Receipts predating this field are treated as "1". */
  version?: string;
  algorithm?: string;
  signing_key_id?: string;
  signature: string;
  // v3 protected fields (bound into the signed body, absent on v1/v2).
  supersedes?: string | null;
  contract_digest?: string | null;
  lifecycle?: string | null;
  safe_to_claim_complete?: boolean | null;
  correlation_strength?: string | null;
  // The observation role: present only when a customer relay produced the source.
  observation_relay_id?: string | null;
  observation_key_id?: string | null;
  observation_digest?: string | null;
  observation_signature?: string | null;
}

export interface Observation {
  relay_id: string | null;
  key_id: string | null;
  digest: string | null;
  signature: string | null;
}

// Stable identifier for the canonical-JSON scheme (sorted keys, no whitespace,
// non-ASCII and control characters escaped). Bound into the v3 signing body so the
// signature covers which scheme produced the bytes. Matches CANONICALIZATION_SCHEME
// in the control plane. Bump both together if the scheme ever changes.
export const CANONICALIZATION_SCHEME = "postcept-canonical-json-v1";

/**
 * The exact subset of a receipt the signature covers, by version. `ts` applies a
 * timestamp spelling so the caller can retry "Z" vs "+00:00" (see verifyReceipt).
 */
function receiptSigningBodyV2(r: Receipt, ts: (s: string) => string): Record<string, unknown> {
  return {
    version: "2",
    id: r.id,
    org_id: r.org_id ?? null,
    operation_id: r.operation_id,
    agent_id: r.agent_id,
    action: r.action,
    connectors_checked: r.connectors_checked,
    test: r.test ?? false,
    postconditions: (r.postconditions ?? []).map((p) => ({
      name: p.name,
      category: p.category ?? null,
      status: p.status,
      expected: p.expected ?? null,
      actual: p.actual ?? null,
    })),
    result: r.result,
    issued_at: ts(r.issued_at),
    valid_as_of: r.valid_as_of ? ts(r.valid_as_of) : null,
  };
}

export function receiptSigningBody(r: Receipt, ts: (s: string) => string): Record<string, unknown> {
  if (r.version === "3") {
    // v3 extends the v2 body with the fields that were server-asserted metadata
    // in v2, plus the observation role when a relay produced the source.
    const v2 = receiptSigningBodyV2(r, ts);
    return {
      ...v2,
      version: "3",
      // Bind the signature metadata into the protected content (see CANONICALIZATION_SCHEME).
      algorithm: r.algorithm ?? "ed25519",
      signing_key_id: r.signing_key_id ?? null,
      canonicalization: CANONICALIZATION_SCHEME,
      supersedes: r.supersedes ?? null,
      contract_digest: r.contract_digest ?? null,
      lifecycle: r.lifecycle ?? null,
      safe_to_claim_complete: r.safe_to_claim_complete ?? null,
      correlation_strength: r.correlation_strength ?? null,
      observation:
        r.observation_signature != null
          ? {
              relay_id: r.observation_relay_id ?? null,
              key_id: r.observation_key_id ?? null,
              digest: r.observation_digest ?? null,
              signature: r.observation_signature,
            }
          : null,
    };
  }
  if (r.version === "2") {
    return receiptSigningBodyV2(r, ts);
  }
  // Legacy v1 body (name + status only).
  return {
    id: r.id,
    operation_id: r.operation_id,
    agent_id: r.agent_id,
    action: r.action,
    connectors_checked: r.connectors_checked,
    postconditions: (r.postconditions ?? []).map((p) => ({ name: p.name, status: p.status })),
    result: r.result,
    issued_at: ts(r.issued_at),
  };
}

/**
 * Verify a receipt's Ed25519 signature against a published public key (base64 raw
 * key from GET /v1/signing-key). Returns false on a bad signature or malformed
 * input instead of throwing.
 */
export async function verifyReceipt(receipt: Receipt, publicKeyB64: string): Promise<boolean> {
  try {
    const sig = base64ToBytes(receipt.signature);
    const pub = base64ToBytes(publicKeyB64);
    for (const ts of TIMESTAMP_SPELLINGS) {
      const msg = new TextEncoder().encode(canonicalize(receiptSigningBody(receipt, ts)));
      // eslint-disable-next-line no-await-in-loop
      if (await ed.verifyAsync(sig, msg, pub)) return true;
    }
    return false;
  } catch {
    return false;
  }
}

// The observation role of a v3 receipt. `verifyReceipt` checks the evaluation
// role, where Postcept signed the result. This checks the source observation:
// given the original relay envelope's signing body, that it hashes to the digest
// in the receipt and that the relay's signature verifies against the relay's
// public key. The two roles together show that the relay observed the source and
// Postcept evaluated it, with neither able to forge the other's statement.
// Returns false, never throws, if there is no observation role or anything fails.
export async function verifyObservation(
  receipt: Receipt,
  envelopeSigningBody: Record<string, unknown>,
  relayPublicKeyB64: string
): Promise<boolean> {
  try {
    if (receipt.observation_signature == null || receipt.observation_digest == null) return false;
    const canonical = new TextEncoder().encode(canonicalize(envelopeSigningBody));
    const digest = `sha256:${await sha256Hex(canonical)}`;
    if (digest !== receipt.observation_digest) return false;
    const sig = base64ToBytes(receipt.observation_signature);
    const pub = base64ToBytes(relayPublicKeyB64);
    return await ed.verifyAsync(sig, canonical, pub);
  } catch {
    return false;
  }
}
