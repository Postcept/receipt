// VCR-audit badge: a signed, PII-free summary of an audit run. Same signing scheme
// as a receipt. The rate is signed as integer basis points so it canonicalizes the
// same way across languages, even at whole-number rates.
import * as ed from "@noble/ed25519";
import { base64ToBytes, canonicalize, TIMESTAMP_SPELLINGS } from "./canonical.js";

export interface AuditBadge {
  label?: string | null;
  account_ref: string;
  connector: string;
  sampled: number;
  verified_completion_rate: number;
  issued_at: string;
  algorithm?: string;
  signing_key_id?: string;
  signature: string;
}

/** The exact, PII-free body the badge signature covers. */
export function badgeSigningBody(
  b: AuditBadge,
  ts: (s: string) => string
): Record<string, unknown> {
  return {
    type: "postcept-vcr-audit",
    label: b.label ?? null,
    account_ref: b.account_ref,
    connector: b.connector,
    sampled: b.sampled,
    verified_completion_rate_bps: Math.round(b.verified_completion_rate * 10000),
    issued_at: ts(b.issued_at),
  };
}

/** Verify a shareable badge against a published public key. */
export async function verifyBadge(badge: AuditBadge, publicKeyB64: string): Promise<boolean> {
  try {
    const sig = base64ToBytes(badge.signature);
    const pub = base64ToBytes(publicKeyB64);
    for (const ts of TIMESTAMP_SPELLINGS) {
      const msg = new TextEncoder().encode(canonicalize(badgeSigningBody(badge, ts)));
      // eslint-disable-next-line no-await-in-loop
      if (await ed.verifyAsync(sig, msg, pub)) return true;
    }
    return false;
  } catch {
    return false;
  }
}
