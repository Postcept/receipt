// Independent verification of an evidence export: the signed manifest, plus a check
// that its content digest still matches the receipts in the bundle, so nothing was
// added, trimmed, or swapped.
import * as ed from "@noble/ed25519";
import { base64ToBytes, canonicalize, sha256Hex, TIMESTAMP_SPELLINGS } from "./canonical.js";
import type { Receipt } from "./receipt.js";

const MANIFEST_TYPE = "postcept-evidence-manifest";

export interface VcrSummaryLike {
  verified_completion_rate: number;
}

export interface EvidenceManifest {
  type?: string;
  org_id?: string | null;
  generated_at: string;
  verification_count: number;
  vcr: VcrSummaryLike;
  audit_chain_intact: boolean;
  transparency_tree_size: number;
  transparency_root: string;
  content_digest: string;
  algorithm?: string;
  signing_key_id?: string;
  signature: string;
}

export interface EvidenceExportLike {
  manifest: EvidenceManifest;
  verifications: Array<{ receipt: Pick<Receipt, "id" | "signature"> }>;
}

/** Recompute the content digest over a bundle's receipts (sorted id + signature). */
export async function evidenceContentDigest(
  verifications: EvidenceExportLike["verifications"]
): Promise<string> {
  const lines = verifications.map((v) => `${v.receipt.id}\n${v.receipt.signature}`).sort();
  return sha256Hex(new TextEncoder().encode(lines.join("\n")));
}

function manifestBody(m: EvidenceManifest, generatedAt: string): Record<string, unknown> {
  return {
    type: MANIFEST_TYPE,
    org_id: m.org_id ?? null,
    generated_at: generatedAt,
    verification_count: m.verification_count,
    vcr_bps: Math.round(m.vcr.verified_completion_rate * 10000),
    audit_chain_intact: m.audit_chain_intact,
    transparency_tree_size: m.transparency_tree_size,
    transparency_root: m.transparency_root,
    content_digest: m.content_digest,
  };
}

/** Verify just the manifest's Ed25519 signature against the published key. */
export async function verifyEvidenceManifest(
  manifest: EvidenceManifest,
  publicKeyB64: string
): Promise<boolean> {
  try {
    const sig = base64ToBytes(manifest.signature);
    const pub = base64ToBytes(publicKeyB64);
    for (const ts of TIMESTAMP_SPELLINGS) {
      const msg = new TextEncoder().encode(
        canonicalize(manifestBody(manifest, ts(manifest.generated_at)))
      );
      // eslint-disable-next-line no-await-in-loop
      if (await ed.verifyAsync(sig, msg, pub)) return true;
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Fully verify an evidence export: the manifest is signed by Postcept, and its
 * signed content digest still matches the receipts actually in the bundle.
 */
export async function verifyEvidenceExport(
  exported: EvidenceExportLike,
  publicKeyB64: string
): Promise<boolean> {
  const digest = await evidenceContentDigest(exported.verifications);
  if (digest !== exported.manifest.content_digest) return false;
  return verifyEvidenceManifest(exported.manifest, publicKeyB64);
}
