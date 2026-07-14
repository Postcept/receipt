// @postcept/receipt: open reference implementation for verifying Postcept Receipts
// and VCR-audit badges. Works in the browser, Node, Deno, and edge runtimes. See
// SPEC.md for the format and signing scheme.
export { asciiJson, base64ToBytes, canonicalize, TIMESTAMP_SPELLINGS } from "./canonical.js";
export {
  CANONICALIZATION_SCHEME,
  type Observation,
  type Postcondition,
  type Receipt,
  receiptSigningBody,
  verifyObservation,
  verifyReceipt,
} from "./receipt.js";
export { type AuditBadge, badgeSigningBody, verifyBadge } from "./badge.js";
export {
  type ConsistencyProof,
  type InclusionProof,
  type SignedTreeHead,
  receiptLeafHash,
  verifyConsistency,
  verifyInclusion,
  verifyReceiptInLog,
  verifySignedTreeHead,
} from "./transparency.js";
export {
  type EvidenceExportLike,
  type EvidenceManifest,
  evidenceContentDigest,
  verifyEvidenceExport,
  verifyEvidenceManifest,
} from "./evidence.js";
