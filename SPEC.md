# Postcept Receipt: open verification standard

**Version 2. Status: stable.**

A Postcept Receipt is a signed, tamper-evident proof that a high-risk AI-agent
action (a refund, a cancellation, a ticket resolution) was checked against the
system of record and classified. This document specifies the receipt format and
how to verify it without going through Postcept: no API call required.

The point is independent verifiability. A customer, an auditor, or a counterparty
can check a receipt with nothing but the public key and the rules below.

## What a receipt proves, and what it doesn't

A valid signature proves the receipt was issued by the holder of the signing key
and has not been altered since. The named postconditions were evaluated against
the named system of record, classified as recorded, at the recorded time, for the
recorded tenant, in test or live mode as flagged. It does not on its own prove
that the source system answered truthfully, that the state stayed the same after
`valid_as_of` (a later receipt can supersede this one when re-verification finds
the truth changed), or that the action was appropriate in the first place. Trust
in the receipt is trust in the signing key. Verify against the published key
registry, and pin it if your risk model calls for that.

## 1. Signature scheme

- **Algorithm:** Ed25519 (`algorithm: "ed25519"`).
- **Signature:** base64-encoded raw 64-byte Ed25519 signature, in the `signature`
  field.
- **Public key:** base64-encoded raw 32-byte Ed25519 public key. Fetch the current
  key from `GET /v1/signing-key`, which returns `{ algorithm, key_id, public_key }`.
  `GET /v1/signing-keys` returns the full registry, the active key plus retired
  keys kept published so receipts signed before a rotation stay verifiable. Pick
  the entry whose `key_id` matches the receipt's `signing_key_id`.
- **Key id:** `ed25519:<first-16-chars-of-url-safe-base64(public_key)>`, in
  `signing_key_id`. A receipt names the key that signed it, so old receipts stay
  verifiable after a key rotation.

## 2. Canonicalization

The signature covers a deterministic encoding of the **signing body** (§3), not the
receipt JSON as transmitted. To reproduce the signed bytes:

1. Build the signing body object for the receipt's `version` (§3).
2. Encode it as **canonical JSON**:
   - object keys sorted lexicographically (by UTF-16 code unit)
   - no insignificant whitespace (separators `,` and `:`)
   - every non-ASCII character escaped as `\uXXXX` (i.e. `ensure_ascii`)
   - numbers as their shortest round-trip form, integers without a decimal point.
3. UTF-8 encode the resulting string. Those are the signed bytes.

This is what Python's `json.dumps(body, sort_keys=True, separators=(",", ":"))`
produces.

### Constraints and rejection

The scheme is injective over the value domain the signing bodies use, given these
constraints. A compliant verifier MUST reject anything outside them rather than
guess.

- **Numbers** are finite integers or decimals. `NaN`, `Infinity`, and `-Infinity`
  are not valid JSON and MUST be rejected, not serialized.
- **Strings** are valid UTF-8. Every code point outside printable ASCII is
  `\uXXXX`-escaped (surrogate pairs for astral characters), so the signed bytes
  are pure ASCII regardless of transport encoding.
- **Malformed input**, such as a non-base64 signature or public key, a
  wrong-length key, or a missing signed field, MUST cause verification to return
  `false` rather than throw. Both reference implementations do this.

Cross-language parity is checked from both sides against one fixed source of
truth. The golden vectors in `test/vectors/` carry a public key and a signature
over specific canonical bytes. The TypeScript suite verifies them and the Python
implementation verifies byte-identical copies, so a canonicalization drift in
either language fails its own vector test, not only the other's.

### Timestamps

Timestamps are ISO-8601 UTC. The signer emits a trailing `Z`
(`2026-06-26T13:24:54.847945Z`). Some JSON serializers re-spell UTC as `+00:00`, so
a verifier SHOULD try both spellings and accept the first that verifies.

## 3. Signing body

### Version 2 (current)

Signs the full evidence, the tenant, the real connector identity, and the test
flag. Neither the evidence nor the provenance can be altered without breaking the
signature, and a sandbox receipt can't be passed off as a live one.

```jsonc
{
  "version": "2",
  "id": "<id>",
  "org_id": "<org_id|null>",
  "operation_id": "<operation_id>",
  "agent_id": "<agent_id>",
  "action": "<refund|cancellation|ticket>",
  "connectors_checked": ["stripe"],
  "test": false,
  "postconditions": [
    {
      "name": "...",
      "category": "...|null",
      "status": "passed|failed|skipped",
      "expected": "...|null",
      "actual": "...|null",
    },
  ],
  "result": "<verified|incomplete|duplicated|mismatched|policy_failed>",
  "issued_at": "<iso8601-utc>",
  "valid_as_of": "<iso8601-utc|null>",
}
```

### Version 1 (legacy)

Predates the full-evidence body. Postconditions carry only `name` and `status`, and
`version`, `org_id`, `test`, `valid_as_of` are absent. A receipt with no `version`
field is treated as version 1.

```jsonc
{
  "id": "<id>",
  "operation_id": "<operation_id>",
  "agent_id": "<agent_id>",
  "action": "<action>",
  "connectors_checked": ["..."],
  "postconditions": [{ "name": "...", "status": "..." }],
  "result": "<result>",
  "issued_at": "<iso8601-utc>",
}
```

### Version 3 (dual-signature)

v3 adds the fields that were server-asserted metadata in v2 to the signed body,
so they become tamper-evident, and adds an optional observation role. A v3 receipt
has two signatures that verify independently.

- **Evaluation role.** Postcept's signature (the receipt's `signature` field) over
  the v3 signing body. This is what `verifyReceipt` checks.
- **Observation role.** Present only when a customer-side relay produced the source
  observation. The relay signs its observation envelope, and the receipt binds
  `{relay_id, key_id, digest, signature}` where `digest = "sha256:" + hex(sha256(
  canonicalize(envelope_signing_body)))` and `signature` is the relay's signature
  over that envelope. `verifyObservation(receipt, envelopeSigningBody, relayKey)`
  confirms the digest matches and the relay signature verifies. Neither signer can
  forge the other's statement. The relay attests it observed the source, and
  Postcept attests it evaluated that observation.

The v3 signing body is the v2 body with `version: "3"` plus:

```jsonc
{
  // ...all v2 fields...
  "version": "3",
  "algorithm": "ed25519",                 // the signature scheme, now signed
  "signing_key_id": "ed25519:...",        // the key that signed, now signed
  "canonicalization": "postcept-canonical-json-v1",  // the scheme in §2, now signed
  "supersedes": "<receipt_id | null>",
  "contract_digest": "sha256:... | null",
  "lifecycle": "finalized | pending_finality | ... | null",
  "safe_to_claim_complete": true,        // or false / null
  "correlation_strength": "deterministic | heuristic | ... | null",
  "observation": {                        // null when no relay produced the source
    "relay_id": "rly_...",
    "key_id": "ed25519:...",
    "digest": "sha256:...",
    "signature": "<base64 relay signature over the envelope>"
  }
}
```

v3 issuance is gated on the server. v1 and v2 receipts remain valid forever, and
the verifier dispatches on `version`. A verifier MAY require the observation role
(for high-assurance, relay-only acceptance) or accept evaluation-only receipts.

## 4. Verification algorithm

```
1. Select the signing body by `version` (absent means "1").
2. Canonicalize it (§2).
3. For each timestamp spelling, Ed25519-verify `signature` over the encoded body
   with the published public key.
4. The receipt is valid if any spelling verifies.
```

The reference is `verifyReceipt(receipt, publicKeyB64)` in this package. The
Postcept API verifies with the same body in Python, and the two are kept
byte-identical.

## 5. VCR-audit badge

A free-audit badge (`verifyBadge`) uses the same scheme over a separate, PII-free
body. The Verified Completion Rate is signed as an integer in basis points
(`verified_completion_rate_bps`, 0 to 10000), not a float, so it canonicalizes the
same way across languages even at whole-number rates.

```jsonc
{
  "type": "postcept-vcr-audit",
  "label": "<label|null>",
  "account_ref": "<fingerprint>",
  "connector": "stripe:<account_ref>",
  "sampled": 25,
  "verified_completion_rate_bps": 9434,
  "issued_at": "<iso8601-utc>",
}
```

## 6. Machine-readable schema

A JSON Schema for the receipt object ships at `@postcept/receipt/schema`
(`schema/receipt.schema.json`). It validates shape only. §2 to §4 govern the
signature.

## 7. Transparency log

Live receipts are appended to a public, append-only Merkle log (RFC 6962). It gives
an independent timestamp: anyone can show that a receipt was logged and was not
removed or back-dated, without taking Postcept's word for it.

- **Leaf hash** (hex): `SHA-256(0x00 || receipt_id || 0x0a || signature)`, where
  `signature` is the base64 string from the receipt. Reconstructible from the
  receipt alone.
- **Node hash:** `SHA-256(0x01 || left || right)`.
- **Merkle root:** RFC 6962 Merkle Tree Hash over the leaf hashes in log order.
- **Signed tree head (STH):** an Ed25519 signature (§1) over the canonical
  `{ "type": "postcept-sth", "tree_size", "root_hash", "timestamp" }`. Served at
  `GET /v1/transparency/sth`.
- **Inclusion proof:** `{ receipt_id, leaf_index, leaf_hash, tree_size, audit_path
  [hex, deepest sibling first], sth }`. Served at
  `GET /v1/transparency/proof/{receipt_id}`. Verify it by recomputing the root from
  the leaf and audit path, comparing to the STH `root_hash`, then checking the STH
  signature.
- **Consistency proof:** `{ first_size, second_size, first_root, second_root, proof
  [hex], sth }`. Served at `GET /v1/transparency/consistency?first={m}&second={n}`
  (`second` defaults to the current tree size). It proves the log at `second_size`
  is an append-only extension of the log at `first_size`. The earlier leaves are
  unchanged, and nothing was removed, reordered, or back-dated (RFC 6962 §2.1.2). A
  holder of an earlier signed tree head fetches a proof against it: verify the proof
  connects the two roots, then check that `first_root` equals the root they
  remembered and that the returned head is validly signed. Without this, inclusion
  proofs alone only bind a receipt to *whatever* root the operator serves now. The
  consistency proof is what makes "append-only" checkable rather than trusted.

Reference: `verifyReceiptInLog`, `verifyInclusion`, `verifyConsistency`,
`verifySignedTreeHead`, `receiptLeafHash` in this package.
