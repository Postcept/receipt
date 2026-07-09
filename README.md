# @postcept/receipt

A Postcept Receipt is a signed proof that an AI agent's high-risk action (a refund,
a cancellation, a credit) was checked against the system of record, and of what that
check found: verified, incomplete, duplicated, mismatched, or policy-failed. This
is the reference library for verifying one.

It runs anywhere JavaScript runs (browser, Node, Deno, edge), and verifying a
receipt needs nothing from Postcept except the published public key. No API call,
and no taking the agent's word for it. A valid signature proves the receipt is
authentic and unmodified since issue. See the spec for what that does and does not
cover.

The format and signing scheme are written up in [SPEC.md](./SPEC.md). This is the
canonical JS implementation of that spec. The Postcept API signs with a
byte-identical implementation in Python.

## Install

```sh
npm i @postcept/receipt
```

## Usage

```ts
import { verifyReceipt, verifyBadge, type Receipt } from "@postcept/receipt";

// Grab the public key once, or pin a key id from the receipt.
const { public_key } = await fetch("https://api.postcept.com/v1/signing-key").then((r) => r.json());

const ok = await verifyReceipt(receipt as Receipt, public_key);
// true when the receipt is authentic and unmodified.
```

`verifyReceipt` and `verifyBadge` are pure functions. On a bad signature or
malformed input they return `false` instead of throwing, so they're safe to call
on untrusted data.

## Exports

| Export | Purpose |
| --- | --- |
| `verifyReceipt` | Verify a receipt's Ed25519 signature against a public key. |
| `verifyBadge` | Verify a VCR-audit badge. |
| `verifyReceiptInLog` | Verify a receipt's transparency-log inclusion and signed tree head. |
| `verifyInclusion` / `verifySignedTreeHead` | Verify a Merkle inclusion proof or an STH on its own. |
| `verifyConsistency` | Verify the log only appended between two signed tree heads. |
| `receiptSigningBody` | The exact body the signature covers, for anyone re-implementing this. |
| `badgeSigningBody` | The badge signing body. |
| `canonicalize` | Deterministic JSON encoding (sorted keys, ASCII-escaped). |
| `@postcept/receipt/schema` | JSON Schema for the receipt object. |

## Why a separate package

One source of truth for the verification logic. Postcept's own site and audit tool
import this same package, and so can you. The "you don't have to trust us" claim
only holds if the reference implementation is open and stands on its own.

## Verifying a release

Every published version carries a signed npm provenance statement linking the
tarball to the commit and CI workflow that built it, plus a CycloneDX SBOM
attached to the GitHub release.

```sh
# Check the installed package's provenance and registry signatures:
npm audit signatures

# Inspect what shipped (attached to the GitHub release):
#   sbom.cyclonedx.json
```

The receipt format is verifiable on its own with the public key, as the spec
describes. Release provenance is a separate check that the code you installed is
the code this repo built.

## License

MIT.
