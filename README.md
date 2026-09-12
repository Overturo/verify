> **Release mirror.** This repository is a read-only snapshot of
> `@overturo/verify` 0.4.1, published from Overturo's main
> development repository. Issues and pull requests are welcome here; accepted
> changes are ported upstream and appear in the next release snapshot.
> Security reports: see [SECURITY.md](./SECURITY.md).

# @overturo/verify

**Documentation:** <https://overturo.com/developers/agent-authorization> · **API reference:** <https://overturo.com/developers/openapi>

Standalone Overturo receipt-verification library. Zero runtime dependencies; Apache-2.0.

**Learn more:** [AI Agent Authorization by Overturo](https://overturo.com/agent-authorization) — protocol overview, the three `iss_role` values + their trust weights, and the full counterparty integration guide.

Two artifacts, two entry points:

- **`verifyReceipt`** — the **runtime receipt**: the short-lived EdDSA-signed JWT issued by the oversight service. Its TTL bounds *honoring*, not evidence — an expired runtime receipt still verifies cryptographically forever.
- **`verifyRecord`** — the **durable record** (the Authorization Receipt, and its consent/notice siblings): the signed record export downloaded with `?flavor=signed`, a JSON envelope with a detached signature over canonical bytes. Verifies fully offline against published keys.

Each entry point rejects the other's artifact with a typed error. Suitable for counterparty verifiers who don't want the full `@overturo/sdk` as a dependency; field semantics live in the Receipt Interop & Verification guide (published with the developer documentation).

## Install

```bash
npm install @overturo/verify
```

## Usage

```typescript
import { verifyReceipt } from "@overturo/verify"

const verified = await verifyReceipt(receiptJwt, {
  jwksUrl: "https://overturo.us/.well-known/jwks.json",
})

console.log(verified.iss_role)      // "authorizer" | "witness" | "approval_url_signer"
console.log(verified.trust_weight)  // "strong" | "witness_only" | "approval_url"
```

`trust_weight` mapping:

- `iss_role: "authorizer"` → `trust_weight: "strong"` — Overturo decided (Conductor mode)
- `iss_role: "witness"` → `trust_weight: "witness_only"` — client decided + Overturo witnessed (Oversight mode)
- `iss_role: "approval_url_signer"` → `trust_weight: "approval_url"` — signed approval-URL token, not a decision receipt

## Throws (`ReceiptInvalid`)

- Missing `iss_role` claim
- Unknown `iss_role` value
- Expired (`exp < now`)
- Issued in the future (`iat > now + clockSkewSeconds`)
- Signature verification fails
- `kid` not in JWKS (after refetch)

## Offline verification

Pass `jwks` directly instead of `jwksUrl`:

```typescript
const verified = await verifyReceipt(receiptJwt, {
  jwks: { keys: [/* ... */] },
})
```

## Verifying durable records (`verifyRecord`)

The signed record export (`?flavor=signed`) verifies against the issuer's published keys. Pass the **raw response text** — JavaScript's `JSON.parse` collapses number lexemes (`5.0` → `5`), and records can carry non-integer numbers, so a pre-parsed object fails closed on such records; string input is always exact.

```typescript
import { verifyRecord } from "@overturo/verify"

// Offline: keys you previously fetched from the region's key-discovery
// document, keyed by key_version.
const verified = await verifyRecord(rawEnvelopeText, {
  publishedKeys: { "us-1": "<base64 raw key>" },
})

// Online: resolve the envelope's own key-discovery URL. The URL is
// envelope-supplied (a forger controls it), so you MUST declare the origins you
// trust — an unlisted origin is refused, keeping `discovered` stronger than
// `embedded`.
const alsoVerified = await verifyRecord(rawEnvelopeText, {
  fetchKeyDiscovery: true,
  discoveryOrigins: ["https://overturo.com"],
})

console.log(verified.recordType) // "authorization_record" | "consent_record" | "notice_record"
console.log(verified.keySource)  // "supplied" | "discovered"
```

`allowEmbeddedKey: true` verifies against the envelope's own key copy — that proves **internal consistency only**, not issuance, and is never the default. Failures throw `RecordInvalid` with a typed `code` (`signature_failed`, `key_mismatch`, `unknown_key_version`, `malformed_envelope`, …); a JWT handed to `verifyRecord` (or an envelope handed to `verifyReceipt`) is a typed refusal, not a crash.

`verifyManifestPin(pin, publishedManifest)` recomputes a published capability-manifest version's content hash against the pin a record carries (`manifestContentHash` is the bare hasher). Cross-language byte-parity is pinned by the shared corpus under `lib/sdk/shared/conformance/signed_records/`.

## License

Apache-2.0
