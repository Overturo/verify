/**
 * `verifyReceipt` main entry.
 *
 * Validates: JWT structure, signature (Ed25519), `iss_role` claim
 * presence + closed-enum membership, temporal claims (`iat` / `exp`
 * with configurable clock skew). Returns the verified payload
 * augmented with the computed `trust_weight`.
 */
import { ReceiptInvalid } from "./errors.js"
import { ISS_ROLE_TO_TRUST_WEIGHT, isValidIssRole } from "./iss-role.js"
import { JwksCache } from "./jwks.js"
import { parseJwt, verifyEd25519 } from "./jwt.js"
import type { IssRole, Jwks, VerifiedReceipt, VerifyOpts } from "./types.js"

// Module-singleton cache so multiple `verifyReceipt` calls share JWKS.
// Tests may import + clear via `_resetJwksCache()`.
let globalCache = new JwksCache()

export async function verifyReceipt(jwt: string, opts: VerifyOpts): Promise<VerifiedReceipt> {
  if (!opts.jwksUrl && !opts.jwks && !opts.issuerJwks) {
    throw new ReceiptInvalid("jwks_fetch_failed", "Either `jwksUrl`, `jwks`, or `issuerJwks` must be supplied")
  }

  const { header, payload, signatureBytes, signedBytes } = parseJwt(jwt)

  if (header.alg !== "EdDSA") {
    throw new ReceiptInvalid("unsupported_algorithm", `Receipts MUST be signed with EdDSA (Ed25519); got ${header.alg}`)
  }
  if (!header.kid) {
    throw new ReceiptInvalid("malformed_jwt", "JWT header missing `kid`")
  }

  if (!("iss_role" in payload)) {
    throw new ReceiptInvalid(
      "missing_iss_role",
      "Missing required iss_role claim — refusing to verify witness/authorizer-ambiguous receipt"
    )
  }
  if (!isValidIssRole(payload.iss_role)) {
    throw new ReceiptInvalid("unknown_iss_role", `Unknown iss_role: ${String(payload.iss_role)}`)
  }

  // Look up the verification key: prefer the presenting issuer's own
  // published key (per-region, no callback) when an issuer key set is supplied.
  const issuerJwks = opts.issuerJwks?.[payload.iss as string]
  const key = issuerJwks
    ? findKeyInJwks(issuerJwks, header.kid)
    : opts.jwks
      ? findKeyInJwks(opts.jwks, header.kid)
      : await resolveCache(opts).findKey(opts.jwksUrl as string, header.kid)

  const verified = await verifyEd25519(signedBytes, signatureBytes, key)
  if (!verified) {
    throw new ReceiptInvalid("signature_failed", "Ed25519 signature verification failed")
  }

  validateTemporal(payload, opts.clockSkewSeconds ?? 300)
  validateIssuerAudience(payload, opts)

  const issRole = payload.iss_role as IssRole
  return {
    ...(payload as Omit<VerifiedReceipt, "trust_weight" | "iss_role">),
    iss: payload.iss as string,
    iat: payload.iat as number,
    iss_role: issRole,
    trust_weight: ISS_ROLE_TO_TRUST_WEIGHT[issRole],
  }
}

function findKeyInJwks(jwks: Jwks, kid: string) {
  const key = jwks.keys.find((k) => k.kid === kid)
  if (!key) {
    throw new ReceiptInvalid("unknown_kid", `JWKS has no key with kid=${kid}`)
  }
  return key
}

function resolveCache(opts: VerifyOpts): JwksCache {
  // Per-call cache overrides not supported in v0.1 — the global cache
  // is keyed by URL so multiple consumers (different issuers) coexist.
  if (opts.jwksCacheTtlSeconds !== undefined) {
    // Reset with a fresh TTL only when the caller asked for one.
    globalCache = new JwksCache(opts.jwksCacheTtlSeconds)
  }
  return globalCache
}

function validateTemporal(payload: Record<string, unknown>, clockSkewSeconds: number) {
  const now = Math.floor(Date.now() / 1000)

  const iat = payload.iat
  if (typeof iat === "number" && iat > now + clockSkewSeconds) {
    throw new ReceiptInvalid("future_issued", `Receipt iat=${iat} is in the future (now=${now})`)
  }

  const exp = payload.exp
  if (typeof exp === "number" && exp + clockSkewSeconds < now) {
    throw new ReceiptInvalid("expired", `Receipt exp=${exp} has elapsed (now=${now})`)
  }
}

// G8 — optional issuer + audience validation. Both opts default to
// "not validated" so existing callers don't break; counterparties
// SHOULD set them to defend against malicious receipts.
function validateIssuerAudience(payload: Record<string, unknown>, opts: VerifyOpts) {
  if (opts.expectedIssuer !== undefined) {
    const allowed = Array.isArray(opts.expectedIssuer) ? opts.expectedIssuer : [opts.expectedIssuer]
    const issuer = payload.iss
    if (typeof issuer !== "string" || !allowed.includes(issuer)) {
      throw new ReceiptInvalid(
        "issuer_not_allowed",
        `Receipt iss=${JSON.stringify(issuer)} not in allowed set ${JSON.stringify(allowed)}`
      )
    }
  }
  if (opts.audience !== undefined) {
    const allowed = Array.isArray(opts.audience) ? opts.audience : [opts.audience]
    const aud = payload.aud
    if (typeof aud !== "string" || !allowed.includes(aud)) {
      throw new ReceiptInvalid(
        "audience_mismatch",
        `Receipt aud=${JSON.stringify(aud)} not in allowed set ${JSON.stringify(allowed)}`
      )
    }
  }
}

// Test-only: reset the global cache between specs.
export function _resetJwksCache(): void {
  globalCache = new JwksCache()
}
