/**
 * public types.
 */

export type IssRole = "authorizer" | "witness" | "approval_url_signer"

export type TrustWeight = "strong" | "witness_only" | "approval_url"

/**
 * Verified-receipt claim shape. Mirrors what
 * `Oap::WitnessReceiptService` / `Oap::EscalationApprovalUrlService`
 * emit, plus the SDK-computed `trust_weight`.
 */
export interface VerifiedReceipt {
  // Standard JWT claims
  iss: string
  iat: number
  exp?: number
  jti?: string
  sub?: string
  aud?: string

  // Overturo-specific claims
  iss_role: IssRole
  oap_ver?: string
  oap_conformance?: string
  attestation_digest?: string
  decision?: string
  legal_basis?: string
  policy_ref?: string
  policy_version?: string

  // SDK-computed
  trust_weight: TrustWeight

  // Any additional claims (forward-compat)
  [key: string]: unknown
}

export interface JwksKey {
  kty: string
  crv?: string
  x?: string
  kid: string
  alg?: string
  use?: string
}

export interface Jwks {
  keys: JwksKey[]
}

export interface VerifyOpts {
  /**
   * URL of the issuer's JWKS endpoint (`/.well-known/jwks.json`).
   * Required unless `jwks` is pre-supplied.
   */
  jwksUrl?: string

  /**
   * Pre-fetched JWKS. When provided, NO network fetch occurs.
   * Useful for offline verification + tests.
   */
  jwks?: Jwks

  /**
   * per-issuer published keys, for verifying credentials presented
   * from multiple issuers (each homed in its own region) against the *issuer's*
   * own published key, with no callback. Keyed by the receipt's `iss`. When the
   * receipt's issuer is present here, its JWKS is used (matched by `kid`, which
   * carries the issuer's key version); otherwise the SDK falls back to `jwks` /
   * `jwksUrl`. Single-issuer callers are unaffected.
   */
  issuerJwks?: Record<string, Jwks>

  /**
   * Tolerance for `iat` / `exp` clock skew, in seconds. Default 300 (5 min).
   */
  clockSkewSeconds?: number

  /**
   * Cache TTL for fetched JWKS, in seconds. Overrides any
   * Cache-Control: max-age on the JWKS response. Default 300 (5 min).
   */
  jwksCacheTtlSeconds?: number

  /**
   * Optional `iss` claim validation (G8). When supplied,
   * `verifyReceipt` rejects with `ReceiptInvalid("issuer_not_allowed")`
   * if the receipt's `iss` doesn't match (or isn't in the array).
   * Recommended for counterparty verifiers.
   */
  expectedIssuer?: string | string[]

  /**
   * Optional `aud` claim validation (G8). When supplied,
   * `verifyReceipt` rejects with `ReceiptInvalid("audience_mismatch")`
   * if the receipt's `aud` doesn't match (or isn't in the array).
   * Set this to your own client identifier so you don't accept
   * receipts issued to somebody else.
   */
  audience?: string | string[]
}
