/**
 * JWT parse + Ed25519 verify.
 *
 * Uses Web Crypto API (Node 20+ ships `crypto.subtle`; modern
 * browsers do too). No JOSE library dependency.
 */
import { ReceiptInvalid } from "./errors.js"
import type { JwksKey } from "./types.js"

interface ParsedJwt {
  header: {
    alg: string
    kid?: string
    typ?: string
  }
  payload: Record<string, unknown>
  signatureBytes: Uint8Array
  signedBytes: Uint8Array
}

export function parseJwt(jwt: string): ParsedJwt {
  const parts = jwt.split(".")
  if (parts.length !== 3) {
    throw new ReceiptInvalid("malformed_jwt", "JWT must have exactly 3 dot-separated parts")
  }
  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string]

  let header: ParsedJwt["header"]
  let payload: ParsedJwt["payload"]
  try {
    header = JSON.parse(decodeBase64UrlString(headerB64))
    payload = JSON.parse(decodeBase64UrlString(payloadB64))
  } catch (e) {
    throw new ReceiptInvalid("malformed_jwt", "JWT header or payload is not valid base64url-encoded JSON")
  }

  if (typeof header.alg !== "string") {
    throw new ReceiptInvalid("malformed_jwt", "JWT header missing `alg`")
  }

  const signatureBytes = decodeBase64Url(signatureB64)
  const signedBytes = new TextEncoder().encode(`${headerB64}.${payloadB64}`)

  return { header, payload, signatureBytes, signedBytes }
}

/**
 * Verify Ed25519 signature against a JWKS key. Returns boolean (does
 * NOT throw on verification failure; caller wraps the result in a
 * `ReceiptInvalid` if needed).
 */
export async function verifyEd25519(
  signedBytes: Uint8Array,
  signatureBytes: Uint8Array,
  key: JwksKey
): Promise<boolean> {
  if (key.kty !== "OKP" || key.crv !== "Ed25519") {
    throw new ReceiptInvalid(
      "unsupported_algorithm",
      `JWKS key must be {kty: OKP, crv: Ed25519}; got {kty: ${key.kty}, crv: ${key.crv ?? "(none)"}}`
    )
  }
  if (!key.x) {
    throw new ReceiptInvalid("malformed_jwt", "JWKS key missing `x` parameter (public key bytes)")
  }

  const publicKeyBytes = decodeBase64Url(key.x)

  // Build a raw Ed25519 public key for SubtleCrypto. The
  // `as BufferSource` casts work around TypeScript 5.7+'s narrower
  // `BufferSource = ArrayBuffer | ...` typing; `Uint8Array` IS a
  // BufferSource at runtime regardless of which ArrayBufferLike
  // backs it.
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    publicKeyBytes as BufferSource,
    { name: "Ed25519" } as AlgorithmIdentifier,
    false,
    ["verify"]
  )

  return crypto.subtle.verify(
    { name: "Ed25519" } as AlgorithmIdentifier,
    cryptoKey,
    signatureBytes as BufferSource,
    signedBytes as BufferSource
  )
}

// ── base64url helpers ──────────────────────────────────────────────

function decodeBase64Url(input: string): Uint8Array {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((input.length + 3) % 4)
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

function decodeBase64UrlString(input: string): string {
  return new TextDecoder().decode(decodeBase64Url(input))
}
