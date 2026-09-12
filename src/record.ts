/**
 * durable signed-record verification.
 *
 * Verifies the record export served with `?flavor=signed`: a JSON
 * envelope `{receipt, signature}` where `signature.value` is a
 * detached Ed25519 signature over the `overturo-jcs-1` canonical bytes
 * of the `receipt` member alone. Exports are stateless — each export
 * signs with the region's then-current key and historical keys stay
 * published — so verification resolves the stamped `key_version`
 * against a published key set, never blindly trusting the envelope's
 * own key copy.
 *
 * Key resolution is an explicit trust ladder (see VerifyRecordOpts):
 * supplied keys → key-discovery fetch (only from a caller-trusted
 * origin, since the discovery URL is envelope-supplied) → embedded-only
 * (opt-in, internal consistency, not issuance).
 */
import { RecordInvalid } from "./errors.js"
import { canonicalBytes } from "./canonical.js"
import { parseWithRawNumbers } from "./rawjson.js"

export interface SignedRecordSignature {
  algorithm: string
  canonicalization: string
  region: string
  key_version: string
  value: string
  public_key: string
  key_discovery?: string
  signed_at?: string
}

export interface SignedRecordEnvelope {
  receipt: Record<string, unknown>
  signature: SignedRecordSignature
}

export interface VerifyRecordOpts {
  /**
   * Published keys by key_version (`"us-1"` → standard-base64 raw
   * 32-byte key), e.g. previously fetched from the region's
   * key-discovery document. Offline mode; checked first.
   */
  publishedKeys?: Record<string, string>

  /**
   * Online mode: fetch the envelope's own `signature.key_discovery`
   * document and resolve the stamped key_version from its published
   * key list. Requires `discoveryOrigins` — the envelope supplies its
   * own discovery URL, so it is trusted ONLY when its origin is one the
   * caller independently trusts.
   */
  fetchKeyDiscovery?: boolean

  /**
   * Trusted origins for key-discovery, e.g. `["https://overturo.com"]`.
   * Required whenever `fetchKeyDiscovery` is set: the envelope carries
   * its own `signature.key_discovery` URL, so a forger who mints the
   * record also controls that URL. Fetching is refused unless the URL's
   * origin is listed here — otherwise `discovered` would prove no more
   * than `embedded` (a forger can serve a matching key). An absent or
   * empty list refuses discovery entirely.
   */
  discoveryOrigins?: string[]

  /**
   * Last-resort opt-in: verify against the envelope's embedded key
   * only. This proves INTERNAL CONSISTENCY (the envelope agrees with
   * itself), not issuance — a forger can mint a self-consistent
   * envelope. Never the default.
   */
  allowEmbeddedKey?: boolean

  /** Injectable fetch (tests / custom transport). */
  fetchFn?: typeof fetch
}

export interface VerifiedRecord {
  receipt: Record<string, unknown>
  /** `receipt.record.record_type` when present. */
  recordType?: string
  region: string
  keyVersion: string
  keySource: "supplied" | "discovered" | "embedded"
}

interface KeyDiscoveryDocument {
  keys?: Array<{ key_version?: string; public_key?: string }>
}

/**
 * Verify a signed record export.
 *
 * Pass the RAW response text (string or bytes) whenever you have it —
 * JavaScript's JSON.parse collapses number lexemes ("5.0" → 5 → "5"),
 * and authority records can carry non-integer numbers, so an envelope
 * verified from a pre-parsed object fails closed (`signature_failed`)
 * on such records even when it is authentic. String/bytes input is
 * always exact.
 */
export async function verifyRecord(
  envelope: string | Uint8Array | SignedRecordEnvelope | unknown,
  opts: VerifyRecordOpts = {}
): Promise<VerifiedRecord> {
  let canonicalSource: unknown = envelope
  let plainEnvelope: unknown = envelope

  if (typeof envelope === "string" || envelope instanceof Uint8Array) {
    const text = typeof envelope === "string" ? envelope : new TextDecoder().decode(envelope)
    try {
      canonicalSource = parseWithRawNumbers(text)
      plainEnvelope = JSON.parse(text)
    } catch {
      throw new RecordInvalid(
        "malformed_envelope",
        "input is not valid JSON — a dot-separated JWT string is the runtime receipt; verify it with verifyReceipt"
      )
    }
  }

  const { receipt: canonicalReceipt, signature } = parseEnvelope(canonicalSource)
  const { receipt } = parseEnvelope(plainEnvelope)

  if (signature.algorithm !== "Ed25519") {
    throw new RecordInvalid(
      "unsupported_algorithm",
      `signature.algorithm must be "Ed25519"; got ${JSON.stringify(signature.algorithm)}`
    )
  }
  if (signature.canonicalization !== "overturo-jcs-1") {
    throw new RecordInvalid(
      "unsupported_canonicalization",
      `signature.canonicalization must be "overturo-jcs-1"; got ${JSON.stringify(signature.canonicalization)}`
    )
  }

  const resolved = await resolveKey(signature, opts)

  const embeddedKey = decodeBase64Std(signature.public_key, "signature.public_key")
  if (resolved.source !== "embedded" && !bytesEqual(resolved.keyBytes, embeddedKey)) {
    throw new RecordInvalid(
      "key_mismatch",
      `envelope's embedded public_key disagrees with the published key for ${signature.key_version}`
    )
  }

  const signatureBytes = decodeBase64Std(signature.value, "signature.value")
  const ok = await verifyEd25519Raw(resolved.keyBytes, signatureBytes, canonicalBytes(canonicalReceipt))
  if (!ok) {
    throw new RecordInvalid("signature_failed", "Ed25519 signature verification failed")
  }

  const record = receipt["record"]
  const recordType =
    record !== null && typeof record === "object" && !Array.isArray(record)
      ? ((record as Record<string, unknown>)["record_type"] as string | undefined)
      : undefined

  return {
    receipt,
    recordType,
    // The region is the key_version prefix, NOT signature.region: key_version is
    // bound by verification (a changed version resolves a different key and
    // fails), whereas signature.region is unsigned and freely mutable.
    region: regionFromKeyVersion(signature.key_version),
    keyVersion: signature.key_version,
    keySource: resolved.source,
  }
}

// ── internals ──────────────────────────────────────────────────────

function parseEnvelope(envelope: unknown): SignedRecordEnvelope {
  if (envelope === null || typeof envelope !== "object" || Array.isArray(envelope)) {
    throw new RecordInvalid(
      "malformed_envelope",
      "signed record must be a JSON object with `receipt` and `signature` members " +
        "(a JWT string is the runtime receipt — verify it with verifyReceipt)"
    )
  }
  const { receipt, signature } = envelope as Record<string, unknown>
  if (receipt === null || typeof receipt !== "object" || Array.isArray(receipt)) {
    throw new RecordInvalid("malformed_envelope", "envelope missing `receipt` object")
  }
  if (signature === null || typeof signature !== "object" || Array.isArray(signature)) {
    throw new RecordInvalid("malformed_envelope", "envelope missing `signature` object")
  }
  const sig = signature as Record<string, unknown>
  for (const member of ["algorithm", "canonicalization", "region", "key_version", "value", "public_key"]) {
    if (typeof sig[member] !== "string") {
      throw new RecordInvalid("malformed_envelope", `signature.${member} must be a string`)
    }
  }
  return { receipt: receipt as Record<string, unknown>, signature: sig as unknown as SignedRecordSignature }
}

async function resolveKey(
  signature: SignedRecordSignature,
  opts: VerifyRecordOpts
): Promise<{ keyBytes: Uint8Array; source: VerifiedRecord["keySource"] }> {
  if (opts.publishedKeys) {
    const published = opts.publishedKeys[signature.key_version]
    if (published === undefined) {
      throw new RecordInvalid(
        "unknown_key_version",
        `key_version ${signature.key_version} not in the supplied published key set`
      )
    }
    return { keyBytes: decodeBase64Std(published, "publishedKeys entry"), source: "supplied" }
  }

  if (opts.fetchKeyDiscovery) {
    const url = signature.key_discovery
    if (!url) {
      throw new RecordInvalid("key_discovery_failed", "envelope carries no key_discovery URL")
    }
    // The discovery URL comes from the envelope, which a forger controls. Only
    // fetch it when its origin is one the caller independently trusts —
    // otherwise `discovered` is exactly as weak as `embedded`.
    assertTrustedDiscoveryOrigin(url, opts.discoveryOrigins)
    const fetchFn = opts.fetchFn ?? fetch
    let document: KeyDiscoveryDocument
    try {
      const response = await fetchFn(url)
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
      }
      document = (await response.json()) as KeyDiscoveryDocument
    } catch (e) {
      throw new RecordInvalid(
        "key_discovery_failed",
        `could not fetch key discovery from ${url}: ${e instanceof Error ? e.message : String(e)}`
      )
    }
    const entry = (document.keys ?? []).find((k) => k.key_version === signature.key_version)
    if (!entry || typeof entry.public_key !== "string") {
      throw new RecordInvalid(
        "unknown_key_version",
        `key_version ${signature.key_version} not in the published key list at ${url}`
      )
    }
    return { keyBytes: decodeBase64Std(entry.public_key, "published key"), source: "discovered" }
  }

  if (opts.allowEmbeddedKey) {
    return { keyBytes: decodeBase64Std(signature.public_key, "signature.public_key"), source: "embedded" }
  }

  throw new RecordInvalid(
    "no_key_source",
    "no key source: pass publishedKeys, set fetchKeyDiscovery, or explicitly opt into allowEmbeddedKey " +
      "(embedded-only proves internal consistency, not issuance)"
  )
}

async function verifyEd25519Raw(
  publicKeyBytes: Uint8Array,
  signatureBytes: Uint8Array,
  messageBytes: Uint8Array
): Promise<boolean> {
  // A wrong-length key is a malformed envelope, not a signature failure — say so
  // before importKey (which would otherwise surface it as signature_failed).
  if (publicKeyBytes.length !== 32) {
    throw new RecordInvalid("malformed_envelope", "public key is not a 32-byte Ed25519 key")
  }
  let cryptoKey: CryptoKey
  try {
    cryptoKey = await crypto.subtle.importKey(
      "raw",
      publicKeyBytes as BufferSource,
      { name: "Ed25519" } as AlgorithmIdentifier,
      false,
      ["verify"]
    )
  } catch {
    throw new RecordInvalid("signature_failed", "public key is not a valid raw Ed25519 key")
  }
  // WebCrypto's Secure Curves spec does not guarantee verify() returns false
  // (vs. throwing) for a malformed signature; a throw must read as a failed
  // signature, never an uncaught rejection.
  try {
    return await crypto.subtle.verify(
      { name: "Ed25519" } as AlgorithmIdentifier,
      cryptoKey,
      signatureBytes as BufferSource,
      messageBytes as BufferSource
    )
  } catch {
    return false
  }
}

/**
 * resolves true iff this runtime can verify Ed25519 signatures via
 * WebCrypto. The public record debugger's browser-support gate lives here, in
 * the package source that already carries the crypto-primitive firewall baseline
 * — so a first-party page never needs the literal. Imports a known-valid raw
 * public key (RFC 8032 section 7.1 Test 1); a successful import alone proves support.
 */
export async function probeSupport(): Promise<boolean> {
  if (typeof crypto === "undefined" || !crypto.subtle) return false
  const KNOWN_GOOD = new Uint8Array([
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72,
    0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
  ])
  try {
    await crypto.subtle.importKey(
      "raw",
      KNOWN_GOOD as BufferSource,
      { name: "Ed25519" } as AlgorithmIdentifier,
      false,
      ["verify"]
    )
    return true
  } catch {
    return false
  }
}

/** The region is the key_version prefix (`"us-1"` → `"us"`). */
function regionFromKeyVersion(keyVersion: string): string {
  const dash = keyVersion.indexOf("-")
  return dash > 0 ? keyVersion.slice(0, dash) : keyVersion
}

/**
 * Refuse a key-discovery URL whose origin the caller has not declared trusted.
 * The URL is envelope-supplied (forger-controlled), so without this gate a fully
 * forged record would verify as `discovered` — a rung the API presents as
 * stronger than `embedded`.
 */
function assertTrustedDiscoveryOrigin(url: string, trusted?: string[]): void {
  if (!trusted || trusted.length === 0) {
    throw new RecordInvalid(
      "key_discovery_failed",
      "fetchKeyDiscovery requires discoveryOrigins: the envelope supplies its own key_discovery URL, " +
        "so it is trusted only when its origin is one the caller independently trusts"
    )
  }
  let origin: string
  try {
    origin = new URL(url).origin
  } catch {
    throw new RecordInvalid("key_discovery_failed", `key_discovery is not a valid URL: ${url}`)
  }
  const allowed = trusted.some((o) => {
    try {
      return new URL(o).origin === origin
    } catch {
      return false
    }
  })
  if (!allowed) {
    throw new RecordInvalid(
      "key_discovery_failed",
      `key_discovery origin ${origin} is not in the trusted discoveryOrigins`
    )
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number)
  return diff === 0
}

/** Standard-alphabet base64 (the envelope's encoding — NOT base64url). */
export function decodeBase64Std(input: string, what: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(input)) {
    throw new RecordInvalid("malformed_envelope", `${what} is not standard base64`)
  }
  let binary: string
  try {
    binary = atob(input)
  } catch {
    throw new RecordInvalid("malformed_envelope", `${what} is not decodable base64`)
  }
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}
