/**
 * verification errors.
 *
 * Single class for every verification failure; `code` discriminates.
 * Counterparty verifiers branch on `code` for policy logic; humans
 * read `message`.
 */
export type ReceiptInvalidCode =
  | "missing_iss_role"
  | "unknown_iss_role"
  | "expired"
  | "future_issued"
  | "signature_failed"
  | "unknown_kid"
  | "malformed_jwt"
  | "unsupported_algorithm"
  | "jwks_fetch_failed"
  | "issuer_not_allowed"
  | "audience_mismatch"

export class ReceiptInvalid extends Error {
  readonly code: ReceiptInvalidCode

  constructor(code: ReceiptInvalidCode, message: string) {
    super(message)
    this.name = "ReceiptInvalid"
    this.code = code
    Object.setPrototypeOf(this, ReceiptInvalid.prototype)
  }
}

/**
 * signed-record verification errors. One class per
 * artifact: `ReceiptInvalid` is the runtime receipt (a JWT),
 * `RecordInvalid` is the durable signed record export (a JSON envelope
 * with a detached signature over canonical bytes). JWT-shaped input to
 * the record verifier is a typed `malformed_envelope`, and vice versa.
 *
 * The code strings are the shared cross-language vocabulary — the
 * corpus manifest's `expect` values and the Python `RecordInvalid`
 * reason codes use the same strings.
 */
export type RecordInvalidCode =
  | "malformed_envelope"
  | "unsupported_algorithm"
  | "unsupported_canonicalization"
  | "no_key_source"
  | "unknown_key_version"
  | "key_mismatch"
  | "key_discovery_failed"
  | "signature_failed"
  | "manifest_hash_mismatch"
  | "malformed_manifest"

export class RecordInvalid extends Error {
  readonly code: RecordInvalidCode

  constructor(code: RecordInvalidCode, message: string) {
    super(message)
    this.name = "RecordInvalid"
    this.code = code
    Object.setPrototypeOf(this, RecordInvalid.prototype)
  }
}
