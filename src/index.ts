/**
 * @overturo/verify — standalone receipt-verification library.
 *
 * Two artifacts, two entry points:
 * `verifyReceipt` for the runtime receipt (a JWT), `verifyRecord` for
 * the durable signed record export (a JSON envelope with a detached
 * signature over canonical bytes).
 */
export { verifyReceipt, _resetJwksCache } from "./verify.js"
export { verifyRecord, decodeBase64Std, probeSupport } from "./record.js"
export { manifestContentHash, verifyManifestPin } from "./manifest.js"
export { canonicalBytes } from "./canonical.js"
export { ReceiptInvalid, RecordInvalid } from "./errors.js"
export { ISS_ROLES, ISS_ROLE_TO_TRUST_WEIGHT } from "./iss-role.js"
export { JwksCache } from "./jwks.js"
export type { VerifiedReceipt, VerifyOpts, Jwks, JwksKey, IssRole, TrustWeight } from "./types.js"
export type { ReceiptInvalidCode, RecordInvalidCode } from "./errors.js"
export type { SignedRecordEnvelope, SignedRecordSignature, VerifyRecordOpts, VerifiedRecord } from "./record.js"
