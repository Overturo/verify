/**
 * capability-manifest pin verification.
 *
 * A record's `extensions.capability_manifest` slot pins
 * `{reference, hash}`; the published manifest document (the
 * transparency endpoint's `overturo-acm/1` shape) carries the frozen
 * `content`. Verification is recompute-and-compare: hash the content's
 * `overturo-jcs-1` canonical bytes and match the pin. Pure hashing —
 * fetching the published document is the caller's two lines.
 */
import { RecordInvalid } from "./errors.js"
import { canonicalBytes } from "./canonical.js"

/**
 * `"sha256:<hex>"` over the overturo-jcs-1 canonical bytes.
 *
 * NOTE (mirrors the record path's number-lexeme lesson): `content` is an
 * already-parsed value, so if it was produced by `JSON.parse` a non-integer
 * number lexeme has already collapsed (`5.0` → `5`) and this would false-REJECT
 * an authentic manifest. Manifest `content` must therefore carry integer-valued
 * numbers only; a raw-text entry point (like verifyRecord's) is the follow-up if
 * that ever stops holding. Fail-closed either way — never a false-accept.
 */
export async function manifestContentHash(content: unknown): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", canonicalBytes(content) as BufferSource)
  const hex = Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
  return `sha256:${hex}`
}

/**
 * Recompute the published manifest's content hash and compare it to
 * the pin a record carries. Returns the recomputed hash on success;
 * throws `RecordInvalid("manifest_hash_mismatch")` when the published
 * content does not hash to the pinned value.
 */
export async function verifyManifestPin(
  pin: { reference?: string; hash?: string },
  publishedManifest: { content?: unknown }
): Promise<string> {
  if (typeof pin?.hash !== "string" || !pin.hash.startsWith("sha256:")) {
    throw new RecordInvalid("malformed_manifest", "pin.hash must be a sha256:<hex> string")
  }
  if (publishedManifest === null || typeof publishedManifest !== "object" || !("content" in publishedManifest)) {
    throw new RecordInvalid("malformed_manifest", "published manifest must carry `content`")
  }
  const recomputed = await manifestContentHash(publishedManifest.content)
  if (recomputed !== pin.hash) {
    throw new RecordInvalid(
      "manifest_hash_mismatch",
      `published content hashes to ${recomputed}, but the record pins ${pin.hash}`
    )
  }
  return recomputed
}
