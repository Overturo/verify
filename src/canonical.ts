/**
 * `overturo-jcs-1` canonical bytes.
 *
 * NOT RFC 8785. The five published rules (Receipt Interop &
 * Verification guide): object keys deep-sorted BYTEWISE on their UTF-8
 * encoding, array order preserved, compact separators only, non-ASCII
 * emitted raw (never \uXXXX escapes), values serialized as the
 * platform serializes them — number LEXEMES are significant ("5.0"
 * stays "5.0"), which is why the verifier canonicalizes from raw
 * response text via `parseWithRawNumbers` (see rawjson.ts).
 *
 * The bytewise comparator is explicit (not the host's default string
 * sort, which compares UTF-16 code units) so supplementary-plane keys
 * could never reorder — the cross-language corpus in
 * `lib/sdk/shared/conformance/signed_records/` is the drift gate.
 */
import { RawJsonNumber } from "./rawjson.js"

const encoder = new TextEncoder()

function compareUtf8(a: string, b: string): number {
  const ab = encoder.encode(a)
  const bb = encoder.encode(b)
  const n = Math.min(ab.length, bb.length)
  for (let i = 0; i < n; i++) {
    const d = (ab[i] as number) - (bb[i] as number)
    if (d !== 0) return d
  }
  return ab.length - bb.length
}

function serialize(value: unknown): string {
  if (value instanceof RawJsonNumber) return value.text
  if (Array.isArray(value)) return `[${value.map(serialize).join(",")}]`
  if (value !== null && typeof value === "object") {
    const members = Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => compareUtf8(a, b))
      .map(([k, v]) => `${JSON.stringify(k)}:${serialize(v)}`)
    return `{${members.join(",")}}`
  }
  // Strings, booleans, null — and plain numbers, whose lexemes are
  // already lost if the caller parsed the JSON themselves (integer
  // values are safe; non-integer values need the raw-text path).
  return JSON.stringify(value) ?? "null"
}

/** overturo-jcs-1 canonical bytes of a JSON value. */
export function canonicalBytes(value: unknown): Uint8Array {
  // JSON.stringify per scalar is compact and emits non-ASCII raw —
  // byte-identical to Ruby's JSON.generate over the same value.
  return encoder.encode(serialize(value))
}
