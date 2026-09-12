/**
 * unit coverage for verifyRecord's trust ladder and typed
 * refusals. Happy-path envelopes come from the committed corpus (the
 * server-generated fixtures), passed as RAW text — the exactness path;
 * malformed inputs are constructed inline. Pre-signature refusals
 * (shape, algorithm, key resolution) may use parsed-object input since
 * they throw before canonical bytes are computed.
 */
import { describe, expect, test } from "vitest"
import { existsSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { verifyRecord, verifyReceipt, ReceiptInvalid, RecordInvalid } from "../src/index.js"

// The shared corpus when this package sits next to it; the vendored copy otherwise.
const SHARED_CORPUS = join(__dirname, "..", "..", "shared", "conformance", "signed_records")
const CORPUS_DIR = existsSync(SHARED_CORPUS) ? SHARED_CORPUS : join(__dirname, "fixtures", "signed_records")

const manifest = JSON.parse(readFileSync(join(CORPUS_DIR, "manifest.json"), "utf8")) as {
  published_keys: Record<string, string>
}

function validEnvelopeRaw(): string {
  return readFileSync(join(CORPUS_DIR, "authorization_record_valid.json"), "utf8")
}

function validEnvelope(): Record<string, unknown> {
  return JSON.parse(validEnvelopeRaw())
}

// The origin of the corpus envelope's own key_discovery URL — the one a caller
// would legitimately trust.
function discoveryOrigin(): string {
  const sig = validEnvelope()["signature"] as Record<string, string>
  return new URL(sig["key_discovery"]).origin
}

async function codeOf(promise: Promise<unknown>): Promise<string> {
  try {
    await promise
    throw new Error("expected rejection")
  } catch (e) {
    if (e instanceof RecordInvalid) return e.code
    throw e
  }
}

describe("verifyRecord — trust ladder", () => {
  test("supplied keys mode verifies and reports keySource", async () => {
    const verified = await verifyRecord(validEnvelopeRaw(), { publishedKeys: manifest.published_keys })
    expect(verified.keySource).toBe("supplied")
    expect(verified.recordType).toBe("authorization_record")
    expect(verified.region).toBe("us")
  })

  test("bytes input verifies identically", async () => {
    const bytes = new TextEncoder().encode(validEnvelopeRaw())
    const verified = await verifyRecord(bytes, { publishedKeys: manifest.published_keys })
    expect(verified.keySource).toBe("supplied")
  })

  test("key-discovery mode fetches the envelope's own URL and matches the stamped version", async () => {
    const signature = validEnvelope()["signature"] as Record<string, string>
    let fetched: string | undefined
    const fetchFn = (async (url: string | URL | Request) => {
      fetched = String(url)
      return new Response(
        JSON.stringify({
          keys: Object.entries(manifest.published_keys).map(([key_version, public_key]) => ({
            key_version,
            public_key,
          })),
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      )
    }) as typeof fetch

    const verified = await verifyRecord(validEnvelopeRaw(), {
      fetchKeyDiscovery: true,
      discoveryOrigins: [discoveryOrigin()],
      fetchFn,
    })
    expect(verified.keySource).toBe("discovered")
    expect(fetched).toBe(signature["key_discovery"])
  })

  test("key-discovery refuses an envelope URL whose origin the caller does not trust (forgery guard)", async () => {
    // A forger controls signature.key_discovery, so an unlisted origin must be
    // refused BEFORE any fetch — otherwise `discovered` is as weak as `embedded`.
    const mustNotFetch = (async () => {
      throw new Error("must not fetch an untrusted discovery origin")
    }) as typeof fetch
    expect(
      await codeOf(
        verifyRecord(validEnvelopeRaw(), {
          fetchKeyDiscovery: true,
          discoveryOrigins: ["https://attacker.example"],
          fetchFn: mustNotFetch,
        })
      )
    ).toBe("key_discovery_failed")
  })

  test("key-discovery requires discoveryOrigins — a bare fetchKeyDiscovery is refused", async () => {
    const mustNotFetch = (async () => {
      throw new Error("must not fetch without a trusted-origins list")
    }) as typeof fetch
    expect(await codeOf(verifyRecord(validEnvelopeRaw(), { fetchKeyDiscovery: true, fetchFn: mustNotFetch }))).toBe(
      "key_discovery_failed"
    )
  })

  test("key-discovery failures are typed", async () => {
    const failing = (async () => new Response("nope", { status: 500 })) as typeof fetch
    expect(
      await codeOf(
        verifyRecord(validEnvelopeRaw(), {
          fetchKeyDiscovery: true,
          discoveryOrigins: [discoveryOrigin()],
          fetchFn: failing,
        })
      )
    ).toBe("key_discovery_failed")
  })

  test("a published list missing the stamped version is unknown_key_version", async () => {
    const empty = (async () => new Response(JSON.stringify({ keys: [] }), { status: 200 })) as typeof fetch
    expect(
      await codeOf(
        verifyRecord(validEnvelopeRaw(), {
          fetchKeyDiscovery: true,
          discoveryOrigins: [discoveryOrigin()],
          fetchFn: empty,
        })
      )
    ).toBe("unknown_key_version")
  })

  test("embedded-only mode requires the explicit opt-in", async () => {
    expect(await codeOf(verifyRecord(validEnvelopeRaw(), {}))).toBe("no_key_source")
    const verified = await verifyRecord(validEnvelopeRaw(), { allowEmbeddedKey: true })
    expect(verified.keySource).toBe("embedded")
  })

  test("supplied keys take precedence over discovery and embedded", async () => {
    const neverFetch = (async () => {
      throw new Error("must not fetch")
    }) as typeof fetch
    const verified = await verifyRecord(validEnvelopeRaw(), {
      publishedKeys: manifest.published_keys,
      fetchKeyDiscovery: true,
      allowEmbeddedKey: true,
      fetchFn: neverFetch,
    })
    expect(verified.keySource).toBe("supplied")
  })

  test("region is the bound key_version prefix, not the unsigned signature.region", async () => {
    // Only `receipt` is signed; signature.region is freely mutable. The corpus
    // receipt carries no `region`, so this raw-text swap changes only the
    // signature block — verification still passes, but the authenticated region
    // must follow key_version ("us-1" → "us"), never the tampered "eu".
    const tampered = validEnvelopeRaw().replace(/"region":\s*"us"/, '"region":"eu"')
    expect(tampered).not.toBe(validEnvelopeRaw())
    const verified = await verifyRecord(tampered, { publishedKeys: manifest.published_keys })
    expect(verified.region).toBe("us")
    expect(verified.keyVersion).toBe("us-1")
  })

  test("a valid-base64 but wrong-length public key is malformed_envelope, not signature_failed", async () => {
    const env = validEnvelope()
    ;(env["signature"] as Record<string, unknown>)["public_key"] = "AAAA" // valid base64, 3 bytes ≠ 32
    expect(await codeOf(verifyRecord(env, { allowEmbeddedKey: true }))).toBe("malformed_envelope")
  })
})

describe("verifyRecord — typed refusals", () => {
  test("wrong algorithm tag", async () => {
    const envelope = validEnvelope()
    ;(envelope["signature"] as Record<string, unknown>)["algorithm"] = "RS256"
    expect(await codeOf(verifyRecord(envelope, { allowEmbeddedKey: true }))).toBe("unsupported_algorithm")
  })

  test("wrong canonicalization tag", async () => {
    const envelope = validEnvelope()
    ;(envelope["signature"] as Record<string, unknown>)["canonicalization"] = "rfc8785"
    expect(await codeOf(verifyRecord(envelope, { allowEmbeddedKey: true }))).toBe("unsupported_canonicalization")
  })

  test("truncated envelope shapes", async () => {
    expect(await codeOf(verifyRecord({}, {}))).toBe("malformed_envelope")
    expect(await codeOf(verifyRecord({ receipt: {} }, {}))).toBe("malformed_envelope")
    expect(await codeOf(verifyRecord({ receipt: {}, signature: { algorithm: "Ed25519" } }, {}))).toBe(
      "malformed_envelope"
    )
    expect(await codeOf(verifyRecord([], {}))).toBe("malformed_envelope")
    expect(await codeOf(verifyRecord(null, {}))).toBe("malformed_envelope")
  })

  test("a JWT string is a typed cross-artifact refusal (not a crash)", async () => {
    expect(await codeOf(verifyRecord("eyJh.eyJi.c2ln", {}))).toBe("malformed_envelope")
  })

  test("an envelope object handed to verifyReceipt is the mirror-image refusal", async () => {
    await expect(verifyReceipt(JSON.stringify(validEnvelope()), { jwks: { keys: [] } })).rejects.toBeInstanceOf(
      ReceiptInvalid
    )
  })

  test("non-base64 signature material is malformed_envelope, not a crash", async () => {
    const envelope = validEnvelope()
    ;(envelope["signature"] as Record<string, unknown>)["value"] = "!!not-base64!!"
    expect(await codeOf(verifyRecord(envelope, { allowEmbeddedKey: true }))).toBe("malformed_envelope")
  })
})
