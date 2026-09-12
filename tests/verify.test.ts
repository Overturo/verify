import { describe, expect, it, beforeEach } from "vitest"
import { ReceiptInvalid, _resetJwksCache, verifyReceipt } from "../src/index.js"
import { getFixture, samplePayload, signJwt } from "./fixtures.js"

describe("verifyReceipt", () => {
  beforeEach(() => _resetJwksCache())

  describe("happy paths (per iss_role)", () => {
    it("admits iss_role=witness and computes trust_weight=witness_only", async () => {
      const { jwks } = await getFixture()
      const jwt = await signJwt(samplePayload({ iss_role: "witness" }))

      const result = await verifyReceipt(jwt, { jwks })

      expect(result.iss_role).toBe("witness")
      expect(result.trust_weight).toBe("witness_only")
      expect(result.iss).toBe("https://overturo.us")
      expect(result.decision).toBe("allow")
    })

    it("admits iss_role=authorizer and computes trust_weight=strong", async () => {
      const { jwks } = await getFixture()
      const jwt = await signJwt(samplePayload({ iss_role: "authorizer" }))

      const result = await verifyReceipt(jwt, { jwks })

      expect(result.iss_role).toBe("authorizer")
      expect(result.trust_weight).toBe("strong")
    })

    it("admits iss_role=approval_url_signer and computes trust_weight=approval_url", async () => {
      const { jwks } = await getFixture()
      const jwt = await signJwt(samplePayload({ iss_role: "approval_url_signer" }))

      const result = await verifyReceipt(jwt, { jwks })

      expect(result.iss_role).toBe("approval_url_signer")
      expect(result.trust_weight).toBe("approval_url")
    })
  })

  describe("iss_role validation", () => {
    it("throws ReceiptInvalid('missing_iss_role') when claim absent", async () => {
      const { jwks } = await getFixture()
      const { iss_role: _, ...rest } = samplePayload()
      const jwt = await signJwt(rest)

      await expect(verifyReceipt(jwt, { jwks })).rejects.toThrowError(
        expect.objectContaining({ code: "missing_iss_role" })
      )
    })

    it("throws ReceiptInvalid('unknown_iss_role') when claim is unknown", async () => {
      const { jwks } = await getFixture()
      const jwt = await signJwt(samplePayload({ iss_role: "rogue_role" }))

      await expect(verifyReceipt(jwt, { jwks })).rejects.toThrowError(
        expect.objectContaining({ code: "unknown_iss_role" })
      )
    })
  })

  describe("signature verification", () => {
    it("throws ReceiptInvalid('signature_failed') when bytes are tampered", async () => {
      const { jwks } = await getFixture()
      const jwt = await signJwt(samplePayload())
      // Replace the entire signature with all-zeros. Swapping one
      // trailing base64 char isn't reliable — base64 padding may drop
      // the swap's bits depending on the signature's mod-4 length.
      const parts = jwt.split(".")
      const tamperedSig = "A".repeat(86) // 86 base64url chars ≈ 64-byte zero sig
      const tampered = `${parts[0]}.${parts[1]}.${tamperedSig}`

      await expect(verifyReceipt(tampered, { jwks })).rejects.toThrowError(ReceiptInvalid)
    })

    it("throws ReceiptInvalid('unknown_kid') when kid not in JWKS", async () => {
      const { jwks } = await getFixture()
      const jwt = await signJwt(samplePayload(), { kid: "rotated-key" })

      await expect(verifyReceipt(jwt, { jwks })).rejects.toThrowError(expect.objectContaining({ code: "unknown_kid" }))
    })

    it("throws ReceiptInvalid('unsupported_algorithm') for non-EdDSA alg header", async () => {
      const { jwks } = await getFixture()
      // Hand-build a JWT with alg=HS256
      const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT", kid: "x" }))
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
      const payload = btoa(JSON.stringify(samplePayload())).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_")
      const jwt = `${header}.${payload}.AAAA`

      await expect(verifyReceipt(jwt, { jwks })).rejects.toThrowError(
        expect.objectContaining({ code: "unsupported_algorithm" })
      )
    })
  })

  describe("temporal claims", () => {
    it("throws ReceiptInvalid('expired') when exp is in the past beyond clockSkew", async () => {
      const { jwks } = await getFixture()
      const past = Math.floor(Date.now() / 1000) - 4000
      const jwt = await signJwt(samplePayload({ iat: past, exp: past + 60 }))

      await expect(verifyReceipt(jwt, { jwks })).rejects.toThrowError(expect.objectContaining({ code: "expired" }))
    })

    it("admits a receipt whose exp elapsed but is within clockSkewSeconds", async () => {
      const { jwks } = await getFixture()
      const now = Math.floor(Date.now() / 1000)
      const jwt = await signJwt(samplePayload({ iat: now - 100, exp: now - 10 }))

      const result = await verifyReceipt(jwt, { jwks, clockSkewSeconds: 60 })
      expect(result.iss_role).toBe("witness")
    })

    it("throws ReceiptInvalid('future_issued') when iat exceeds now + clockSkew", async () => {
      const { jwks } = await getFixture()
      const future = Math.floor(Date.now() / 1000) + 10_000
      const jwt = await signJwt(samplePayload({ iat: future, exp: future + 3600 }))

      await expect(verifyReceipt(jwt, { jwks })).rejects.toThrowError(
        expect.objectContaining({ code: "future_issued" })
      )
    })
  })

  describe("JWT structural validation", () => {
    it("throws ReceiptInvalid('malformed_jwt') on a JWT missing parts", async () => {
      const { jwks } = await getFixture()
      await expect(verifyReceipt("not.a.complete-jwt-with-three", { jwks })).rejects.toThrowError(
        expect.objectContaining({ code: "malformed_jwt" })
      )
    })

    it("throws ReceiptInvalid on totally invalid input", async () => {
      const { jwks } = await getFixture()
      await expect(verifyReceipt("garbage", { jwks })).rejects.toThrowError(ReceiptInvalid)
    })
  })

  describe("opts validation", () => {
    it("throws when neither jwksUrl nor jwks is supplied", async () => {
      const jwt = await signJwt(samplePayload())
      await expect(verifyReceipt(jwt, {})).rejects.toThrowError(ReceiptInvalid)
    })
  })

  describe("forward-compat — additional claims preserved", () => {
    it("returns unknown claims unchanged on the VerifiedReceipt", async () => {
      const { jwks } = await getFixture()
      const jwt = await signJwt(samplePayload({ custom_field: "future-value", nested: { a: 1 } }))

      const result = await verifyReceipt(jwt, { jwks })

      expect(result.custom_field).toBe("future-value")
      expect(result.nested).toEqual({ a: 1 })
    })
  })

  describe("G8 — optional issuer + audience validation", () => {
    it("admits the receipt when expectedIssuer matches", async () => {
      const { jwks } = await getFixture()
      const jwt = await signJwt(samplePayload({ iss: "https://overturo.us" }))
      const result = await verifyReceipt(jwt, { jwks, expectedIssuer: "https://overturo.us" })
      expect(result.iss).toBe("https://overturo.us")
    })

    it("rejects when expectedIssuer doesn't match", async () => {
      const { jwks } = await getFixture()
      const jwt = await signJwt(samplePayload({ iss: "https://overturo.us" }))
      await expect(verifyReceipt(jwt, { jwks, expectedIssuer: "https://overturo.eu" })).rejects.toThrowError(
        expect.objectContaining({ code: "issuer_not_allowed" })
      )
    })

    it("accepts an array of expectedIssuers", async () => {
      const { jwks } = await getFixture()
      const jwt = await signJwt(samplePayload({ iss: "https://overturo.us" }))
      const result = await verifyReceipt(jwt, {
        jwks,
        expectedIssuer: ["https://overturo.eu", "https://overturo.us"],
      })
      expect(result.iss).toBe("https://overturo.us")
    })

    it("admits when audience matches", async () => {
      const { jwks } = await getFixture()
      const jwt = await signJwt(samplePayload({ aud: "tp_dev_xyz" }))
      const result = await verifyReceipt(jwt, { jwks, audience: "tp_dev_xyz" })
      expect(result.aud).toBe("tp_dev_xyz")
    })

    it("rejects when audience doesn't match", async () => {
      const { jwks } = await getFixture()
      const jwt = await signJwt(samplePayload({ aud: "tp_dev_other" }))
      await expect(verifyReceipt(jwt, { jwks, audience: "tp_dev_xyz" })).rejects.toThrowError(
        expect.objectContaining({ code: "audience_mismatch" })
      )
    })

    it("admits without validation when both opts omitted (back-compat)", async () => {
      const { jwks } = await getFixture()
      const jwt = await signJwt(samplePayload({ iss: "https://rogue.example" }))
      const result = await verifyReceipt(jwt, { jwks })
      expect(result.iss).toBe("https://rogue.example")
    })
  })

  // verify a presented credential against its issuer's own published
  // key (per region, no callback), resolved from the issuer set by `iss`.
  describe("per-issuer key resolution", () => {
    it("resolves the verification key from issuerJwks by the receipt's iss", async () => {
      const { jwks } = await getFixture()
      const jwt = await signJwt(samplePayload({ iss_role: "authorizer", iss: "https://overturo.eu" }))
      const result = await verifyReceipt(jwt, {
        issuerJwks: { "https://overturo.eu": jwks },
      })
      expect(result.iss).toBe("https://overturo.eu")
    })

    it("falls back to jwks when the issuer isn't in the issuer set", async () => {
      const { jwks } = await getFixture()
      const jwt = await signJwt(samplePayload({ iss_role: "authorizer", iss: "https://overturo.us" }))
      const result = await verifyReceipt(jwt, {
        jwks,
        issuerJwks: { "https://overturo.eu": { keys: [] } },
      })
      expect(result.iss).toBe("https://overturo.us")
    })
  })
})
