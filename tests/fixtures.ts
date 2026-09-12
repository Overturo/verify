/**
 * Test fixtures — generate Ed25519 keypair + sign sample receipts.
 * Runs once per test process; pure Web Crypto, no external deps.
 */
import { webcrypto } from "node:crypto"
import type { Jwks } from "../src/types.js"

const subtle = webcrypto.subtle

interface Fixture {
  keypair: { publicKey: CryptoKey; privateKey: CryptoKey }
  jwks: Jwks
  kid: string
}

let fixturePromise: Promise<Fixture> | null = null

export async function getFixture(): Promise<Fixture> {
  if (!fixturePromise) {
    fixturePromise = createFixture()
  }
  return fixturePromise
}

async function createFixture(): Promise<Fixture> {
  // @ts-expect-error — Node's webcrypto types don't fully cover Ed25519
  const keypair = (await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair

  // Export the public key as raw bytes for JWKS `x` parameter.
  const publicRaw = new Uint8Array(await subtle.exportKey("raw", keypair.publicKey))
  const kid = "test-key-1"
  const jwks: Jwks = {
    keys: [
      {
        kty: "OKP",
        crv: "Ed25519",
        x: encodeBase64Url(publicRaw),
        kid,
        alg: "EdDSA",
      },
    ],
  }

  return { keypair, jwks, kid }
}

/**
 * Sign a JWT payload with the fixture's Ed25519 private key.
 * Returns the compact-serialised JWT string.
 */
export async function signJwt(payload: Record<string, unknown>, opts: { kid?: string } = {}): Promise<string> {
  const fixture = await getFixture()
  const header = {
    alg: "EdDSA",
    typ: "JWT",
    kid: opts.kid ?? fixture.kid,
  }
  const headerB64 = encodeBase64Url(new TextEncoder().encode(JSON.stringify(header)))
  const payloadB64 = encodeBase64Url(new TextEncoder().encode(JSON.stringify(payload)))
  const signed = `${headerB64}.${payloadB64}`

  // @ts-expect-error — Node's webcrypto types don't fully cover Ed25519
  const signatureBuf = await subtle.sign(
    { name: "Ed25519" },
    fixture.keypair.privateKey,
    new TextEncoder().encode(signed)
  )
  const signatureB64 = encodeBase64Url(new Uint8Array(signatureBuf))

  return `${signed}.${signatureB64}`
}

/**
 * A canonical "valid" payload approximating a witness receipt.
 */
export function samplePayload(overrides: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000)
  return {
    iss: "https://overturo.us",
    iss_role: "witness",
    sub: "att_dev_test123",
    aud: "tp_dev_test456",
    iat: now,
    exp: now + 3600,
    jti: "jti-test-1",
    oap_ver: "1.0",
    decision: "allow",
    legal_basis: "consent",
    ...overrides,
  }
}

function encodeBase64Url(bytes: Uint8Array): string {
  // Convert to standard base64 then strip + replace.
  let binary = ""
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i] as number)
  }
  const standard = btoa(binary)
  return standard.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_")
}
