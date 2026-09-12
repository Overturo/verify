import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { JwksCache } from "../src/jwks.js"

describe("JwksCache", () => {
  let cache: JwksCache
  const URL = "https://overturo.us/.well-known/jwks.json"

  beforeEach(() => {
    cache = new JwksCache(60)
    vi.restoreAllMocks()
  })

  afterEach(() => vi.restoreAllMocks())

  function mockFetch(response: { keys: unknown[] }, init: { headers?: Record<string, string>; status?: number } = {}) {
    // Build a fresh Response on every call — Response bodies are
    // single-use; reusing the same instance across mock calls trips
    // "Body is unusable" on the second invocation.
    const fetchSpy = vi.spyOn(globalThis, "fetch" as any).mockImplementation(async () => {
      return new Response(JSON.stringify(response), {
        status: init.status ?? 200,
        headers: new Headers(init.headers ?? {}),
      })
    })
    return fetchSpy
  }

  it("fetches JWKS on first call", async () => {
    const fetchSpy = mockFetch({ keys: [{ kid: "a", kty: "OKP", crv: "Ed25519", x: "xxx" }] })
    const jwks = await cache.fetch(URL)
    expect(jwks.keys).toHaveLength(1)
    expect(fetchSpy).toHaveBeenCalledOnce()
  })

  it("returns cached JWKS within TTL", async () => {
    const fetchSpy = mockFetch({ keys: [{ kid: "a", kty: "OKP", crv: "Ed25519", x: "xxx" }] })
    await cache.fetch(URL)
    await cache.fetch(URL)
    await cache.fetch(URL)
    expect(fetchSpy).toHaveBeenCalledOnce()
  })

  it("honors Cache-Control: max-age header", async () => {
    mockFetch(
      { keys: [{ kid: "a", kty: "OKP", crv: "Ed25519", x: "xxx" }] },
      { headers: { "cache-control": "public, max-age=10" } }
    )
    const before = Date.now()
    await cache.fetch(URL)
    // The cache entry should have ~10s TTL not the default 60s
    const entry = (cache as any).entries.get(URL)
    expect(entry.expiresAt - before).toBeLessThanOrEqual(10_500)
    expect(entry.expiresAt - before).toBeGreaterThan(9_500)
  })

  it("invalidate() forces a refetch on next call", async () => {
    const fetchSpy = mockFetch({ keys: [{ kid: "a", kty: "OKP", crv: "Ed25519", x: "xxx" }] })
    await cache.fetch(URL)
    cache.invalidate(URL)
    await cache.fetch(URL)
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  it("findKey() refetches on unknown kid (handles server-side rotation)", async () => {
    // First fetch: only "old" key
    const fetchSpy = vi
      .spyOn(globalThis, "fetch" as any)
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ keys: [{ kid: "old", kty: "OKP", crv: "Ed25519", x: "xxx" }] }))
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            keys: [
              { kid: "old", kty: "OKP", crv: "Ed25519", x: "xxx" },
              { kid: "new", kty: "OKP", crv: "Ed25519", x: "yyy" },
            ],
          })
        )
      )

    const key = await cache.findKey(URL, "new")
    expect(key.kid).toBe("new")
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  it("findKey() throws unknown_kid when key still absent after refetch", async () => {
    mockFetch({ keys: [{ kid: "a", kty: "OKP", crv: "Ed25519", x: "xxx" }] })
    await expect(cache.findKey(URL, "nonexistent")).rejects.toThrowError(/no key with kid=nonexistent/i)
  })

  it("throws on non-200 JWKS fetch", async () => {
    mockFetch({ keys: [] }, { status: 503 })
    await expect(cache.fetch(URL)).rejects.toThrowError(/HTTP 503/)
  })

  it("throws when response body is missing keys[]", async () => {
    mockFetch({ keys: null as unknown as unknown[] })
    await expect(cache.fetch(URL)).rejects.toThrowError(/keys/)
  })
})
