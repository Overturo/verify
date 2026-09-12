/**
 * JWKS lazy fetch + cache.
 *
 * Per-URL cache keyed by `jwksUrl`. Honors HTTP `Cache-Control:
 * max-age` (falls back to `VerifyOpts.jwksCacheTtlSeconds`, default
 * 300s). On unknown-kid: invalidate + refetch once.
 */
import { ReceiptInvalid } from "./errors.js"
import type { Jwks, JwksKey } from "./types.js"

interface CachedEntry {
  jwks: Jwks
  expiresAt: number
}

export class JwksCache {
  private readonly entries = new Map<string, CachedEntry>()
  // G7 — single-flight: concurrent `fetch(url)` calls on a cold cache
  // share the same in-flight Promise instead of each issuing its own
  // HTTPS round-trip. Under burst load (e.g. heartbeat + first attest)
  // the JWKS endpoint receives one request, not N.
  private readonly inflight = new Map<string, Promise<Jwks>>()
  private readonly defaultTtlMs: number

  constructor(defaultTtlSeconds = 300) {
    this.defaultTtlMs = defaultTtlSeconds * 1000
  }

  /**
   * Look up a key by `kid`. Fetches the JWKS lazily on first call;
   * on miss, invalidates + refetches once.
   */
  async findKey(jwksUrl: string, kid: string): Promise<JwksKey> {
    let jwks = await this.fetch(jwksUrl)
    let key = jwks.keys.find((k) => k.kid === kid)
    if (key) return key

    // Cache miss — possibly server-side key rotation. Refetch once.
    this.entries.delete(jwksUrl)
    jwks = await this.fetch(jwksUrl)
    key = jwks.keys.find((k) => k.kid === kid)
    if (key) return key

    throw new ReceiptInvalid("unknown_kid", `JWKS at ${jwksUrl} has no key with kid=${kid} (after refetch)`)
  }

  /**
   * Returns the cached JWKS or fetches it. Public so callers can
   * "warm" the cache (e.g., on app startup). Concurrent callers on a
   * cold cache share the same in-flight fetch (single-flight).
   */
  async fetch(jwksUrl: string): Promise<Jwks> {
    const cached = this.entries.get(jwksUrl)
    if (cached && cached.expiresAt > Date.now()) return cached.jwks

    const inflight = this.inflight.get(jwksUrl)
    if (inflight) return inflight

    const fetchPromise = this.doFetch(jwksUrl)
    this.inflight.set(jwksUrl, fetchPromise)
    try {
      return await fetchPromise
    } finally {
      this.inflight.delete(jwksUrl)
    }
  }

  private async doFetch(jwksUrl: string): Promise<Jwks> {
    let response: Response
    try {
      response = await fetch(jwksUrl)
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e)
      throw new ReceiptInvalid("jwks_fetch_failed", `Network error fetching JWKS at ${jwksUrl}: ${message}`)
    }

    if (!response.ok) {
      throw new ReceiptInvalid("jwks_fetch_failed", `JWKS fetch at ${jwksUrl} returned HTTP ${response.status}`)
    }

    const jwks = (await response.json()) as Jwks
    if (!Array.isArray(jwks.keys)) {
      throw new ReceiptInvalid("jwks_fetch_failed", `JWKS at ${jwksUrl} missing keys[] array`)
    }

    const ttlMs = parseMaxAge(response.headers.get("cache-control")) ?? this.defaultTtlMs
    this.entries.set(jwksUrl, { jwks, expiresAt: Date.now() + ttlMs })
    return jwks
  }

  /** Force a refetch on next `fetch` / `findKey` for this URL. */
  invalidate(jwksUrl: string): void {
    this.entries.delete(jwksUrl)
  }

  /** Clear all cached entries. */
  clear(): void {
    this.entries.clear()
  }
}

function parseMaxAge(header: string | null): number | null {
  if (!header) return null
  const match = header.match(/max-age\s*=\s*(\d+)/i)
  if (!match) return null
  const seconds = parseInt(match[1] as string, 10)
  if (isNaN(seconds) || seconds < 0) return null
  return seconds * 1000
}
