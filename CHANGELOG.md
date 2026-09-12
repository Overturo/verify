# Changelog

## [Unreleased]

### Changed

- Source comments, tests and this changelog describe behaviour only; planning references were removed.
- The test suite is self-contained: the signed-record corpus is vendored under `tests/fixtures/signed_records/` (the shared copy is read when the package sits next to it).
- Repository, homepage, and issue-tracker metadata point at the public source mirror under https://github.com/overturo; a LICENSE file now ships with the package.

## [0.4.0] - 2026-08-15


### Added

- **`probeSupport()`** — resolves `true` iff the runtime can verify signatures via
  WebCrypto (the public record debugger's browser-support gate).
- **IIFE browser build** (`dist/index.global.js`, global `OverturoVerify`),
  served first-party for the record debugger; no bundler required.

### Changed — security

- **`fetchKeyDiscovery` now requires `discoveryOrigins`.** The envelope supplies
  its own `key_discovery` URL, so trusting it unconditionally let a forger who
  mints the record also control the discovery document and get a forged record
  labeled `keySource: "discovered"`. Discovery now fetches only when the URL's
  origin is in the caller-provided `discoveryOrigins` allow-list, and refuses any
  other origin (`key_discovery_failed`). **Breaking:** a bare
  `fetchKeyDiscovery: true` (no `discoveryOrigins`) is refused, fail-closed.
- **The verified result's home is derived from the bound `key_version` prefix**,
  not the separate unsigned envelope field that duplicated it — a forger can
  change that field while the record still verifies.
- A wrong-length public key is now `malformed_envelope` (was `signature_failed`),
  and `crypto.subtle.verify` is wrapped so a throwing runtime reads as a failed
  signature, never an uncaught rejection.

### Known

- `manifestContentHash` / `verifyManifestPin` canonicalize a pre-parsed value; a
  manifest whose `content` carries non-integer numbers would false-reject
  (fail-closed, never false-accept). Manifest content must be integer-number-only
  until a raw-text entry lands.

## [0.3.0] - 2026-08-06


### Added — durable signed-record verification

- **`verifyRecord`** — verifies the signed record export (`?flavor=signed`):
  `overturo-jcs-1` canonicalization, a detached signature over the `receipt`
  member, key resolution as an explicit trust ladder (`publishedKeys` /
  `fetchKeyDiscovery` / opt-in `allowEmbeddedKey`). Accepts the raw response
  text (the exactness path — number lexemes are significant) or a parsed
  envelope. Throws `RecordInvalid` with a typed `code`.
- **`verifyManifestPin` / `manifestContentHash`** — recompute-and-compare for
  the capability-manifest pin.
- **`canonicalBytes`** — the `overturo-jcs-1` canonicalizer, exported for
  advanced integrations.
- Cross-language conformance: the suite iterates the shared corpus at
  `lib/sdk/shared/conformance/signed_records/` (generated from the platform's
  real exporter; the server and Python legs iterate the same manifest).

### Compatibility

- Additive, no break. `verifyReceipt` is unchanged; the README's former
  "not this library" disclaimer is replaced by the second entry point.

## [0.2.0] - 2026-06-26


### Added — multi-issuer verification

- **`issuerJwks`** — an optional `VerifyOpts` field mapping each issuer (`iss`)
  to its own published JWKS. When a presented credential's issuer is in the map,
  it is verified against that issuer's own published key (matched by `kid`,
  which carries the issuer's key version) — so a credential issued anywhere
  verifies against its issuer's own key with **no callback**. Falls back to
  `jwks` / `jwksUrl` when the issuer isn't in the map.

### Compatibility

- Additive, no break. Single-issuer callers (`jwks` / `jwksUrl`) are unaffected.
  First changelog. Minor bump (0.1.0 → 0.2.0).
