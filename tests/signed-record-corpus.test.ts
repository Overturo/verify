/**
 * the TS leg of the signed-record conformance corpus.
 *
 * One fixture set, three legs: the server spec
 * (spec/conformance/signed_record_corpus_spec.rb) generates and
 * re-verifies; this suite and the Python suite
 * (lib/sdk/overturo-py/tests/records/) iterate the same manifest. A
 * canonicalizer that drifts from the server by one byte fails here.
 */
import { describe, expect, test } from "vitest"
import { existsSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { verifyRecord, verifyManifestPin, manifestContentHash, RecordInvalid } from "../src/index.js"

// The shared corpus when this package sits next to it; the vendored copy otherwise.
const SHARED_CORPUS = join(__dirname, "..", "..", "shared", "conformance", "signed_records")
const CORPUS_DIR = existsSync(SHARED_CORPUS) ? SHARED_CORPUS : join(__dirname, "fixtures", "signed_records")

interface CorpusCase {
  fixture: string
  expect: string
  record_type?: string
  key_version?: string
}

interface CorpusManifest {
  schema: string
  published_keys: Record<string, string>
  cases: CorpusCase[]
}

const manifest: CorpusManifest = JSON.parse(readFileSync(join(CORPUS_DIR, "manifest.json"), "utf8"))

function readFixture(name: string): unknown {
  return JSON.parse(readFileSync(join(CORPUS_DIR, name), "utf8"))
}

// Envelopes verify from RAW text — the corpus's authorization records
// carry non-integer numbers ("threshold": 5.0), whose lexemes
// JSON.parse cannot round-trip in JavaScript.
function readFixtureRaw(name: string): string {
  return readFileSync(join(CORPUS_DIR, name), "utf8")
}

describe("signed-record corpus", () => {
  test("corpus schema", () => {
    expect(manifest.schema).toBe("overturo-signed-record-corpus/1")
    expect(manifest.cases.length).toBeGreaterThanOrEqual(9)
  })

  for (const corpusCase of manifest.cases) {
    test(`${corpusCase.fixture} → ${corpusCase.expect}`, async () => {
      switch (corpusCase.expect) {
        case "valid": {
          const verified = await verifyRecord(readFixtureRaw(corpusCase.fixture), {
            publishedKeys: manifest.published_keys,
          })
          expect(verified.keySource).toBe("supplied")
          expect(verified.keyVersion).toBe(corpusCase.key_version)
          if (corpusCase.record_type) {
            expect(verified.recordType).toBe(corpusCase.record_type)
          }
          break
        }
        case "signature_failed":
        case "key_mismatch":
        case "unknown_key_version": {
          await expect(
            verifyRecord(readFixtureRaw(corpusCase.fixture), { publishedKeys: manifest.published_keys })
          ).rejects.toMatchObject({ name: "RecordInvalid", code: corpusCase.expect })
          break
        }
        case "manifest_valid": {
          const pair = readFixture(corpusCase.fixture) as { content: unknown; content_hash: string }
          const recomputed = await verifyManifestPin(
            { reference: "corpus/manifest/v1", hash: pair.content_hash },
            { content: pair.content }
          )
          expect(recomputed).toBe(pair.content_hash)
          expect(await manifestContentHash(pair.content)).toBe(pair.content_hash)
          break
        }
        case "manifest_hash_mismatch": {
          const pair = readFixture(corpusCase.fixture) as { content: unknown; content_hash: string }
          await expect(
            verifyManifestPin({ reference: "corpus/manifest/v1", hash: pair.content_hash }, { content: pair.content })
          ).rejects.toMatchObject({ name: "RecordInvalid", code: "manifest_hash_mismatch" })
          break
        }
        default:
          throw new Error(`unknown corpus expectation ${corpusCase.expect} — extend this suite`)
      }
    })
  }

  test("a tampered fixture also fails in embedded-only mode (bytes, not key resolution)", async () => {
    await expect(
      verifyRecord(readFixtureRaw("tampered_receipt.json"), { allowEmbeddedKey: true })
    ).rejects.toMatchObject({ code: "signature_failed" })
  })

  test("object input fails closed on records carrying non-integer numbers (pass raw text)", async () => {
    // JSON.parse collapses "5.0" → 5; the canonical bytes can no longer
    // match, so an authentic record refuses rather than false-passing.
    const parsed = readFixture("authorization_record_valid.json")
    await expect(verifyRecord(parsed, { publishedKeys: manifest.published_keys })).rejects.toMatchObject({
      code: "signature_failed",
    })
  })

  test("RecordInvalid instances carry the artifact-specific name", async () => {
    try {
      await verifyRecord("not an envelope", { allowEmbeddedKey: true })
      expect.unreachable()
    } catch (e) {
      expect(e).toBeInstanceOf(RecordInvalid)
      expect((e as RecordInvalid).code).toBe("malformed_envelope")
    }
  })
})
