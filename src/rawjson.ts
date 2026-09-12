/**
 * number-lexeme-preserving JSON parse.
 *
 * JavaScript cannot round-trip JSON number lexemes: `JSON.parse("5.0")`
 * yields the number 5 and re-serializes as "5". Signed records CAN
 * carry non-integer numbers (authority bounds pass operator-supplied
 * values through, e.g. `"threshold": 5.0`), and the platform's signer
 * serializes them as Ruby does ("5.0"). Verifying such a record from a
 * parsed object is therefore unfixably lossy in JS — the verifier must
 * canonicalize from the RAW response text, with number lexemes kept
 * verbatim.
 *
 * This is a small strict JSON parser that returns ordinary values for
 * strings/booleans/null/objects/arrays but wraps every number in
 * `RawJsonNumber`, preserving its exact source lexeme for the
 * canonical serializer. A full tokenizer (not a regex transform) so
 * adversarial receipt strings cannot confuse number detection.
 */

export class RawJsonNumber {
  constructor(readonly text: string) {}
}

export function parseWithRawNumbers(text: string): unknown {
  let i = 0

  const error = (message: string): never => {
    throw new SyntaxError(`${message} at position ${i}`)
  }

  const skipWs = (): void => {
    while (i < text.length) {
      const c = text[i]
      if (c === " " || c === "\t" || c === "\n" || c === "\r") i++
      else break
    }
  }

  const parseValue = (): unknown => {
    skipWs()
    const c = text[i]
    if (c === "{") return parseObject()
    if (c === "[") return parseArray()
    if (c === '"') return parseString()
    if (c === "t") return parseLiteral("true", true)
    if (c === "f") return parseLiteral("false", false)
    if (c === "n") return parseLiteral("null", null)
    if (c === "-" || (c !== undefined && c >= "0" && c <= "9")) return parseNumber()
    return error("unexpected character")
  }

  const parseLiteral = (literal: string, value: unknown): unknown => {
    if (text.slice(i, i + literal.length) !== literal) error(`invalid literal (expected ${literal})`)
    i += literal.length
    return value
  }

  const parseNumber = (): RawJsonNumber => {
    const start = i
    if (text[i] === "-") i++
    if (text[i] === "0") {
      i++
    } else if (text[i] !== undefined && (text[i] as string) >= "1" && (text[i] as string) <= "9") {
      while (text[i] !== undefined && (text[i] as string) >= "0" && (text[i] as string) <= "9") i++
    } else {
      error("invalid number")
    }
    if (text[i] === ".") {
      i++
      if (!(text[i] !== undefined && (text[i] as string) >= "0" && (text[i] as string) <= "9")) error("invalid number")
      while (text[i] !== undefined && (text[i] as string) >= "0" && (text[i] as string) <= "9") i++
    }
    if (text[i] === "e" || text[i] === "E") {
      i++
      if (text[i] === "+" || text[i] === "-") i++
      if (!(text[i] !== undefined && (text[i] as string) >= "0" && (text[i] as string) <= "9")) error("invalid number")
      while (text[i] !== undefined && (text[i] as string) >= "0" && (text[i] as string) <= "9") i++
    }
    return new RawJsonNumber(text.slice(start, i))
  }

  const parseString = (): string => {
    if (text[i] !== '"') error("expected string")
    i++
    let out = ""
    for (;;) {
      const c = text[i]
      if (c === undefined) error("unterminated string")
      if (c === '"') {
        i++
        return out
      }
      if (c === "\\") {
        i++
        const esc = text[i]
        switch (esc) {
          case '"':
            out += '"'
            i++
            break
          case "\\":
            out += "\\"
            i++
            break
          case "/":
            out += "/"
            i++
            break
          case "b":
            out += "\b"
            i++
            break
          case "f":
            out += "\f"
            i++
            break
          case "n":
            out += "\n"
            i++
            break
          case "r":
            out += "\r"
            i++
            break
          case "t":
            out += "\t"
            i++
            break
          case "u": {
            const hex = text.slice(i + 1, i + 5)
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) error("invalid \\u escape")
            out += String.fromCharCode(parseInt(hex, 16))
            i += 5
            break
          }
          default:
            error("invalid escape")
        }
        continue
      }
      if ((c as string) < " ") error("unescaped control character in string")
      out += c
      i++
    }
  }

  const parseObject = (): Record<string, unknown> => {
    i++ // {
    const obj: Record<string, unknown> = {}
    skipWs()
    if (text[i] === "}") {
      i++
      return obj
    }
    for (;;) {
      skipWs()
      const key = parseString()
      skipWs()
      if (text[i] !== ":") error("expected ':'")
      i++
      obj[key] = parseValue()
      skipWs()
      if (text[i] === ",") {
        i++
        continue
      }
      if (text[i] === "}") {
        i++
        return obj
      }
      error("expected ',' or '}'")
    }
  }

  const parseArray = (): unknown[] => {
    i++ // [
    const arr: unknown[] = []
    skipWs()
    if (text[i] === "]") {
      i++
      return arr
    }
    for (;;) {
      arr.push(parseValue())
      skipWs()
      if (text[i] === ",") {
        i++
        continue
      }
      if (text[i] === "]") {
        i++
        return arr
      }
      error("expected ',' or ']'")
    }
  }

  const value = parseValue()
  skipWs()
  if (i !== text.length) error("trailing characters")
  return value
}
