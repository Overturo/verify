import { describe, expect, it } from "vitest"
import { ISS_ROLES, ISS_ROLE_TO_TRUST_WEIGHT } from "../src/iss-role.js"

describe("iss-role mapping", () => {
  it("ISS_ROLES is the closed enum: authorizer / witness / approval_url_signer", () => {
    expect([...ISS_ROLES]).toEqual(["authorizer", "witness", "approval_url_signer"])
  })

  it("ISS_ROLE_TO_TRUST_WEIGHT covers every role", () => {
    for (const role of ISS_ROLES) {
      expect(ISS_ROLE_TO_TRUST_WEIGHT[role]).toBeDefined()
    }
  })

  it("authorizer → strong", () => {
    expect(ISS_ROLE_TO_TRUST_WEIGHT.authorizer).toBe("strong")
  })

  it("witness → witness_only", () => {
    expect(ISS_ROLE_TO_TRUST_WEIGHT.witness).toBe("witness_only")
  })

  it("approval_url_signer → approval_url", () => {
    expect(ISS_ROLE_TO_TRUST_WEIGHT.approval_url_signer).toBe("approval_url")
  })
})
