/**
 * iss_role → trust_weight mapping.
 *
 * Closed enum; the server advertises these via
 * `/.well-known/openid-configuration#iss_roles_supported`. Mismatch
 * indicates either a wire-protocol version mismatch or a malicious
 * receipt — fail closed.
 */
import type { IssRole, TrustWeight } from "./types.js"

export const ISS_ROLES: readonly IssRole[] = ["authorizer", "witness", "approval_url_signer"]

export const ISS_ROLE_TO_TRUST_WEIGHT: Record<IssRole, TrustWeight> = {
  authorizer: "strong",
  witness: "witness_only",
  approval_url_signer: "approval_url",
}

export function isValidIssRole(value: unknown): value is IssRole {
  return typeof value === "string" && ISS_ROLES.includes(value as IssRole)
}
