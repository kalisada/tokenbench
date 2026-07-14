import { SUPPORTED_ALGS, getAlgorithm } from "./algorithms";
import { formatDuration } from "./decode";
import type { DecodedJwt } from "./types";

/**
 * S7: the security lint layer. Lints are informational and never block a
 * decode — the user is mid-debugging and always gets their token back.
 */

export type LintLevel = "red" | "amber" | "info";

export interface Lint {
  readonly id: string;
  readonly level: LintLevel;
  readonly title: string;
  readonly detail: string;
}

/**
 * Secrets that appear in tutorials, framework scaffolds and jwt.io's own
 * default. A token signed with one of these is signed with a public value.
 */
export const KNOWN_WEAK_SECRETS = [
  "secret",
  "your-256-bit-secret",
  "your-384-bit-secret",
  "your-512-bit-secret",
  "changeme",
  "change-me",
  "password",
  "supersecret",
  "super-secret",
  "jwt-secret",
  "jwtsecret",
  "mysecret",
  "my-secret",
  "test",
  "secretkey",
  "secret-key",
  "s3cr3t",
  "topsecret",
  "qwerty",
  "0123456789",
];

const THIRTY_DAYS = 30 * 24 * 60 * 60;

export interface LintContext {
  /** Present only when the user actually attempted verification (S7). */
  readonly secret?: string;
  readonly now?: Date;
}

export function lintToken(decoded: DecodedJwt, context: LintContext = {}): Lint[] {
  const lints: Lint[] = [];
  const { header, payload } = decoded;
  const alg = header.alg;

  if (decoded.unsecured) {
    lints.push({
      id: "alg-none",
      level: "red",
      title: "Unsecured token (alg: none)",
      detail:
        "This token carries no signature, so any party can rewrite its claims. A server that accepts it is trusting unauthenticated input. Only ever valid as a deliberate test of your rejection path.",
    });
  }

  if (alg && !getAlgorithm(alg) && alg.toLowerCase() !== "none") {
    lints.push({
      id: "alg-unknown",
      level: "info",
      title: `Unrecognized algorithm "${alg}"`,
      detail: `The header names an algorithm outside the JOSE set (${SUPPORTED_ALGS.join(", ")}). Servers should verify against an allowlist of expected algorithms rather than trusting this field.`,
    });
  }

  if (context.secret !== undefined && alg && getAlgorithm(alg)?.family === "HMAC") {
    const normalized = context.secret.trim().toLowerCase();
    if (KNOWN_WEAK_SECRETS.includes(normalized)) {
      lints.push({
        id: "weak-secret",
        level: "amber",
        title: "Well-known default secret",
        detail: `"${context.secret.trim()}" appears in tutorials and framework defaults. Anyone can forge tokens for this key. Rotate to a random secret at least as long as the hash (see the secret key generator).`,
      });
    } else {
      const bits = new TextEncoder().encode(context.secret).length * 8;
      const required = getAlgorithm(alg)!.minSecretBits ?? 256;
      if (bits < required) {
        lints.push({
          id: "short-secret",
          level: "amber",
          title: "Secret is shorter than the hash",
          detail: `${alg} uses a ${required}-bit hash, but this secret is ${bits} bits. RFC 7518 requires an HMAC key at least as long as the hash output; shorter keys weaken the signature against brute force.`,
        });
      }
    }
  }

  if (payload.exp === undefined) {
    lints.push({
      id: "no-exp",
      level: "amber",
      title: "Token never expires",
      detail:
        "There is no exp claim, so this token is valid until the signing key is rotated. A leaked copy stays usable indefinitely.",
    });
  } else if (
    typeof payload.exp === "number" &&
    typeof payload.iat === "number" &&
    payload.exp - payload.iat > THIRTY_DAYS
  ) {
    lints.push({
      id: "long-lived",
      level: "info",
      title: "Long-lived token",
      detail: `This token is valid for ${formatDuration(payload.exp - payload.iat)} after issue. Long lifetimes widen the window in which a stolen token is useful — consider short access tokens plus a refresh flow.`,
    });
  }

  if (payload.nbf === undefined && payload.iat === undefined) {
    lints.push({
      id: "no-timestamps",
      level: "info",
      title: "No iat or nbf claim",
      detail:
        "Without iat or nbf there is no record of when this token became valid, which makes replay windows harder to reason about.",
    });
  }

  if (header.kid !== undefined) {
    lints.push({
      id: "kid",
      level: "info",
      title: `Key lookup via kid "${header.kid}"`,
      detail:
        "The verifier is expected to resolve this key id, usually against a JWKS endpoint. Make sure kid is looked up in a trusted key set and never used to load a key from a path or URL in the token itself.",
    });
  }

  return lints;
}
