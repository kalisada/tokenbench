import { encodeBase64Url, encodeStringToBase64Url } from "./base64url";
import { getAlgorithm } from "./algorithms";
import { KeyError, importKeyFor, type SecretEncoding } from "./keys";
import type { JwtHeader, JwtPayload } from "./types";

export interface SignOptions {
  readonly alg: string;
  readonly payload: JwtPayload;
  /** Extra header members (kid, typ, cty…). alg is always set from `alg`. */
  readonly header?: Omit<JwtHeader, "alg">;
  /** HMAC secret, or a private key (PEM/JWK). Ignored when alg is "none". */
  readonly key?: string;
  readonly secretEncoding?: SecretEncoding;
  /**
   * S19: emit a token whose signature is deliberately wrong, for testing that a
   * server actually rejects it. Always surfaced in the UI as such.
   */
  readonly tamper?: boolean;
}

function corruptSignature(signature: string): string {
  if (signature.length === 0) return "";
  // Flip the trailing character to something else in the base64url alphabet, so
  // the token still *parses* and only fails at the verification step.
  const last = signature.at(-1)!;
  const replacement = last === "A" ? "B" : "A";
  return signature.slice(0, -1) + replacement;
}

export async function signJwt(options: SignOptions): Promise<string> {
  const { alg, payload, header = {}, key = "", secretEncoding = "utf-8", tamper } = options;

  const headerSegment = encodeStringToBase64Url(
    JSON.stringify({ alg, typ: "JWT", ...header }),
  );
  const payloadSegment = encodeStringToBase64Url(JSON.stringify(payload));
  const signingInput = `${headerSegment}.${payloadSegment}`;

  // S19: alg:none is a real thing servers must be tested against. It is gated in
  // the UI behind an explainer, not removed.
  if (alg === "none") {
    return `${signingInput}.`;
  }

  const spec = getAlgorithm(alg);
  if (!spec) throw new KeyError(`Unsupported algorithm "${alg}".`);

  const cryptoKey = await importKeyFor(alg, key, "sign", secretEncoding);
  const signature = await crypto.subtle.sign(
    spec.signParams as AlgorithmIdentifier,
    cryptoKey,
    new TextEncoder().encode(signingInput) as unknown as BufferSource,
  );

  const encoded = encodeBase64Url(new Uint8Array(signature));
  return `${signingInput}.${tamper ? corruptSignature(encoded) : encoded}`;
}

/** S16: the generator loads with a working token already in place. */
export function defaultPayload(now: Date = new Date()): JwtPayload {
  const iat = Math.floor(now.getTime() / 1000);
  return {
    sub: "1234567890",
    name: "Test User",
    iat,
    exp: iat + 3600,
  };
}

/** Parses the relative-expiry input from S17 ("+2h", "30m", "7d"). */
export function parseRelativeExpiry(input: string, now: Date = new Date()): number {
  const match = /^\+?\s*(\d+)\s*([smhd])$/i.exec(input.trim());
  if (!match) {
    throw new Error('Use a relative time like "+1h", "30m", "7d".');
  }
  const amount = Number(match[1]);
  const unit = match[2]!.toLowerCase();
  const seconds = { s: 1, m: 60, h: 3600, d: 86400 }[unit]!;
  return Math.floor(now.getTime() / 1000) + amount * seconds;
}
