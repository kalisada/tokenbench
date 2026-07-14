import { decodeBase64Url, looksLikeBase64 } from "./base64url";
import { getAlgorithm } from "./algorithms";
import { decodeJwt, evaluateTime } from "./decode";
import {
  KeyError,
  importJwkFor,
  importKeyFor,
  selectFromJwks,
  type SecretEncoding,
} from "./keys";
import type { DecodedJwt, TimeVerdict } from "./types";

export type SignatureStatus = "valid" | "invalid" | "unsecured" | "error";

export interface VerificationResult {
  readonly decoded: DecodedJwt;
  /**
   * S9: signature validity and time validity are separate verdicts and are
   * never collapsed — "valid but expired" is the most common real state.
   */
  readonly signature: SignatureStatus;
  readonly time: TimeVerdict;
  readonly message: string;
  /** S10: surfaced when a failing utf-8 secret is plausibly base64 bytes. */
  readonly hint?: string;
  /** S12: which JWKS key actually verified the token. */
  readonly matchedKid?: string;
}

async function verifySignature(
  decoded: DecodedJwt,
  key: CryptoKey,
  alg: string,
): Promise<boolean> {
  const spec = getAlgorithm(alg)!;
  const signature = decodeBase64Url(decoded.signature);
  const data = new TextEncoder().encode(decoded.signingInput);

  return crypto.subtle.verify(
    spec.signParams as AlgorithmIdentifier,
    key,
    signature as unknown as BufferSource,
    data as unknown as BufferSource,
  );
}

export interface VerifyOptions {
  readonly secretEncoding?: SecretEncoding;
  readonly now?: Date;
}

export async function verifyJwt(
  token: string,
  keyInput: string,
  options: VerifyOptions = {},
): Promise<VerificationResult> {
  const { secretEncoding = "utf-8", now } = options;
  const decoded = decodeJwt(token);
  const time = evaluateTime(decoded.payload, now);

  if (decoded.unsecured) {
    return {
      decoded,
      signature: "unsecured",
      time,
      message:
        "UNSECURED — this token has no signature (alg: none). Anyone can alter its contents.",
    };
  }

  const alg = decoded.header.alg;
  if (!alg || !getAlgorithm(alg)) {
    return {
      decoded,
      signature: "error",
      time,
      message: `The token's header declares alg "${alg ?? "(missing)"}", which this tool cannot verify.`,
    };
  }

  try {
    const key = await importKeyFor(alg, keyInput, "verify", secretEncoding);
    const valid = await verifySignature(decoded, key, alg);

    if (valid) {
      return { decoded, signature: "valid", time, message: "Signature VALID" };
    }

    // S10: the most frequent cause of a "wrong secret" that isn't wrong.
    const hint =
      getAlgorithm(alg)!.family === "HMAC" &&
      secretEncoding === "utf-8" &&
      looksLikeBase64(keyInput)
        ? "Secret looks base64-encoded — try the base64 toggle."
        : undefined;

    return {
      decoded,
      signature: "invalid",
      time,
      message:
        "Signature INVALID — the secret doesn't match or the token was tampered with.",
      hint,
    };
  } catch (error) {
    if (error instanceof KeyError) {
      return { decoded, signature: "error", time, message: error.message };
    }
    throw error;
  }
}

/**
 * S12: verify against a JWKS. Prefer the key whose `kid` matches the token's;
 * with no match, try every key and report which one worked.
 */
export async function verifyWithJwks(
  token: string,
  jwks: unknown,
  options: VerifyOptions = {},
): Promise<VerificationResult> {
  const decoded = decodeJwt(token);
  const time = evaluateTime(decoded.payload, options.now);

  if (decoded.unsecured) {
    return {
      decoded,
      signature: "unsecured",
      time,
      message:
        "UNSECURED — this token has no signature (alg: none). Anyone can alter its contents.",
    };
  }

  const alg = decoded.header.alg;
  if (!alg || !getAlgorithm(alg)) {
    return {
      decoded,
      signature: "error",
      time,
      message: `The token's header declares alg "${alg ?? "(missing)"}", which this tool cannot verify.`,
    };
  }

  const candidates = selectFromJwks(jwks, decoded.header.kid);
  const failures: string[] = [];

  for (const jwk of candidates) {
    const kid = (jwk as { kid?: string }).kid;
    try {
      const key = await importJwkFor(alg, jwk, "verify");
      if (await verifySignature(decoded, key, alg)) {
        return {
          decoded,
          signature: "valid",
          time,
          matchedKid: kid,
          message: kid
            ? `Signature VALID — matched key "${kid}" from the JWKS.`
            : "Signature VALID — matched a key from the JWKS.",
        };
      }
      failures.push(kid ?? "(no kid)");
    } catch (error) {
      failures.push(`${kid ?? "(no kid)"}: ${(error as Error).message}`);
    }
  }

  const noKidMatch =
    decoded.header.kid !== undefined &&
    !candidates.some((jwk) => (jwk as { kid?: string }).kid === decoded.header.kid);

  return {
    decoded,
    signature: "invalid",
    time,
    message: noKidMatch
      ? `No key in the JWKS has kid "${decoded.header.kid}". Tried all ${candidates.length} key(s); none verified this token.`
      : `Signature INVALID — no key in the JWKS verified this token. Tried: ${failures.join(", ")}.`,
  };
}

/**
 * S13: a JWKS fetch is the one network call this tool makes, and only on an
 * explicit click. CORS failure is the common case, not the exception — the
 * caller shows the curl fallback.
 */
export class JwksFetchError extends Error {
  constructor(
    message: string,
    readonly corsLikely: boolean,
    readonly url: string,
  ) {
    super(message);
    this.name = "JwksFetchError";
  }
}

export function curlCommandFor(url: string): string {
  return `curl -s ${JSON.stringify(url)}`;
}

export async function fetchJwks(url: string): Promise<unknown> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new JwksFetchError(`"${url}" is not a valid URL.`, false, url);
  }
  if (parsed.protocol !== "https:" && parsed.hostname !== "localhost") {
    throw new JwksFetchError("JWKS URLs must use https.", false, url);
  }

  let response: Response;
  try {
    response = await fetch(url, { headers: { accept: "application/json" } });
  } catch {
    // A blocked cross-origin request is indistinguishable from a network error
    // in the browser, and CORS is overwhelmingly the reason.
    throw new JwksFetchError(
      "That server doesn't allow browser requests (CORS). Paste the JWKS JSON manually instead — curl the URL and paste the result.",
      true,
      url,
    );
  }

  if (!response.ok) {
    throw new JwksFetchError(
      `That URL returned HTTP ${response.status}.`,
      false,
      url,
    );
  }

  try {
    return await response.json();
  } catch {
    throw new JwksFetchError("That URL did not return JSON.", false, url);
  }
}
