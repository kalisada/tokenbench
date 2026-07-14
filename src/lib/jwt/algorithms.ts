/**
 * The complete algorithm set from S15. Incumbent tools' gaps here are the
 * product wedge, so every entry must be genuinely wired to WebCrypto — an
 * algorithm listed but unsupported is worse than one that is absent.
 */

export type Family = "HMAC" | "RSA" | "RSA-PSS" | "EC" | "OKP";

export interface AlgorithmSpec {
  readonly alg: string;
  readonly family: Family;
  /** Key material the user must supply on the validator page. */
  readonly keyKind: "secret" | "public/private";
  readonly importParams: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams;
  readonly signParams: AlgorithmIdentifier | RsaPssParams | EcdsaParams;
  readonly generateParams: RsaHashedKeyGenParams | EcKeyGenParams | HmacKeyGenParams | AlgorithmIdentifier;
  /** JWK `kty` this algorithm's keys must carry. */
  readonly kty: string;
  /** Expected JWK `crv`, for EC and OKP. */
  readonly crv?: string;
  /** Bits of entropy an HMAC secret should have; see S7 weak-secret lint. */
  readonly minSecretBits?: number;
}

function hmac(alg: string, hash: string, bits: number): AlgorithmSpec {
  return {
    alg,
    family: "HMAC",
    keyKind: "secret",
    kty: "oct",
    minSecretBits: bits,
    importParams: { name: "HMAC", hash },
    signParams: { name: "HMAC" },
    generateParams: { name: "HMAC", hash, length: bits },
  };
}

function rsa(alg: string, hash: string): AlgorithmSpec {
  return {
    alg,
    family: "RSA",
    keyKind: "public/private",
    kty: "RSA",
    importParams: { name: "RSASSA-PKCS1-v1_5", hash },
    signParams: { name: "RSASSA-PKCS1-v1_5" },
    generateParams: {
      name: "RSASSA-PKCS1-v1_5",
      hash,
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
    },
  };
}

function rsaPss(alg: string, hash: string, saltLength: number): AlgorithmSpec {
  return {
    alg,
    family: "RSA-PSS",
    keyKind: "public/private",
    kty: "RSA",
    importParams: { name: "RSA-PSS", hash },
    // RFC 7518 §3.5: salt length equals the hash output length.
    signParams: { name: "RSA-PSS", saltLength },
    generateParams: {
      name: "RSA-PSS",
      hash,
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
    },
  };
}

function ecdsa(alg: string, hash: string, namedCurve: string): AlgorithmSpec {
  return {
    alg,
    family: "EC",
    keyKind: "public/private",
    kty: "EC",
    crv: namedCurve,
    importParams: { name: "ECDSA", namedCurve },
    signParams: { name: "ECDSA", hash },
    generateParams: { name: "ECDSA", namedCurve },
  };
}

export const ALGORITHMS: Record<string, AlgorithmSpec> = {
  HS256: hmac("HS256", "SHA-256", 256),
  HS384: hmac("HS384", "SHA-384", 384),
  HS512: hmac("HS512", "SHA-512", 512),

  RS256: rsa("RS256", "SHA-256"),
  RS384: rsa("RS384", "SHA-384"),
  RS512: rsa("RS512", "SHA-512"),

  PS256: rsaPss("PS256", "SHA-256", 32),
  PS384: rsaPss("PS384", "SHA-384", 48),
  PS512: rsaPss("PS512", "SHA-512", 64),

  ES256: ecdsa("ES256", "SHA-256", "P-256"),
  ES384: ecdsa("ES384", "SHA-384", "P-384"),
  ES512: ecdsa("ES512", "SHA-512", "P-521"),

  EdDSA: {
    alg: "EdDSA",
    family: "OKP",
    keyKind: "public/private",
    kty: "OKP",
    crv: "Ed25519",
    importParams: { name: "Ed25519" },
    signParams: { name: "Ed25519" },
    generateParams: { name: "Ed25519" },
  },
};

export const SUPPORTED_ALGS = Object.keys(ALGORITHMS);

export function getAlgorithm(alg: string): AlgorithmSpec | undefined {
  return ALGORITHMS[alg];
}

export function isSymmetric(alg: string): boolean {
  return getAlgorithm(alg)?.family === "HMAC";
}

/**
 * Ed25519 is absent from some older browsers (S15, and a named risk in the
 * spec). Feature-detect rather than assuming, so the UI can degrade with a real
 * message instead of an opaque WebCrypto exception.
 */
export async function isAlgorithmAvailable(alg: string): Promise<boolean> {
  const spec = getAlgorithm(alg);
  if (!spec) return false;
  if (spec.family !== "OKP") return true;
  try {
    await crypto.subtle.generateKey(spec.generateParams as AlgorithmIdentifier, true, [
      "sign",
      "verify",
    ]);
    return true;
  } catch {
    return false;
  }
}
