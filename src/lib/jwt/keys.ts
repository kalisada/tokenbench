import { decodeBase64Url } from "./base64url";
import { getAlgorithm, type AlgorithmSpec } from "./algorithms";
import {
  CURVE_BY_OID,
  DerError,
  OID,
  TAG,
  concat,
  encodeBitString,
  encodeInteger,
  encodeNull,
  encodeOid,
  encodeSequence,
  encode,
  readChildren,
  readNode,
  readOid,
  tlv,
} from "./der";

export class KeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KeyError";
  }
}

export type KeyFamily = "RSA" | "EC" | "OKP" | "oct";

export interface ParsedKey {
  readonly family: KeyFamily;
  readonly isPrivate: boolean;
  /** P-256 / P-384 / P-521 / Ed25519, when the family has one. */
  readonly curve?: string;
  readonly format: "spki" | "pkcs8" | "jwk";
  readonly der?: Uint8Array;
  readonly jwk?: JsonWebKey;
}

const PEM_BODY = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/;

/** Recognizes a pasted key before we know whether it's the *right* key (S14). */
export function looksLikeAsymmetricKey(input: string): boolean {
  const text = input.trim();
  if (PEM_BODY.test(text)) return true;
  try {
    const parsed = JSON.parse(text) as { kty?: unknown; keys?: unknown };
    return parsed.kty === "RSA" || parsed.kty === "EC" || parsed.kty === "OKP" ||
      Array.isArray(parsed.keys);
  } catch {
    return false;
  }
}

export function looksLikeJwks(input: string): boolean {
  try {
    const parsed = JSON.parse(input.trim()) as { keys?: unknown };
    return Array.isArray(parsed.keys);
  } catch {
    return false;
  }
}

// --- PEM -------------------------------------------------------------------

interface Pem {
  readonly label: string;
  readonly der: Uint8Array;
}

/** S11: tolerate CRLF, leading whitespace, and indented heredoc-style pastes. */
function parsePem(input: string): Pem | undefined {
  const match = PEM_BODY.exec(input.trim().replace(/\r\n/g, "\n"));
  if (!match) return undefined;

  const label = match[1]!.trim();
  const body = match[2]!.replace(/\s+/g, "");
  try {
    return { label, der: decodeBase64Url(body) };
  } catch {
    throw new KeyError(
      `The ${label} block is not valid base64 — it may have been truncated or altered in copying.`,
    );
  }
}

/** SPKI = SEQUENCE { AlgorithmIdentifier, BIT STRING }; read the algorithm OID. */
function inspectSpki(der: Uint8Array): { family: KeyFamily; curve?: string } {
  const root = readNode(der);
  const [algId] = readChildren(der, root);
  if (!algId || algId.tag !== TAG.SEQUENCE) {
    throw new KeyError("This does not look like a public key (SubjectPublicKeyInfo).");
  }
  const algParts = readChildren(der, algId);
  const oid = readOid(der, algParts[0]!);

  if (oid === OID.RSA || oid === OID.RSA_PSS) return { family: "RSA" };
  if (oid === OID.ED25519) return { family: "OKP", curve: "Ed25519" };
  if (oid === OID.EC_PUBLIC_KEY) {
    const curveNode = algParts[1];
    const curveOid = curveNode ? readOid(der, curveNode) : undefined;
    const curve = curveOid ? CURVE_BY_OID[curveOid] : undefined;
    if (!curve) throw new KeyError(`Unsupported elliptic curve in key (OID ${curveOid}).`);
    return { family: "EC", curve };
  }
  throw new KeyError(`Unsupported key algorithm (OID ${oid}).`);
}

/** PKCS#8 = SEQUENCE { version, AlgorithmIdentifier, OCTET STRING }. */
function inspectPkcs8(der: Uint8Array): { family: KeyFamily; curve?: string } {
  const root = readNode(der);
  const children = readChildren(der, root);
  const algId = children[1];
  if (!algId || algId.tag !== TAG.SEQUENCE) {
    throw new KeyError("This does not look like a private key (PKCS#8).");
  }
  const algParts = readChildren(der, algId);
  const oid = readOid(der, algParts[0]!);

  if (oid === OID.RSA || oid === OID.RSA_PSS) return { family: "RSA" };
  if (oid === OID.ED25519) return { family: "OKP", curve: "Ed25519" };
  if (oid === OID.EC_PUBLIC_KEY) {
    const curveNode = algParts[1];
    const curveOid = curveNode ? readOid(der, curveNode) : undefined;
    const curve = curveOid ? CURVE_BY_OID[curveOid] : undefined;
    if (!curve) throw new KeyError(`Unsupported elliptic curve in key (OID ${curveOid}).`);
    return { family: "EC", curve };
  }
  throw new KeyError(`Unsupported key algorithm (OID ${oid}).`);
}

/** X.509 → the SPKI inside it. S11: a pasted certificate is a pasted public key. */
function spkiFromCertificate(der: Uint8Array): Uint8Array {
  const cert = readNode(der);
  const [tbs] = readChildren(der, cert);
  if (!tbs) throw new KeyError("Certificate is malformed.");

  const fields = readChildren(der, tbs);
  // TBSCertificate: [0] version (optional), serial, signature, issuer,
  // validity, subject, subjectPublicKeyInfo.
  const hasVersion = fields[0]?.tag === 0xa0;
  const spki = fields[hasVersion ? 6 : 5];
  if (!spki || spki.tag !== TAG.SEQUENCE) {
    throw new KeyError("Could not find a public key inside that certificate.");
  }
  return tlv(der, spki).slice();
}

/** PKCS#1 RSAPublicKey → SPKI, the only RSA public form WebCrypto imports. */
function spkiFromPkcs1(der: Uint8Array): Uint8Array {
  return encodeSequence(
    encodeSequence(encodeOid(OID.RSA), encodeNull()),
    encodeBitString(der),
  );
}

/** PKCS#1 RSAPrivateKey → PKCS#8. */
function pkcs8FromPkcs1Private(der: Uint8Array): Uint8Array {
  return encodeSequence(
    encodeInteger(0),
    encodeSequence(encodeOid(OID.RSA), encodeNull()),
    encode(TAG.OCTET_STRING, der),
  );
}

/** SEC1 ECPrivateKey → PKCS#8; the curve OID is carried in the [0] parameter. */
function pkcs8FromSec1(der: Uint8Array): Uint8Array {
  const root = readNode(der);
  const children = readChildren(der, root);
  const params = children.find((child) => child.tag === 0xa0);
  if (!params) {
    throw new KeyError(
      "That EC private key does not name its curve. Re-export it with `openssl pkcs8 -topk8` and paste the PRIVATE KEY block.",
    );
  }
  const [curveOidNode] = readChildren(der, params);
  const curveOid = readOid(der, curveOidNode!);
  if (!CURVE_BY_OID[curveOid]) {
    throw new KeyError(`Unsupported elliptic curve in key (OID ${curveOid}).`);
  }

  return encodeSequence(
    encodeInteger(0),
    encodeSequence(encodeOid(OID.EC_PUBLIC_KEY), encodeOid(curveOid)),
    encode(TAG.OCTET_STRING, der),
  );
}

// --- unified parse ---------------------------------------------------------

export function parseKey(input: string): ParsedKey {
  const text = input.trim();
  if (text === "") throw new KeyError("No key provided.");

  const pem = parsePem(text);

  if (pem) {
    try {
      switch (pem.label) {
        case "PUBLIC KEY": {
          const info = inspectSpki(pem.der);
          return { ...info, isPrivate: false, format: "spki", der: pem.der };
        }
        case "RSA PUBLIC KEY": {
          const der = spkiFromPkcs1(pem.der);
          return { family: "RSA", isPrivate: false, format: "spki", der };
        }
        case "CERTIFICATE": {
          const der = spkiFromCertificate(pem.der);
          const info = inspectSpki(der);
          return { ...info, isPrivate: false, format: "spki", der };
        }
        case "PRIVATE KEY": {
          const info = inspectPkcs8(pem.der);
          return { ...info, isPrivate: true, format: "pkcs8", der: pem.der };
        }
        case "RSA PRIVATE KEY": {
          const der = pkcs8FromPkcs1Private(pem.der);
          return { family: "RSA", isPrivate: true, format: "pkcs8", der };
        }
        case "EC PRIVATE KEY": {
          const der = pkcs8FromSec1(pem.der);
          const info = inspectPkcs8(der);
          return { ...info, isPrivate: true, format: "pkcs8", der };
        }
        default:
          throw new KeyError(
            `Unsupported PEM block: "${pem.label}". Paste a PUBLIC KEY, PRIVATE KEY, CERTIFICATE, or an RSA/EC key block.`,
          );
      }
    } catch (error) {
      if (error instanceof KeyError) throw error;
      if (error instanceof DerError) {
        throw new KeyError(
          `That ${pem.label} block is not valid DER — it may be truncated or corrupted.`,
        );
      }
      throw error;
    }
  }

  // JWK or JWKS
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new KeyError(
      "Could not read that key. Paste a PEM block (-----BEGIN PUBLIC KEY-----), a JWK, or a JWKS.",
    );
  }

  return parseJwk(json as JsonWebKey);
}

export function parseJwk(jwk: JsonWebKey): ParsedKey {
  const kty = jwk.kty;
  if (kty !== "RSA" && kty !== "EC" && kty !== "OKP" && kty !== "oct") {
    throw new KeyError(`Unsupported JWK key type "${String(kty)}".`);
  }

  // A private JWK carries the private exponent (RSA) or scalar (EC/OKP).
  const isPrivate = Boolean(jwk.d);
  const curve = (jwk as { crv?: string }).crv;

  return { family: kty, isPrivate, curve, format: "jwk", jwk };
}

/** S12: a JWKS is chosen by `kid`; with no match, the caller tries every key. */
export function selectFromJwks(jwks: unknown, kid?: string): JsonWebKey[] {
  const keys = (jwks as { keys?: unknown }).keys;
  if (!Array.isArray(keys) || keys.length === 0) {
    throw new KeyError('That JWKS has no "keys" array.');
  }

  if (kid) {
    const match = keys.filter((key) => (key as JsonWebKey & { kid?: string }).kid === kid);
    if (match.length > 0) return match as JsonWebKey[];
  }
  return keys as JsonWebKey[];
}

// --- import ----------------------------------------------------------------

function assertKeyMatchesAlgorithm(key: ParsedKey, spec: AlgorithmSpec): void {
  const expected = spec.kty;

  if (key.family !== expected) {
    // S14: this specific pairing is the algorithm-confusion attack, and is worth
    // explaining rather than reporting as a type error.
    if (spec.family === "HMAC") {
      throw new KeyError(
        "Verifying an HS256-family token with a public key as the HMAC secret is the classic JWT algorithm-confusion attack. If your server does this, it's vulnerable. Choose the key type matching the algorithm.",
      );
    }
    throw new KeyError(
      `The token's algorithm is ${spec.alg}, which needs an ${expected} key — but you pasted an ${key.family} key.`,
    );
  }

  if (spec.crv && key.curve && key.curve !== spec.crv) {
    throw new KeyError(
      `${spec.alg} requires a ${spec.crv} key, but that key uses ${key.curve}.`,
    );
  }
}

async function importAsymmetric(
  key: ParsedKey,
  spec: AlgorithmSpec,
  usage: "verify" | "sign",
): Promise<CryptoKey> {
  assertKeyMatchesAlgorithm(key, spec);

  const wantsPrivate = usage === "sign";
  if (wantsPrivate && !key.isPrivate) {
    throw new KeyError("Signing needs a private key, but that is a public key.");
  }
  if (!wantsPrivate && key.isPrivate) {
    // Verifying with a private key is a common paste mistake; WebCrypto simply
    // refuses, so derive the public half by dropping the private JWK fields.
    if (key.format === "jwk" && key.jwk) {
      const { d, p, q, dp, dq, qi, ...pub } = key.jwk as Record<string, unknown>;
      return crypto.subtle.importKey(
        "jwk",
        { ...pub, key_ops: ["verify"] } as JsonWebKey,
        spec.importParams as AlgorithmIdentifier,
        true,
        ["verify"],
      );
    }
    throw new KeyError(
      "That is a private key. Paste the matching public key to verify a signature.",
    );
  }

  const format = key.format === "jwk" ? "jwk" : wantsPrivate ? "pkcs8" : "spki";
  const material = key.format === "jwk" ? key.jwk! : (key.der! as unknown as BufferSource);

  try {
    return await crypto.subtle.importKey(
      format as "jwk",
      material as JsonWebKey,
      spec.importParams as AlgorithmIdentifier,
      true,
      [usage],
    );
  } catch (error) {
    if (spec.family === "OKP") {
      throw new KeyError(
        "This browser does not support Ed25519 (EdDSA) in WebCrypto. Try a current Chrome, Edge, Firefox or Safari.",
      );
    }
    throw new KeyError(
      `That key could not be imported for ${spec.alg}: ${(error as Error).message}`,
    );
  }
}

export type SecretEncoding = "utf-8" | "base64";

/** S10: an HMAC secret is either literal text or base64-encoded bytes. */
export function secretToBytes(secret: string, encoding: SecretEncoding): Uint8Array {
  if (encoding === "base64") {
    try {
      return decodeBase64Url(secret.trim());
    } catch {
      throw new KeyError("The secret is not valid base64. Switch the toggle to utf-8.");
    }
  }
  return new TextEncoder().encode(secret);
}

export async function importHmacKey(
  secret: string,
  encoding: SecretEncoding,
  spec: AlgorithmSpec,
  usage: "verify" | "sign",
): Promise<CryptoKey> {
  if (looksLikeAsymmetricKey(secret)) {
    // S14 again: catch it before WebCrypto turns it into bytes.
    throw new KeyError(
      "Verifying an HS256-family token with a public key as the HMAC secret is the classic JWT algorithm-confusion attack. If your server does this, it's vulnerable. Choose the key type matching the algorithm.",
    );
  }

  const bytes = secretToBytes(secret, encoding);
  if (bytes.length === 0) throw new KeyError("The secret is empty.");

  return crypto.subtle.importKey(
    "raw",
    bytes as unknown as BufferSource,
    spec.importParams as HmacImportParams,
    false,
    [usage],
  );
}

/** Entry point used by verify/sign: resolve arbitrary user input to a CryptoKey. */
export async function importKeyFor(
  alg: string,
  keyInput: string,
  usage: "verify" | "sign",
  secretEncoding: SecretEncoding = "utf-8",
): Promise<CryptoKey> {
  const spec = getAlgorithm(alg);
  if (!spec) throw new KeyError(`Unsupported algorithm "${alg}".`);

  if (spec.family === "HMAC") {
    return importHmacKey(keyInput, secretEncoding, spec, usage);
  }
  return importAsymmetric(parseKey(keyInput), spec, usage);
}

export async function importJwkFor(
  alg: string,
  jwk: JsonWebKey,
  usage: "verify" | "sign",
): Promise<CryptoKey> {
  const spec = getAlgorithm(alg);
  if (!spec) throw new KeyError(`Unsupported algorithm "${alg}".`);
  return importAsymmetric(parseJwk(jwk), spec, usage);
}

// --- export ----------------------------------------------------------------

function toPem(label: string, der: ArrayBuffer): string {
  const bytes = new Uint8Array(der);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const body = btoa(binary).replace(/(.{64})/g, "$1\n").trim();
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----`;
}

export interface GeneratedKeyPair {
  readonly publicKeyPem: string;
  readonly privateKeyPem: string;
}

/** S18. Keys are generated in-page and never persisted; the UI carries the warning. */
export async function generateKeyPair(alg: string): Promise<GeneratedKeyPair> {
  const spec = getAlgorithm(alg);
  if (!spec || spec.family === "HMAC") {
    throw new KeyError(`${alg} uses a shared secret, not a key pair.`);
  }

  const pair = (await crypto.subtle.generateKey(
    spec.generateParams as AlgorithmIdentifier,
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;

  const [spki, pkcs8] = await Promise.all([
    crypto.subtle.exportKey("spki", pair.publicKey),
    crypto.subtle.exportKey("pkcs8", pair.privateKey),
  ]);

  return {
    publicKeyPem: toPem("PUBLIC KEY", spki),
    privateKeyPem: toPem("PRIVATE KEY", pkcs8),
  };
}
