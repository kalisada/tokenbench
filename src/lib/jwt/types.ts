export interface JwtHeader {
  alg?: string;
  typ?: string;
  kid?: string;
  cty?: string;
  [key: string]: unknown;
}

export interface JwtPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [key: string]: unknown;
}

export interface DecodedJwt {
  /** The token as parsed, after S4 normalization. */
  readonly raw: string;
  readonly header: JwtHeader;
  readonly payload: JwtPayload;
  readonly signature: string;
  /** header + "." + payload — the bytes a signature covers. */
  readonly signingInput: string;
  /** alg:none or a two-segment token: decodable, but carrying no signature. */
  readonly unsecured: boolean;
}

export type TokenSegment = "header" | "payload" | "signature";

export class JwtDecodeError extends Error {
  constructor(
    message: string,
    readonly segment?: TokenSegment,
  ) {
    super(message);
    this.name = "JwtDecodeError";
  }
}

/** A JWE (5 segments) is a legitimate thing to paste, and needs S6's explanation. */
export class JweError extends Error {
  constructor() {
    super(
      "This is an encrypted JWT (JWE) — contents can't be displayed without the decryption key. This tool handles signed JWTs (JWS).",
    );
    this.name = "JweError";
  }
}

export type TimeStatus = "valid" | "expired" | "not-yet-valid";

export interface TimeVerdict {
  readonly status: TimeStatus;
  /** Human sentence for the status banner, e.g. "EXPIRED 3 days ago". */
  readonly summary: string;
  readonly expiresAt?: Date;
  readonly notBefore?: Date;
  readonly issuedAt?: Date;
}
