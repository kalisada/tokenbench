import { decodeBase64Url, decodeBase64UrlToString } from "./base64url";
import {
  JweError,
  JwtDecodeError,
  type DecodedJwt,
  type JwtHeader,
  type JwtPayload,
  type TimeVerdict,
} from "./types";

/**
 * S5: cap input rather than letting a multi-megabyte paste lock the main thread.
 * Real JWTs are well under this; anything larger is a mistake or an attack.
 */
export const MAX_TOKEN_LENGTH = 100_000;

/**
 * S4: the token as typed by a human is rarely the token as specified. Strip the
 * things a terminal, a browser bar or a copied Authorization header add.
 */
export function normalizeToken(input: string): string {
  let token = input.trim();

  // "Authorization: Bearer eyJ..." — take what follows, case-insensitively.
  token = token.replace(/^authorization\s*:\s*/i, "");
  token = token.replace(/^bearer\s+/i, "");

  // Terminal copies wrap lines; JWTs never contain whitespace.
  token = token.replace(/\s+/g, "");

  // A token pulled out of a query string arrives percent-encoded.
  if (/%[0-9a-f]{2}/i.test(token)) {
    try {
      token = decodeURIComponent(token);
    } catch {
      // Malformed escapes: leave as-is and let segment parsing report it.
    }
  }

  // Some sources wrap the value in quotes.
  token = token.replace(/^["'`]|["'`]$/g, "");

  return token;
}

function parseJsonSegment<T>(segment: string, which: "header" | "payload"): T {
  let json: string;
  try {
    json = decodeBase64UrlToString(segment);
  } catch (error) {
    const reason = error instanceof Error ? error.message : "could not be decoded";
    throw new JwtDecodeError(
      `The ${which} ${reason.startsWith("is") || reason.startsWith("contains") ? reason : "could not be decoded"}. It must be valid base64url.`,
      which,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new JwtDecodeError(
      `The ${which} decoded, but its contents are not valid JSON.`,
      which,
    );
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new JwtDecodeError(
      `The ${which} must be a JSON object, but it decoded to ${Array.isArray(parsed) ? "an array" : typeof parsed}.`,
      which,
    );
  }

  return parsed as T;
}

/**
 * Decode without verifying. S2/S3: an expired or not-yet-valid token still
 * decodes — the user is usually here *because* something is wrong with it.
 */
export function decodeJwt(input: string): DecodedJwt {
  if (input.length > MAX_TOKEN_LENGTH) {
    throw new JwtDecodeError(
      `That input is ${input.length.toLocaleString()} characters. Tokens are capped at ${MAX_TOKEN_LENGTH.toLocaleString()} here — this is almost certainly not a JWT.`,
    );
  }

  const raw = normalizeToken(input);
  if (raw === "") {
    throw new JwtDecodeError("No token provided.");
  }

  const segments = raw.split(".");

  if (segments.length === 5) throw new JweError();

  if (segments.length !== 3 && segments.length !== 2) {
    throw new JwtDecodeError(
      `A JWT has 3 dot-separated segments (header.payload.signature); this input has ${segments.length}.`,
    );
  }

  const [headerSegment, payloadSegment, signatureSegment = ""] = segments as [
    string,
    string,
    string?,
  ];

  const header = parseJsonSegment<JwtHeader>(headerSegment, "header");
  const payload = parseJsonSegment<JwtPayload>(payloadSegment, "payload");

  // Signature must decode if present — a corrupt signature segment is worth
  // naming rather than surfacing later as a mystery verification failure.
  if (signatureSegment !== "") {
    try {
      decodeBase64Url(signatureSegment);
    } catch {
      throw new JwtDecodeError(
        "The signature is not valid base64url.",
        "signature",
      );
    }
  }

  return {
    raw,
    header,
    payload,
    signature: signatureSegment,
    signingInput: `${headerSegment}.${payloadSegment}`,
    unsecured: signatureSegment === "" || header.alg?.toLowerCase() === "none",
  };
}

const MINUTE = 60;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** "3 days", "2 hours", "45 seconds" — magnitude only; caller supplies direction. */
export function formatDuration(seconds: number): string {
  const s = Math.abs(Math.round(seconds));
  if (s < MINUTE) return `${s} second${s === 1 ? "" : "s"}`;
  if (s < HOUR) {
    const m = Math.round(s / MINUTE);
    return `${m} minute${m === 1 ? "" : "s"}`;
  }
  if (s < DAY) {
    const h = Math.round(s / HOUR);
    return `${h} hour${h === 1 ? "" : "s"}`;
  }
  const d = Math.round(s / DAY);
  return `${d} day${d === 1 ? "" : "s"}`;
}

function toDate(claim: unknown): Date | undefined {
  return typeof claim === "number" && Number.isFinite(claim)
    ? new Date(claim * 1000)
    : undefined;
}

/**
 * S2/S3. Deliberately independent of signature verification: "valid but
 * expired" is the most common real state, so the two verdicts never collapse
 * into one boolean (S9).
 */
export function evaluateTime(payload: JwtPayload, now: Date = new Date()): TimeVerdict {
  const nowSeconds = now.getTime() / 1000;
  const expiresAt = toDate(payload.exp);
  const notBefore = toDate(payload.nbf);
  const issuedAt = toDate(payload.iat);

  if (typeof payload.exp === "number" && payload.exp <= nowSeconds) {
    return {
      status: "expired",
      summary: `EXPIRED ${formatDuration(nowSeconds - payload.exp)} ago`,
      expiresAt,
      notBefore,
      issuedAt,
    };
  }

  if (typeof payload.nbf === "number" && payload.nbf > nowSeconds) {
    return {
      status: "not-yet-valid",
      summary: `Not valid yet (nbf in ${formatDuration(payload.nbf - nowSeconds)})`,
      expiresAt,
      notBefore,
      issuedAt,
    };
  }

  return {
    status: "valid",
    summary:
      typeof payload.exp === "number"
        ? `Valid — expires in ${formatDuration(payload.exp - nowSeconds)}`
        : "Valid — no expiry set",
    expiresAt,
    notBefore,
    issuedAt,
  };
}

/** e.g. "Expires: 2026-07-11 14:32 UTC (in 2 hours)" — the S1 claims table. */
export function describeTimestamp(seconds: number, now: Date = new Date()): string {
  const date = new Date(seconds * 1000);
  const iso = `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
  const delta = seconds - now.getTime() / 1000;
  const relative =
    delta >= 0 ? `in ${formatDuration(delta)}` : `${formatDuration(delta)} ago`;
  return `${iso} (${relative})`;
}
