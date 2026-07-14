/**
 * base64url codec with the input tolerance S4 requires: tokens arrive pasted
 * from terminals, URLs and log lines, so standard-base64 alphabet and missing
 * padding are treated as valid input rather than errors.
 */

export class Base64UrlError extends Error {}

const B64_CHARS = /^[A-Za-z0-9+/_-]*={0,2}$/;

export function decodeBase64Url(input: string): Uint8Array {
  if (!B64_CHARS.test(input)) {
    throw new Base64UrlError("contains characters that are not valid base64url");
  }

  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(
    normalized.length + ((4 - (normalized.length % 4)) % 4),
    "=",
  );

  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new Base64UrlError("is not decodable base64url");
  }

  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function decodeBase64UrlToString(input: string): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(decodeBase64Url(input));
}

export function encodeStringToBase64Url(input: string): string {
  return encodeBase64Url(new TextEncoder().encode(input));
}

/** True when the string decodes as base64 — used for the S10 secret-encoding hint. */
export function looksLikeBase64(input: string): boolean {
  const trimmed = input.trim();
  if (trimmed.length < 8 || trimmed.length % 4 === 1) return false;
  if (!B64_CHARS.test(trimmed)) return false;
  // Plain words like "secret" are valid base64 characters; require a signal that
  // the value is actually encoded bytes rather than a passphrase.
  if (!/[+/_=-]|[A-Z].*[a-z0-9]|[0-9]/.test(trimmed)) return false;
  try {
    decodeBase64Url(trimmed);
    return true;
  } catch {
    return false;
  }
}
