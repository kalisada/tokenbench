import { encodeBase64Url } from "./base64url";

/** S20: the secret key generator. crypto.getRandomValues is the only source. */

export type SecretBits = 256 | 384 | 512;
export type SecretFormat = "hex" | "base64" | "base64url";

export const SECRET_BITS: readonly SecretBits[] = [256, 384, 512];
export const SECRET_FORMATS: readonly SecretFormat[] = ["hex", "base64", "base64url"];

export function randomBytes(bits: SecretBits): Uint8Array {
  const bytes = new Uint8Array(bits / 8);
  crypto.getRandomValues(bytes);
  return bytes;
}

export function formatSecret(bytes: Uint8Array, format: SecretFormat): string {
  switch (format) {
    case "hex":
      return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    case "base64url":
      return encodeBase64Url(bytes);
    case "base64": {
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      return btoa(binary);
    }
  }
}

export function generateSecret(bits: SecretBits, format: SecretFormat): string {
  return formatSecret(randomBytes(bits), format);
}
