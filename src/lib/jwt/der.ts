/**
 * A minimal DER reader/writer — just enough to identify what a pasted key
 * actually is, and to convert the legacy encodings WebCrypto refuses to import
 * (PKCS#1, SEC1, X.509 certificates) into the SPKI/PKCS#8 it accepts.
 *
 * This exists because S11 requires naming the *specific* mismatch ("that's an
 * EC key, but the token says RS256") rather than reporting "invalid key".
 */

export class DerError extends Error {}

export const TAG = {
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  SEQUENCE: 0x30,
} as const;

export interface DerNode {
  readonly tag: number;
  /** Content bounds, excluding tag and length bytes. */
  readonly start: number;
  readonly end: number;
  /** Bounds of the whole TLV, for slicing a node back out verbatim. */
  readonly tlvStart: number;
  readonly tlvEnd: number;
}

export function readNode(bytes: Uint8Array, offset = 0): DerNode {
  if (offset + 2 > bytes.length) throw new DerError("truncated DER");

  const tag = bytes[offset]!;
  let cursor = offset + 1;
  const first = bytes[cursor++]!;

  let length: number;
  if (first < 0x80) {
    length = first;
  } else {
    const byteCount = first & 0x7f;
    if (byteCount === 0 || byteCount > 4) throw new DerError("unsupported DER length");
    length = 0;
    for (let i = 0; i < byteCount; i++) {
      length = length * 256 + bytes[cursor++]!;
    }
  }

  const end = cursor + length;
  if (end > bytes.length) throw new DerError("DER length exceeds buffer");

  return { tag, start: cursor, end, tlvStart: offset, tlvEnd: end };
}

export function readChildren(bytes: Uint8Array, node: DerNode): DerNode[] {
  const children: DerNode[] = [];
  let offset = node.start;
  while (offset < node.end) {
    const child = readNode(bytes, offset);
    children.push(child);
    offset = child.tlvEnd;
  }
  return children;
}

export function content(bytes: Uint8Array, node: DerNode): Uint8Array {
  return bytes.subarray(node.start, node.end);
}

export function tlv(bytes: Uint8Array, node: DerNode): Uint8Array {
  return bytes.subarray(node.tlvStart, node.tlvEnd);
}

/** Dotted OID string, e.g. "1.2.840.113549.1.1.1". */
export function readOid(bytes: Uint8Array, node: DerNode): string {
  if (node.tag !== TAG.OID) throw new DerError("expected an OID");
  const body = content(bytes, node);
  if (body.length === 0) throw new DerError("empty OID");

  const parts: number[] = [Math.floor(body[0]! / 40), body[0]! % 40];
  let value = 0;
  for (let i = 1; i < body.length; i++) {
    const byte = body[i]!;
    value = value * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join(".");
}

export const OID = {
  RSA: "1.2.840.113549.1.1.1",
  RSA_PSS: "1.2.840.113549.1.1.10",
  EC_PUBLIC_KEY: "1.2.840.10045.2.1",
  ED25519: "1.3.101.112",
  P256: "1.2.840.10045.3.1.7",
  P384: "1.3.132.0.34",
  P521: "1.3.132.0.35",
} as const;

export const CURVE_BY_OID: Record<string, string> = {
  [OID.P256]: "P-256",
  [OID.P384]: "P-384",
  [OID.P521]: "P-521",
};

// --- writing ---------------------------------------------------------------

function encodeLength(length: number): number[] {
  if (length < 0x80) return [length];
  const bytes: number[] = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining = Math.floor(remaining / 256);
  }
  return [0x80 | bytes.length, ...bytes];
}

export function encode(tag: number, body: Uint8Array): Uint8Array {
  const header = [tag, ...encodeLength(body.length)];
  const out = new Uint8Array(header.length + body.length);
  out.set(header, 0);
  out.set(body, header.length);
  return out;
}

export function concat(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export function encodeOid(oid: string): Uint8Array {
  const parts = oid.split(".").map(Number);
  const body: number[] = [parts[0]! * 40 + parts[1]!];
  for (const part of parts.slice(2)) {
    const chunk: number[] = [part & 0x7f];
    let remaining = Math.floor(part / 128);
    while (remaining > 0) {
      chunk.unshift((remaining & 0x7f) | 0x80);
      remaining = Math.floor(remaining / 128);
    }
    body.push(...chunk);
  }
  return encode(TAG.OID, new Uint8Array(body));
}

export function encodeSequence(...children: Uint8Array[]): Uint8Array {
  return encode(TAG.SEQUENCE, concat(...children));
}

export function encodeNull(): Uint8Array {
  return new Uint8Array([TAG.NULL, 0x00]);
}

/** BIT STRING with the mandatory zero "unused bits" prefix byte. */
export function encodeBitString(body: Uint8Array): Uint8Array {
  return encode(TAG.BIT_STRING, concat(new Uint8Array([0x00]), body));
}

export function encodeInteger(value: number): Uint8Array {
  return encode(TAG.INTEGER, new Uint8Array([value]));
}
