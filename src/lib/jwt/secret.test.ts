import { describe, expect, it } from "vitest";
import { SECRET_BITS, SECRET_FORMATS, formatSecret, generateSecret, randomBytes } from "./secret";
import { signJwt } from "./sign";
import { verifyJwt } from "./verify";

describe("S20 — secret key generator", () => {
  it.each(SECRET_BITS)("generates %i bits of entropy", (bits) => {
    expect(randomBytes(bits)).toHaveLength(bits / 8);
  });

  it.each(SECRET_FORMATS)("renders as %s", (format) => {
    const bytes = new Uint8Array([0xff, 0x00, 0xbe, 0xef]);
    const output = formatSecret(bytes, format);

    switch (format) {
      case "hex":
        expect(output).toBe("ff00beef");
        break;
      case "base64":
        expect(output).toBe("/wC+7w==");
        break;
      case "base64url":
        expect(output).toBe("_wC-7w");
        break;
    }
  });

  it("does not repeat itself", () => {
    const secrets = new Set(Array.from({ length: 50 }, () => generateSecret(256, "hex")));
    expect(secrets.size).toBe(50);
  });

  it("produces a secret usable as an HS256 key", async () => {
    const secret = generateSecret(256, "base64");
    const token = await signJwt({
      alg: "HS256",
      key: secret,
      secretEncoding: "base64",
      payload: { sub: "x" },
    });

    const result = await verifyJwt(token, secret, { secretEncoding: "base64" });
    expect(result.signature).toBe("valid");
  });
});
