import { describe, expect, it } from "vitest";
import { decodeJwt } from "./decode";
import { generateKeyPair } from "./keys";
import { defaultPayload, parseRelativeExpiry, signJwt } from "./sign";
import { verifyJwt } from "./verify";
import { RSA_PKCS1_PRIVATE, RSA_SPKI_PUBLIC } from "./fixtures";

const NOW = new Date("2026-07-11T12:00:00Z");
const nowSeconds = Math.floor(NOW.getTime() / 1000);

describe("S16 — quick generate", () => {
  it("ships a working default payload with sub, name, iat and a +1h exp", () => {
    const payload = defaultPayload(NOW);

    expect(payload.sub).toBe("1234567890");
    expect(payload.name).toBe("Test User");
    expect(payload.iat).toBe(nowSeconds);
    expect(payload.exp).toBe(nowSeconds + 3600);
  });

  it("produces a token that verifies against the secret it was signed with", async () => {
    const secret = "generated-test-secret-0000000000";
    const token = await signJwt({ alg: "HS256", key: secret, payload: defaultPayload(NOW) });

    const result = await verifyJwt(token, secret, { now: NOW });
    expect(result.signature).toBe("valid");
    expect(result.time.status).toBe("valid");
  });
});

describe("S17 — full control", () => {
  it("carries custom header members through, with alg and typ set", async () => {
    const token = await signJwt({
      alg: "HS256",
      key: "secret-value-0000000000000000000",
      header: { kid: "key-1", cty: "example" },
      payload: { sub: "x" },
    });

    expect(decodeJwt(token).header).toEqual({
      alg: "HS256",
      typ: "JWT",
      kid: "key-1",
      cty: "example",
    });
  });

  it("parses relative expiry input", () => {
    expect(parseRelativeExpiry("+2h", NOW)).toBe(nowSeconds + 7200);
    expect(parseRelativeExpiry("30m", NOW)).toBe(nowSeconds + 1800);
    expect(parseRelativeExpiry("7d", NOW)).toBe(nowSeconds + 7 * 86400);
    expect(() => parseRelativeExpiry("soon")).toThrow(/relative time/);
  });
});

describe("S18 — asymmetric generate", () => {
  it("generates a usable PEM key pair", async () => {
    const { privateKeyPem, publicKeyPem } = await generateKeyPair("RS256");

    expect(privateKeyPem).toMatch(/^-----BEGIN PRIVATE KEY-----/);
    expect(publicKeyPem).toMatch(/^-----BEGIN PUBLIC KEY-----/);

    const token = await signJwt({ alg: "RS256", key: privateKeyPem, payload: { sub: "x" } });
    expect((await verifyJwt(token, publicKeyPem)).signature).toBe("valid");
  });

  it("accepts a pasted PKCS#1 private key, matching S11's input tolerance", async () => {
    const token = await signJwt({ alg: "RS256", key: RSA_PKCS1_PRIVATE, payload: { sub: "x" } });
    expect((await verifyJwt(token, RSA_SPKI_PUBLIC)).signature).toBe("valid");
  });

  it("refuses to sign with a public key", async () => {
    const result = signJwt({ alg: "RS256", key: RSA_SPKI_PUBLIC, payload: { sub: "x" } });
    await expect(result).rejects.toThrow(/Signing needs a private key/);
  });

  it("refuses to generate a key pair for a symmetric algorithm", async () => {
    await expect(generateKeyPair("HS256")).rejects.toThrow(/shared secret, not a key pair/);
  });
});

describe("S19 — deliberate bad tokens", () => {
  it("emits a tampered token that parses but fails verification", async () => {
    const secret = "test-secret-000000000000000000000";
    const token = await signJwt({
      alg: "HS256",
      key: secret,
      payload: { sub: "x" },
      tamper: true,
    });

    // It must still decode — the point is to test a server's rejection path,
    // not its parser.
    expect(decodeJwt(token).payload).toEqual({ sub: "x" });

    const result = await verifyJwt(token, secret);
    expect(result.signature).toBe("invalid");
  });

  it("emits an alg:none token with an empty signature", async () => {
    const token = await signJwt({ alg: "none", payload: { sub: "x" } });

    expect(token.endsWith(".")).toBe(true);

    const decoded = decodeJwt(token);
    expect(decoded.header.alg).toBe("none");
    expect(decoded.unsecured).toBe(true);
  });
});
