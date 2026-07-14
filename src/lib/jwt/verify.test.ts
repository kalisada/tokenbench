import { describe, expect, it } from "vitest";
import { SUPPORTED_ALGS, getAlgorithm, isAlgorithmAvailable } from "./algorithms";
import { generateKeyPair } from "./keys";
import { signJwt } from "./sign";
import { verifyJwt, verifyWithJwks } from "./verify";
import {
  EC_P256_PUBLIC,
  EC_SEC1_PRIVATE,
  HS256_SECRET,
  HS256_TOKEN,
  RSA_CERTIFICATE,
  RSA_PKCS1_PUBLIC,
  RSA_PKCS8_PRIVATE,
  RSA_SPKI_PUBLIC,
} from "./fixtures";

const NOW = new Date("2026-07-11T12:00:00Z");
const nowSeconds = Math.floor(NOW.getTime() / 1000);

describe("S8 — HS256 verify with the correct secret", () => {
  it("reports a valid signature", async () => {
    const result = await verifyJwt(HS256_TOKEN, HS256_SECRET);

    expect(result.signature).toBe("valid");
    expect(result.message).toBe("Signature VALID");
  });
});

describe("S9 — wrong secret, and separated verdicts", () => {
  it("reports an invalid signature", async () => {
    const result = await verifyJwt(HS256_TOKEN, "not-the-secret");

    expect(result.signature).toBe("invalid");
    expect(result.message).toMatch(/doesn't match or the token was tampered with/);
  });

  it("keeps signature and expiry as independent verdicts", async () => {
    // The single most common real state: correctly signed, but expired.
    const secret = "a-test-secret-of-sufficient-length-000000";
    const token = await signJwt({
      alg: "HS256",
      key: secret,
      payload: { sub: "x", exp: nowSeconds - 86400 },
    });

    const result = await verifyJwt(token, secret, { now: NOW });

    expect(result.signature).toBe("valid");
    expect(result.time.status).toBe("expired");
  });
});

describe("S10 — secret encoding trap", () => {
  it("verifies a base64-encoded secret under the base64 toggle", async () => {
    const secretBytes = "0123456789abcdef0123456789abcdef";
    const base64 = btoa(secretBytes);

    const token = await signJwt({
      alg: "HS256",
      key: base64,
      secretEncoding: "base64",
      payload: { sub: "x" },
    });

    await expect(
      verifyJwt(token, base64, { secretEncoding: "base64" }).then((r) => r.signature),
    ).resolves.toBe("valid");

    // Same string read as utf-8 is a different key, and so must fail.
    const asUtf8 = await verifyJwt(token, base64, { secretEncoding: "utf-8" });
    expect(asUtf8.signature).toBe("invalid");
  });

  it("hints at the base64 toggle when a failing secret looks base64", async () => {
    const base64Secret = btoa("0123456789abcdef0123456789abcdef");
    const result = await verifyJwt(HS256_TOKEN, base64Secret);

    expect(result.signature).toBe("invalid");
    expect(result.hint).toMatch(/base64 toggle/);
  });

  it("does not hint for an ordinary passphrase", async () => {
    const result = await verifyJwt(HS256_TOKEN, "hunter2");
    expect(result.hint).toBeUndefined();
  });
});

describe("S11 — RS256 with a public key, in every encoding it arrives in", () => {
  const rs256Token = () =>
    signJwt({ alg: "RS256", key: RSA_PKCS8_PRIVATE, payload: { sub: "rsa" } });

  it("verifies against SPKI PEM", async () => {
    const result = await verifyJwt(await rs256Token(), RSA_SPKI_PUBLIC);
    expect(result.signature).toBe("valid");
  });

  it("verifies against a PKCS#1 (BEGIN RSA PUBLIC KEY) PEM", async () => {
    const result = await verifyJwt(await rs256Token(), RSA_PKCS1_PUBLIC);
    expect(result.signature).toBe("valid");
  });

  it("verifies against a certificate, extracting the key inside", async () => {
    const result = await verifyJwt(await rs256Token(), RSA_CERTIFICATE);
    expect(result.signature).toBe("valid");
  });

  it("tolerates CRLF line endings and leading whitespace", async () => {
    const mangled = `\n   ${RSA_SPKI_PUBLIC.replace(/\n/g, "\r\n")}\n  `;
    const result = await verifyJwt(await rs256Token(), mangled);
    expect(result.signature).toBe("valid");
  });

  it("names the mismatch when the key type is wrong for the algorithm", async () => {
    const result = await verifyJwt(await rs256Token(), EC_P256_PUBLIC);

    expect(result.signature).toBe("error");
    expect(result.message).toMatch(/RS256.*needs an RSA key.*you pasted an EC key/i);
  });

  it("names the mismatch when the EC curve is wrong for the algorithm", async () => {
    const token = await signJwt({
      alg: "ES384",
      key: (await generateKeyPair("ES384")).privateKeyPem,
      payload: { sub: "x" },
    });

    const result = await verifyJwt(token, EC_P256_PUBLIC);
    expect(result.signature).toBe("error");
    expect(result.message).toMatch(/ES384 requires a P-384 key, but that key uses P-256/);
  });
});

describe("S12 — JWK and JWKS input", () => {
  it("verifies against a bare JWK", async () => {
    const { privateKeyPem } = await generateKeyPair("RS256");
    const token = await signJwt({ alg: "RS256", key: privateKeyPem, payload: { sub: "x" } });

    // Export the matching public JWK the way an IdP would publish it.
    const publicJwk = await publicJwkFor("RS256", privateKeyPem);
    const result = await verifyJwt(token, JSON.stringify(publicJwk));

    expect(result.signature).toBe("valid");
  });

  it("selects the JWKS key matching the token's kid", async () => {
    const signer = await generateKeyPair("RS256");
    const decoy = await generateKeyPair("RS256");

    const token = await signJwt({
      alg: "RS256",
      key: signer.privateKeyPem,
      header: { kid: "signing-key-2" },
      payload: { sub: "x" },
    });

    const jwks = {
      keys: [
        { ...(await publicJwkFor("RS256", decoy.privateKeyPem)), kid: "signing-key-1" },
        { ...(await publicJwkFor("RS256", signer.privateKeyPem)), kid: "signing-key-2" },
      ],
    };

    const result = await verifyWithJwks(token, jwks);

    expect(result.signature).toBe("valid");
    expect(result.matchedKid).toBe("signing-key-2");
  });

  it("falls back to trying every key when no kid matches, and says which worked", async () => {
    const signer = await generateKeyPair("RS256");
    const decoy = await generateKeyPair("RS256");

    // Token names a kid the JWKS does not contain.
    const token = await signJwt({
      alg: "RS256",
      key: signer.privateKeyPem,
      header: { kid: "rotated-away" },
      payload: { sub: "x" },
    });

    const jwks = {
      keys: [
        { ...(await publicJwkFor("RS256", decoy.privateKeyPem)), kid: "a" },
        { ...(await publicJwkFor("RS256", signer.privateKeyPem)), kid: "b" },
      ],
    };

    const result = await verifyWithJwks(token, jwks);

    expect(result.signature).toBe("valid");
    expect(result.matchedKid).toBe("b");
  });

  it("reports clearly when no key in the JWKS verifies the token", async () => {
    const signer = await generateKeyPair("RS256");
    const decoy = await generateKeyPair("RS256");

    const token = await signJwt({
      alg: "RS256",
      key: signer.privateKeyPem,
      header: { kid: "missing" },
      payload: { sub: "x" },
    });

    const jwks = { keys: [{ ...(await publicJwkFor("RS256", decoy.privateKeyPem)), kid: "a" }] };
    const result = await verifyWithJwks(token, jwks);

    expect(result.signature).toBe("invalid");
    expect(result.message).toMatch(/No key in the JWKS has kid "missing"/);
  });
});

describe("S14 — algorithm confusion", () => {
  it("refuses an HS256 verify against a pasted public key, with the explanation", async () => {
    const result = await verifyJwt(HS256_TOKEN, RSA_SPKI_PUBLIC);

    expect(result.signature).toBe("error");
    expect(result.message).toMatch(/algorithm-confusion attack/i);
    expect(result.message).toMatch(/your server does this, it's vulnerable/i);
  });

  it("refuses a JWK pasted as the HMAC secret too", async () => {
    const jwk = JSON.stringify(await publicJwkFor("RS256", RSA_PKCS8_PRIVATE));
    const result = await verifyJwt(HS256_TOKEN, jwk);

    expect(result.signature).toBe("error");
    expect(result.message).toMatch(/algorithm-confusion attack/i);
  });
});

describe("S15 — every algorithm round-trips", () => {
  const asymmetric = SUPPORTED_ALGS.filter((alg) => getAlgorithm(alg)!.family !== "HMAC");
  const symmetric = SUPPORTED_ALGS.filter((alg) => getAlgorithm(alg)!.family === "HMAC");

  it.each(symmetric)("%s signs and verifies", async (alg) => {
    const secret = "a-secret-long-enough-for-sha512-hashing-0000000000000000000000000000";
    const token = await signJwt({ alg, key: secret, payload: { sub: alg } });

    const result = await verifyJwt(token, secret);
    expect(result.signature).toBe("valid");
  });

  it.each(asymmetric)("%s signs and verifies", async (alg) => {
    if (!(await isAlgorithmAvailable(alg))) {
      // EdDSA is absent in older engines; the tool feature-detects rather than
      // claiming support it does not have.
      return;
    }

    const { privateKeyPem, publicKeyPem } = await generateKeyPair(alg);
    const token = await signJwt({ alg, key: privateKeyPem, payload: { sub: alg } });

    const result = await verifyJwt(token, publicKeyPem);
    expect(result.signature).toBe("valid");
  });

  it("verifies an ES256 token signed with a SEC1 (BEGIN EC PRIVATE KEY) key", async () => {
    const token = await signJwt({ alg: "ES256", key: EC_SEC1_PRIVATE, payload: { sub: "ec" } });
    const result = await verifyJwt(token, EC_P256_PUBLIC);

    expect(result.signature).toBe("valid");
  });
});

describe("unsecured tokens", () => {
  it("reports alg:none as unsecured rather than valid or invalid", async () => {
    const token = await signJwt({ alg: "none", payload: { sub: "x" } });
    const result = await verifyJwt(token, "irrelevant");

    expect(result.signature).toBe("unsecured");
    expect(result.message).toMatch(/UNSECURED/);
  });
});

/** Publish a private PEM's public half as a JWK, the way an IdP's JWKS would. */
async function publicJwkFor(alg: string, privatePem: string): Promise<JsonWebKey> {
  const spec = getAlgorithm(alg)!;
  const der = pemToDer(privatePem);
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    der as unknown as BufferSource,
    spec.importParams as AlgorithmIdentifier,
    true,
    ["sign"],
  );

  const jwk = (await crypto.subtle.exportKey("jwk", privateKey)) as Record<string, unknown>;
  const { d, p, q, dp, dq, qi, key_ops, ...pub } = jwk;
  return pub as JsonWebKey;
}

function pemToDer(pem: string): Uint8Array {
  const body = pem
    .replace(/-----[A-Z ]+-----/g, "")
    .replace(/\s+/g, "");
  const binary = atob(body);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
