import { describe, expect, it } from "vitest";
import { decodeJwt } from "./decode";
import { lintToken, type Lint } from "./lint";
import { signJwt } from "./sign";
import type { JwtPayload } from "./types";

const NOW = new Date("2026-07-11T12:00:00Z");
const nowSeconds = Math.floor(NOW.getTime() / 1000);

async function lintsFor(
  payload: JwtPayload,
  options: { header?: Record<string, unknown>; secret?: string; alg?: string } = {},
): Promise<Lint[]> {
  const alg = options.alg ?? "HS256";
  const token = await signJwt({
    alg,
    key: "a-perfectly-fine-secret-000000000000",
    header: options.header,
    payload,
  });
  return lintToken(decodeJwt(token), { secret: options.secret, now: NOW });
}

const ids = (lints: Lint[]) => lints.map((lint) => lint.id);

describe("S7 — security lint layer", () => {
  it("flags alg:none in red", async () => {
    const token = await signJwt({ alg: "none", payload: { sub: "x" } });
    const lints = lintToken(decodeJwt(token));

    const none = lints.find((lint) => lint.id === "alg-none");
    expect(none?.level).toBe("red");
  });

  it("flags a well-known default secret, but only when verification was attempted", async () => {
    const withSecret = await lintsFor({ exp: nowSeconds + 60 }, { secret: "your-256-bit-secret" });
    expect(ids(withSecret)).toContain("weak-secret");
    expect(withSecret.find((lint) => lint.id === "weak-secret")?.level).toBe("amber");

    // No secret supplied means no claim can be made about it.
    const withoutSecret = await lintsFor({ exp: nowSeconds + 60 });
    expect(ids(withoutSecret)).not.toContain("weak-secret");
  });

  it("flags a secret shorter than the algorithm's hash", async () => {
    const lints = await lintsFor({ exp: nowSeconds + 60 }, { secret: "short" });
    expect(ids(lints)).toContain("short-secret");
  });

  it("passes a strong, long secret", async () => {
    const lints = await lintsFor(
      { exp: nowSeconds + 60, iat: nowSeconds },
      { secret: "9f2c8ab41d7e5630a1b9c4e8f70d2a6b3c5e9f1a4d8b2c6e0f3a7d9b1c4e8f2a" },
    );
    expect(ids(lints)).not.toContain("weak-secret");
    expect(ids(lints)).not.toContain("short-secret");
  });

  it("flags a token with no expiry", async () => {
    const lints = await lintsFor({ sub: "x", iat: nowSeconds });

    const noExp = lints.find((lint) => lint.id === "no-exp");
    expect(noExp?.level).toBe("amber");
    expect(noExp?.title).toMatch(/never expires/i);
  });

  it("flags a token living longer than 30 days as info", async () => {
    const lints = await lintsFor({ iat: nowSeconds, exp: nowSeconds + 90 * 86400 });

    const longLived = lints.find((lint) => lint.id === "long-lived");
    expect(longLived?.level).toBe("info");
    expect(longLived?.detail).toMatch(/90 days/);
  });

  it("does not flag a normal one-hour token", async () => {
    const lints = await lintsFor({ iat: nowSeconds, exp: nowSeconds + 3600 });
    expect(ids(lints)).toEqual([]);
  });

  it("notes a kid as an informational key-lookup signal", async () => {
    const lints = await lintsFor(
      { iat: nowSeconds, exp: nowSeconds + 3600 },
      { header: { kid: "key-7" } },
    );

    const kid = lints.find((lint) => lint.id === "kid");
    expect(kid?.level).toBe("info");
    expect(kid?.title).toContain("key-7");
  });

  it("never blocks: lints are additive to a successful decode", async () => {
    // A maximally alarming token still decodes and simply carries more lints.
    const token = await signJwt({ alg: "none", payload: { sub: "x" } });
    const decoded = decodeJwt(token);

    expect(decoded.payload).toEqual({ sub: "x" });
    expect(lintToken(decoded).length).toBeGreaterThan(1);
  });
});
