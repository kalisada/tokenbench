import { describe, expect, it } from "vitest";
import { encodeStringToBase64Url } from "./base64url";
import { MAX_TOKEN_LENGTH, decodeJwt, describeTimestamp, evaluateTime } from "./decode";
import { JweError, JwtDecodeError, type JwtPayload } from "./types";
import { HS256_TOKEN } from "./fixtures";

/** Build an unsigned-but-well-formed token so decode paths can be exercised. */
function tokenWith(payload: JwtPayload, header: Record<string, unknown> = { alg: "HS256" }) {
  return `${encodeStringToBase64Url(JSON.stringify(header))}.${encodeStringToBase64Url(
    JSON.stringify(payload),
  )}.c2ln`;
}

const NOW = new Date("2026-07-11T12:00:00Z");
const nowSeconds = Math.floor(NOW.getTime() / 1000);

describe("S1 — happy path", () => {
  it("splits a valid token into header, payload and signature", () => {
    const decoded = decodeJwt(HS256_TOKEN);

    expect(decoded.header).toEqual({ alg: "HS256", typ: "JWT" });
    expect(decoded.payload).toEqual({
      sub: "1234567890",
      name: "John Doe",
      iat: 1516239022,
    });
    expect(decoded.signature).toBe("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
    expect(decoded.unsecured).toBe(false);
  });

  it("renders timestamps human-readably for the claims table", () => {
    expect(describeTimestamp(nowSeconds + 7200, NOW)).toBe(
      "2026-07-11 14:00 UTC (in 2 hours)",
    );
  });
});

describe("S2 — expired token", () => {
  it("still decodes, and reports expiry prominently", () => {
    const token = tokenWith({ exp: nowSeconds - 3 * 86400 });
    const decoded = decodeJwt(token);
    const verdict = evaluateTime(decoded.payload, NOW);

    expect(decoded.payload.exp).toBeDefined();
    expect(verdict.status).toBe("expired");
    expect(verdict.summary).toBe("EXPIRED 3 days ago");
  });
});

describe("S3 — not-yet-valid token", () => {
  it("reports nbf in the future", () => {
    const verdict = evaluateTime({ nbf: nowSeconds + 7200 }, NOW);

    expect(verdict.status).toBe("not-yet-valid");
    expect(verdict.summary).toBe("Not valid yet (nbf in 2 hours)");
  });

  it("treats expiry as taking precedence over nbf", () => {
    const verdict = evaluateTime({ exp: nowSeconds - 60, nbf: nowSeconds + 60 }, NOW);
    expect(verdict.status).toBe("expired");
  });
});

describe("S4 — hostile-but-innocent input", () => {
  const expected = decodeJwt(HS256_TOKEN).payload;

  it("strips a Bearer prefix", () => {
    expect(decodeJwt(`Bearer ${HS256_TOKEN}`).payload).toEqual(expected);
  });

  it("strips a full Authorization header line", () => {
    expect(decodeJwt(`Authorization: Bearer ${HS256_TOKEN}`).payload).toEqual(expected);
  });

  it("strips whitespace and newlines from a terminal copy", () => {
    const wrapped = `  ${HS256_TOKEN.slice(0, 40)}\n  ${HS256_TOKEN.slice(40)}  \n`;
    expect(decodeJwt(wrapped).payload).toEqual(expected);
  });

  it("un-escapes a URL-encoded token", () => {
    expect(decodeJwt(encodeURIComponent(HS256_TOKEN)).payload).toEqual(expected);
  });

  it("strips surrounding quotes", () => {
    expect(decodeJwt(`"${HS256_TOKEN}"`).payload).toEqual(expected);
  });

  it("accepts standard base64 segments and missing padding", () => {
    // "+/" instead of "-_" is what a hand-rolled encoder often emits.
    const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
    const payload = btoa(JSON.stringify({ sub: "abc" }));
    const decoded = decodeJwt(`${header}.${payload}.sig`);
    expect(decoded.payload).toEqual({ sub: "abc" });
  });

  it("decodes a two-segment token as unsecured rather than refusing", () => {
    const token = `${encodeStringToBase64Url(
      JSON.stringify({ alg: "none" }),
    )}.${encodeStringToBase64Url(JSON.stringify({ sub: "x" }))}`;
    const decoded = decodeJwt(token);

    expect(decoded.unsecured).toBe(true);
    expect(decoded.payload).toEqual({ sub: "x" });
  });

  it("names the failing segment on true garbage", () => {
    const error = (() => {
      try {
        decodeJwt("!!!.!!!.!!!");
      } catch (e) {
        return e as JwtDecodeError;
      }
    })();

    expect(error).toBeInstanceOf(JwtDecodeError);
    expect(error!.segment).toBe("header");
    expect(error!.message).toMatch(/header/i);
    expect(error!.message).toMatch(/base64url/i);
  });

  it("explains a wrong segment count instead of blanking", () => {
    expect(() => decodeJwt("abc.def.ghi.jkl")).toThrow(/3 dot-separated segments/);
  });
});

describe("S5 — hostile payloads", () => {
  it("caps oversized input", () => {
    const huge = "a".repeat(MAX_TOKEN_LENGTH + 1);
    expect(() => decodeJwt(huge)).toThrow(/capped at/);
  });

  it("preserves script tags as data, never interpreting them", () => {
    const decoded = decodeJwt(tokenWith({ name: "<script>alert(1)</script>" }));
    // The renderer's job is textContent; the decoder's job is to not mangle it.
    expect(decoded.payload.name).toBe("<script>alert(1)</script>");
  });

  it("round-trips unicode and emoji claims", () => {
    const decoded = decodeJwt(tokenWith({ name: "山田太郎 🎫" }));
    expect(decoded.payload.name).toBe("山田太郎 🎫");
  });
});

describe("S6 — JWE", () => {
  it("identifies a five-segment token rather than erroring generically", () => {
    expect(() => decodeJwt("a.b.c.d.e")).toThrow(JweError);
    expect(() => decodeJwt("a.b.c.d.e")).toThrow(/encrypted JWT \(JWE\)/);
  });
});
