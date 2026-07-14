import { describe, expect, it } from "vitest";
import { sanitize, type Props } from "./analytics";
import { HS256_TOKEN, HS256_SECRET, RSA_PKCS8_PRIVATE } from "./jwt/fixtures";

/**
 * S33's never-log list, turned into a test. The privacy page makes written
 * promises about what analytics can carry; this is what holds us to them.
 */
describe("S33 — analytics cannot transmit content", () => {
  it("drops a token, however it is smuggled in", () => {
    // Under every allowed key, under a disallowed key, as the whole prop bag.
    expect(sanitize("verify_result", { alg: HS256_TOKEN })).toEqual({});
    expect(sanitize("verify_result", { result: HS256_TOKEN })).toEqual({});
    expect(sanitize("lint_shown", { lint: HS256_TOKEN })).toEqual({});
    expect(sanitize("tool_used", { token: HS256_TOKEN } as Props)).toEqual({});
  });

  it("drops secrets, keys and JWKS URLs", () => {
    expect(sanitize("verify_result", { alg: HS256_SECRET })).toEqual({});
    expect(sanitize("token_generated", { alg: RSA_PKCS8_PRIVATE })).toEqual({});
    expect(
      sanitize("jwks_fetch", { outcome: "https://idp.example.com/.well-known/jwks.json" }),
    ).toEqual({});
  });

  it("drops claim values", () => {
    expect(sanitize("tool_used", { sub: "1234567890", name: "John Doe" } as Props)).toEqual({});
  });

  it("rejects token fragments and short secrets", () => {
    // These are the two that defeated the original pattern-based check: both are
    // short and contain only innocuous characters. A closed vocabulary stops
    // them; a regex does not. This test is why the design changed.
    for (const value of ["eyJhbGciOi", "hunter2", "your-256-bit-secret", "abc.def", "a+b/c="]) {
      const result = sanitize("verify_result", { alg: value });
      expect(result.alg, `"${value}" must not survive`).toBeUndefined();
    }
  });

  it("rejects any value outside the enumerated vocabulary", () => {
    // Even a well-formed, harmless-looking value is dropped if it isn't a known
    // constant. Nothing derived from user input can be a known constant.
    expect(sanitize("verify_result", { result: "probably_fine" })).toEqual({});
    expect(sanitize("lint_shown", { lint: "some-new-lint" })).toEqual({});
    expect(sanitize("tool_used", { tool: "decoder2" })).toEqual({});
    expect(sanitize("copy", { what: "everything" })).toEqual({});
  });

  it("still lets the metadata S33 actually asked for through", () => {
    expect(sanitize("verify_result", { result: "invalid", alg: "RS256" })).toEqual({
      result: "invalid",
      alg: "RS256",
    });
    expect(sanitize("lint_shown", { lint: "alg-none" })).toEqual({ lint: "alg-none" });
    expect(sanitize("jwks_fetch", { outcome: "cors_blocked" })).toEqual({
      outcome: "cors_blocked",
    });
    expect(sanitize("token_generated", { alg: "EdDSA", tamper: true })).toEqual({
      alg: "EdDSA",
      tamper: "true",
    });
  });

  it("ignores properties that are not declared for the event", () => {
    // `alg` is meaningful on verify_result but is not declared on lint_shown.
    expect(sanitize("lint_shown", { lint: "no-exp", alg: "RS256" })).toEqual({ lint: "no-exp" });
  });
});
