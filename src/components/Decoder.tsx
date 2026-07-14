import { useEffect, useMemo, useState } from "preact/hooks";
import type { JSX } from "preact";
import { trackOnce } from "@lib/analytics";
import { decodeJwt, evaluateTime } from "@lib/jwt/decode";
import { lintToken } from "@lib/jwt/lint";
import { JweError, JwtDecodeError, type DecodedJwt } from "@lib/jwt/types";
import { ClaimsTable, DecodedPanes, LintPanel, StatusBar, TimeStatus } from "./ui";

const SAMPLE =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

type Outcome =
  | { kind: "empty" }
  | { kind: "ok"; decoded: DecodedJwt }
  | { kind: "jwe"; message: string }
  | { kind: "error"; message: string };

function decode(input: string): Outcome {
  if (input.trim() === "") return { kind: "empty" };

  try {
    return { kind: "ok", decoded: decodeJwt(input) };
  } catch (error) {
    // S6: a JWE is a legitimate paste that deserves an explanation, not a
    // parse failure.
    if (error instanceof JweError) return { kind: "jwe", message: error.message };
    if (error instanceof JwtDecodeError) return { kind: "error", message: error.message };
    throw error;
  }
}

export default function Decoder(): JSX.Element {
  const [token, setToken] = useState("");

  // Decoding is synchronous and cheap, so it runs on every keystroke — S1
  // requires results on input, with no button to press.
  const outcome = useMemo(() => decode(token), [token]);

  return (
    <div>
      <div class="panel">
        <label for="token">
          Paste a JWT — a <code>Bearer</code> prefix, line breaks or URL-encoding are fine
        </label>
        <textarea
          id="token"
          class="token-input"
          spellcheck={false}
          autocomplete="off"
          autocapitalize="off"
          autocorrect="off"
          placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9…"
          value={token}
          onInput={(event) => setToken(event.currentTarget.value)}
        />
        <div class="btn-row" style="margin-top:10px">
          <button type="button" onClick={() => setToken(SAMPLE)}>
            Load a sample
          </button>
          <button type="button" onClick={() => setToken("")} disabled={token === ""}>
            Clear
          </button>
          <span class="hint" style="margin:0 0 0 auto">
            Decoding happens on this page. Nothing is sent anywhere.
          </span>
        </div>
      </div>

      {outcome.kind === "jwe" && (
        <div style="margin-top:16px">
          <StatusBar tone="info" label="ENCRYPTED (JWE)" note={outcome.message} />
        </div>
      )}

      {outcome.kind === "error" && (
        <div style="margin-top:16px">
          <StatusBar tone="red" label="Could not decode" note={outcome.message} />
        </div>
      )}

      {outcome.kind === "ok" && <Decoded decoded={outcome.decoded} />}
    </div>
  );
}

function Decoded({ decoded }: { decoded: DecodedJwt }): JSX.Element {
  const time = evaluateTime(decoded.payload);
  const lints = lintToken(decoded);

  // S33: counted in memory, transmitted only when the page closes. `alg` is the
  // header's algorithm name and nothing else — see the allowlist in analytics.ts.
  useEffect(() => {
    trackOnce("tool_used", { tool: "decoder" });
    trackOnce("verify_result", { result: "decoded", alg: decoded.header.alg ?? "none" });
    for (const lint of lints) trackOnce("lint_shown", { lint: lint.id });
  }, [decoded, lints]);

  return (
    <div style="margin-top:16px">
      {/* S4: an unsecured token still decodes; the banner carries the warning. */}
      {decoded.unsecured && (
        <StatusBar
          tone="red"
          label="UNSECURED — no signature"
          note="This token declares alg:none, so nothing stops anyone from rewriting its claims."
        />
      )}

      <TimeStatus verdict={time} />

      <div style="margin-top:16px">
        <DecodedPanes decoded={decoded} />
      </div>

      <div class="panel" style="margin-top:16px">
        <p class="panel__title">Claims</p>
        <ClaimsTable payload={decoded.payload} />
      </div>

      <div style="margin-top:16px">
        <LintPanel lints={lints} />
      </div>
    </div>
  );
}
