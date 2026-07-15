import { useEffect, useMemo, useState } from "preact/hooks";
import type { JSX } from "preact";
import { trackOnce } from "@lib/analytics";
import { getAlgorithm } from "@lib/jwt/algorithms";
import { decodeJwt } from "@lib/jwt/decode";
import { looksLikeJwks } from "@lib/jwt/keys";
import { lintToken } from "@lib/jwt/lint";
import type { SecretEncoding } from "@lib/jwt/keys";
import {
  JwksFetchError,
  curlCommandFor,
  fetchJwks,
  verifyJwt,
  verifyWithJwks,
  type VerificationResult,
} from "@lib/jwt/verify";
import { JweError, JwtDecodeError } from "@lib/jwt/types";
import { ClaimsTable, DecodedPanes, LintPanel, StatusBar, TimeStatus } from "./ui";

type KeySource = "paste" | "jwks-url";

const SIGNATURE_TONE = {
  valid: "valid",
  invalid: "invalid",
  unsecured: "red",
  error: "amber",
} as const;

export default function Validator(): JSX.Element {
  const [token, setToken] = useState("");
  const [key, setKey] = useState("");
  const [encoding, setEncoding] = useState<SecretEncoding>("utf-8");
  const [source, setSource] = useState<KeySource>("paste");

  const [jwksUrl, setJwksUrl] = useState("");
  const [jwks, setJwks] = useState<unknown>(undefined);
  const [fetchState, setFetchState] = useState<
    { kind: "idle" } | { kind: "loading" } | { kind: "error"; error: JwksFetchError }
  >({ kind: "idle" });

  const [result, setResult] = useState<VerificationResult | undefined>();
  const [decodeError, setDecodeError] = useState<string | undefined>();

  // The token's own alg decides which key inputs even make sense.
  const alg = useMemo(() => {
    try {
      return decodeJwt(token).header.alg;
    } catch {
      return undefined;
    }
  }, [token]);

  const isHmac = alg !== undefined && getAlgorithm(alg)?.family === "HMAC";

  useEffect(() => {
    if (token.trim() === "") {
      setResult(undefined);
      setDecodeError(undefined);
      return;
    }

    // Surface a bad token immediately, without waiting for a key.
    try {
      decodeJwt(token);
      setDecodeError(undefined);
    } catch (error) {
      if (error instanceof JweError || error instanceof JwtDecodeError) {
        setDecodeError(error.message);
        setResult(undefined);
        return;
      }
      throw error;
    }

    const usingJwks = source === "jwks-url" ? jwks !== undefined : looksLikeJwks(key);
    if (!usingJwks && (source === "jwks-url" || key.trim() === "")) {
      setResult(undefined);
      return;
    }

    // Verification is async; a later keystroke must win over an earlier one.
    let current = true;

    const run = async (): Promise<VerificationResult> => {
      if (source === "jwks-url") return verifyWithJwks(token, jwks);
      if (looksLikeJwks(key)) return verifyWithJwks(token, JSON.parse(key));
      return verifyJwt(token, key, { secretEncoding: encoding });
    };

    void run()
      .then((next) => {
        if (current) setResult(next);
      })
      .catch((error: unknown) => {
        if (!current) return;
        setDecodeError(error instanceof Error ? error.message : String(error));
        setResult(undefined);
      });

    return () => {
      current = false;
    };
  }, [token, key, encoding, source, jwks]);

  // S7: the weak-secret lint can only fire when the user actually supplied one.
  const lints = useMemo(() => {
    if (!result) return [];
    return lintToken(result.decoded, {
      secret: isHmac && source === "paste" && key !== "" ? key : undefined,
    });
  }, [result, key, isHmac, source]);

  // S33. The verdict and the algorithm name only — never the token, the key, or
  // the URL. Queued in memory; nothing goes out until the page closes.
  useEffect(() => {
    if (!result) return;
    trackOnce("tool_used", { tool: "validator" });
    trackOnce("verify_result", {
      result: result.signature,
      alg: result.decoded.header.alg ?? "none",
    });
    for (const lint of lints) trackOnce("lint_shown", { lint: lint.id });
  }, [result, lints]);

  const doFetch = async (): Promise<void> => {
    setFetchState({ kind: "loading" });
    try {
      const fetched = await fetchJwks(jwksUrl);
      setJwks(fetched);
      setFetchState({ kind: "idle" });
      trackOnce("jwks_fetch", { outcome: "ok" });
    } catch (error) {
      const failure = error as JwksFetchError;
      setJwks(undefined);
      setFetchState({ kind: "error", error: failure });
      // The CORS failure rate is the single most useful number S33 asks for:
      // it sizes how many visitors are wrestling with a real JWKS endpoint.
      trackOnce("jwks_fetch", { outcome: failure.corsLikely ? "cors_blocked" : "failed" });
    }
  };

  return (
    <div>
      <div class="grid-2 io-grid">
        <div class="panel">
          <div class="io-head">
            <label for="token">Token</label>
          </div>
          <textarea
            id="token"
            class="token-input"
            spellcheck={false}
            autocomplete="off"
            placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9…"
            value={token}
            onInput={(event) => setToken(event.currentTarget.value)}
          />
          {/* Always render a hint so this panel's footer matches the key
              panel's, keeping the two boxes the same height. */}
          <p class="hint">
            {alg ? (
              <>
                Header declares <code>{alg}</code>
                {isHmac ? " — a shared secret" : " — a public/private key pair"}.
              </>
            ) : (
              "Paste a signed JWT. Expired or unsigned tokens are fine."
            )}
          </p>
        </div>

        <div class="panel">
          {/* Label and every toggle share one header row so this box's top
              lines up with the token box's top. */}
          <div class="io-head">
            {source === "paste" && (
              <label for="key">{isHmac ? "HMAC secret" : "Public key"}</label>
            )}

            <div class="io-head__controls">
              {/* S10: raw text and base64-encoded bytes are both common. */}
              {isHmac && source === "paste" && (
                <div class="segmented">
                  <button
                    type="button"
                    aria-pressed={encoding === "utf-8"}
                    onClick={() => setEncoding("utf-8")}
                  >
                    utf-8
                  </button>
                  <button
                    type="button"
                    aria-pressed={encoding === "base64"}
                    onClick={() => setEncoding("base64")}
                  >
                    base64
                  </button>
                </div>
              )}

              <div class="segmented">
                <button
                  type="button"
                  aria-pressed={source === "paste"}
                  onClick={() => setSource("paste")}
                >
                  Paste key
                </button>
                <button
                  type="button"
                  aria-pressed={source === "jwks-url"}
                  onClick={() => setSource("jwks-url")}
                >
                  JWKS URL
                </button>
              </div>
            </div>
          </div>

          {source === "paste" ? (
            <>
              <textarea
                id="key"
                class="token-input"
                spellcheck={false}
                autocomplete="off"
                placeholder={
                  isHmac
                    ? "your-256-bit-secret"
                    : "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq…\n-----END PUBLIC KEY-----"
                }
                value={key}
                onInput={(event) => setKey(event.currentTarget.value)}
              />
              <p class="hint">
                Accepts SPKI and PKCS#1 PEM, certificates, a bare JWK, or a full JWKS.
              </p>
            </>
          ) : (
            <JwksUrlPanel
              url={jwksUrl}
              onUrl={setJwksUrl}
              state={fetchState}
              loaded={jwks !== undefined}
              onFetch={doFetch}
              onPaste={(text) => {
                try {
                  setJwks(JSON.parse(text));
                  setFetchState({ kind: "idle" });
                } catch {
                  /* Ignore partial JSON while the user is still pasting. */
                }
              }}
            />
          )}
        </div>
      </div>

      {decodeError && (
        <div style="margin-top:16px">
          <StatusBar tone="red" label="Could not decode" note={decodeError} />
        </div>
      )}

      {result && (
        <div style="margin-top:16px">
          {/* S9: two verdicts, never merged. A correctly-signed expired token is
              the single most common real state, and collapsing them hides it. */}
          <StatusBar
            tone={SIGNATURE_TONE[result.signature]}
            label={result.message}
            note={result.hint}
          />
          <TimeStatus verdict={result.time} />

          <div style="margin-top:16px">
            <DecodedPanes decoded={result.decoded} />
          </div>

          <div class="panel" style="margin-top:16px">
            <p class="panel__title">Claims</p>
            <ClaimsTable payload={result.decoded.payload} />
          </div>

          <div style="margin-top:16px">
            <LintPanel lints={lints} />
          </div>
        </div>
      )}
    </div>
  );
}

function JwksUrlPanel({
  url,
  onUrl,
  state,
  loaded,
  onFetch,
  onPaste,
}: {
  url: string;
  onUrl: (value: string) => void;
  state: { kind: "idle" } | { kind: "loading" } | { kind: "error"; error: JwksFetchError };
  loaded: boolean;
  onFetch: () => void;
  onPaste: (text: string) => void;
}): JSX.Element {
  return (
    <>
      <label for="jwks-url">JWKS endpoint</label>
      <input
        id="jwks-url"
        type="url"
        spellcheck={false}
        placeholder="https://idp.example.com/.well-known/jwks.json"
        value={url}
        onInput={(event) => onUrl(event.currentTarget.value)}
      />

      {/* S13: the only network request this site makes, and only on this click. */}
      <div class="btn-row" style="margin-top:10px">
        <button
          type="button"
          class="primary"
          onClick={onFetch}
          disabled={url === "" || state.kind === "loading"}
        >
          {state.kind === "loading" ? "Fetching…" : "Fetch JWKS"}
        </button>
        {loaded && <span class="hint">JWKS loaded.</span>}
      </div>

      <p class="hint">
        This request goes directly from your browser to that server. The token itself is
        never sent anywhere.
      </p>

      {state.kind === "error" && (
        <div style="margin-top:12px">
          <StatusBar
            tone={state.error.corsLikely ? "amber" : "red"}
            label={state.error.corsLikely ? "Blocked by CORS" : "Fetch failed"}
            note={state.error.message}
          />
          {state.error.corsLikely && (
            <>
              <p class="hint" style="margin-top:10px">
                Most identity providers do not send CORS headers on their JWKS endpoint, so
                a browser cannot read it. Run this, then paste the result below:
              </p>
              <pre class="code wrap">{curlCommandFor(state.error.url)}</pre>
            </>
          )}
        </div>
      )}

      <div class="field">
        <label for="jwks-json">…or paste the JWKS JSON</label>
        <textarea
          id="jwks-json"
          spellcheck={false}
          placeholder={'{"keys":[{"kty":"RSA","kid":"…","n":"…","e":"AQAB"}]}'}
          onInput={(event) => onPaste(event.currentTarget.value)}
        />
      </div>
    </>
  );
}
