import { useEffect, useMemo, useState } from "preact/hooks";
import type { JSX } from "preact";
import { trackOnce } from "@lib/analytics";
import { SUPPORTED_ALGS, getAlgorithm } from "@lib/jwt/algorithms";
import { generateKeyPair, type SecretEncoding } from "@lib/jwt/keys";
import { defaultPayload, parseRelativeExpiry, signJwt } from "@lib/jwt/sign";
import { generateSecret } from "@lib/jwt/secret";
import type { JwtPayload } from "@lib/jwt/types";
import { CopyButton, StatusBar, TokenSegments } from "./ui";

const pretty = (value: unknown): string => JSON.stringify(value, null, 2);

export default function Generator(): JSX.Element {
  const [alg, setAlg] = useState("HS256");
  // Hex, not base64: the encoding toggle starts on utf-8, and a base64-looking
  // secret read as utf-8 text is exactly the confusion S10 exists to warn about.
  // Don't ship the trap as the default state.
  const [secret, setSecret] = useState(() => generateSecret(256, "hex"));
  const [encoding, setEncoding] = useState<SecretEncoding>("utf-8");
  const [privateKey, setPrivateKey] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [headerText, setHeaderText] = useState("{}");
  const [payloadText, setPayloadText] = useState(() => pretty(defaultPayload()));
  const [tamper, setTamper] = useState(false);
  const [allowNone, setAllowNone] = useState(false);

  const [token, setToken] = useState("");
  const [error, setError] = useState<string | undefined>();
  const [keygenBusy, setKeygenBusy] = useState(false);

  const spec = getAlgorithm(alg);
  const isHmac = alg !== "none" && spec?.family === "HMAC";
  const isNone = alg === "none";

  // S17: bad JSON must not destroy the last good token — it greys out instead.
  const parsed = useMemo(() => {
    try {
      const header = JSON.parse(headerText || "{}") as Record<string, unknown>;
      const payload = JSON.parse(payloadText || "{}") as JwtPayload;
      if (typeof header !== "object" || header === null || Array.isArray(header)) {
        return { error: "The header must be a JSON object." } as const;
      }
      if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
        return { error: "The payload must be a JSON object." } as const;
      }
      return { header, payload } as const;
    } catch (e) {
      return { error: `Invalid JSON — ${(e as Error).message}` } as const;
    }
  }, [headerText, payloadText]);

  const key = isHmac ? secret : privateKey;

  useEffect(() => {
    if ("error" in parsed) {
      setError(parsed.error);
      return;
    }
    if (!isNone && key.trim() === "") {
      setError(undefined);
      setToken("");
      return;
    }

    let current = true;

    void signJwt({
      alg,
      header: parsed.header,
      payload: parsed.payload,
      key,
      secretEncoding: encoding,
      tamper,
    })
      .then((next) => {
        if (!current) return;
        setToken(next);
        setError(undefined);
        // S33: which algorithms people actually reach for, and how many are
        // testing their rejection path. The token itself is never touched.
        trackOnce("tool_used", { tool: "generator" });
        trackOnce("token_generated", { alg, tamper });
      })
      .catch((e: unknown) => {
        if (!current) return;
        setError((e as Error).message);
      });

    return () => {
      current = false;
    };
  }, [alg, parsed, key, encoding, tamper, isNone]);

  const generatePair = async (): Promise<void> => {
    setKeygenBusy(true);
    try {
      const pair = await generateKeyPair(alg);
      setPrivateKey(pair.privateKeyPem);
      setPublicKey(pair.publicKeyPem);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setKeygenBusy(false);
    }
  };

  /** S17: claim helpers insert with the right *type*, which is the usual bug. */
  const addClaim = (claim: string): void => {
    if ("error" in parsed) return;
    const now = Math.floor(Date.now() / 1000);
    const values: Record<string, unknown> = {
      iss: "https://issuer.example.com",
      aud: "https://api.example.com",
      nbf: now,
      jti: crypto.randomUUID(),
      iat: now,
    };
    setPayloadText(pretty({ ...parsed.payload, [claim]: values[claim] }));
  };

  const setExpiry = (relative: string): void => {
    if ("error" in parsed) return;
    try {
      setPayloadText(pretty({ ...parsed.payload, exp: parseRelativeExpiry(relative) }));
    } catch (e) {
      setError((e as Error).message);
    }
  };

  return (
    <div>
      <div class="grid-2">
        <div>
          <div class="panel">
            <div class="field">
              <label for="alg">Algorithm</label>
              <select
                id="alg"
                value={alg}
                onChange={(event) => {
                  const next = event.currentTarget.value;
                  setAlg(next);
                  setTamper(false);
                }}
              >
                {SUPPORTED_ALGS.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
                {allowNone && <option value="none">none (unsecured)</option>}
              </select>
            </div>

            {isHmac && (
              <div class="field">
                <div class="btn-row" style="margin-bottom:6px">
                  <label for="secret" style="margin:0">Secret</label>
                  <div class="segmented" style="margin-left:auto">
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
                </div>
                <input
                  id="secret"
                  type="text"
                  spellcheck={false}
                  value={secret}
                  onInput={(event) => setSecret(event.currentTarget.value)}
                />
                <div class="btn-row" style="margin-top:8px">
                  <button
                    type="button"
                    onClick={() =>
                      setSecret(
                        generateSecret(
                          (spec?.minSecretBits ?? 256) as 256 | 384 | 512,
                          encoding === "base64" ? "base64" : "hex",
                        ),
                      )
                    }
                  >
                    New random secret
                  </button>
                </div>
              </div>
            )}

            {!isHmac && !isNone && (
              <div class="field">
                <label for="private-key">Private key (PEM)</label>
                <textarea
                  id="private-key"
                  spellcheck={false}
                  placeholder="-----BEGIN PRIVATE KEY-----"
                  value={privateKey}
                  onInput={(event) => setPrivateKey(event.currentTarget.value)}
                />
                <div class="btn-row" style="margin-top:8px">
                  <button type="button" onClick={() => void generatePair()} disabled={keygenBusy}>
                    {keygenBusy ? "Generating…" : "Generate key pair"}
                  </button>
                </div>
                {publicKey && (
                  <>
                    <p class="warn-note">
                      Generated locally in your browser. For testing only — don't use
                      browser-generated keys in production.
                    </p>
                    <div class="field">
                      <div class="btn-row" style="margin-bottom:6px">
                        <label style="margin:0">Public key (give this to the verifier)</label>
                        <span style="margin-left:auto">
                          <CopyButton value={publicKey} what="public_key" />
                        </span>
                      </div>
                      <pre class="code wrap">{publicKey}</pre>
                    </div>
                  </>
                )}
              </div>
            )}
          </div>

          <div class="panel">
            <label class="panel__title" for="payload">Payload</label>
            <textarea
              id="payload"
              class="token-input"
              spellcheck={false}
              value={payloadText}
              onInput={(event) => setPayloadText(event.currentTarget.value)}
            />
            <div class="btn-row" style="margin-top:8px">
              {(["iss", "aud", "nbf", "jti", "iat"] as const).map((claim) => (
                <button key={claim} type="button" onClick={() => addClaim(claim)}>
                  + {claim}
                </button>
              ))}
            </div>
            <div class="btn-row" style="margin-top:8px">
              <span class="hint" style="margin:0">Expires:</span>
              {["5m", "1h", "24h", "7d"].map((relative) => (
                <button key={relative} type="button" onClick={() => setExpiry(relative)}>
                  +{relative}
                </button>
              ))}
            </div>
          </div>

          <div class="panel">
            <label class="panel__title" for="header">Header extras</label>
            <textarea
              id="header"
              spellcheck={false}
              style="min-height:80px"
              value={headerText}
              onInput={(event) => setHeaderText(event.currentTarget.value)}
            />
            <p class="hint">
              <code>alg</code> and <code>typ</code> are set for you. Add <code>kid</code> or
              other members here.
            </p>
          </div>
        </div>

        <div>
          <div class="panel">
            <div class="btn-row" style="margin-bottom:10px">
              <p class="panel__title" style="margin:0">Token</p>
              <span style="margin-left:auto">
                <CopyButton value={token} label="Copy token" what="token" />
              </span>
            </div>

            {error && <StatusBar tone="amber" label="Not regenerating" note={error} />}

            <div style={error ? "opacity:.45;margin-top:10px" : "margin-top:0"}>
              {token ? (
                <TokenSegments token={token} />
              ) : (
                <p class="hint">Supply a {isHmac ? "secret" : "private key"} to mint a token.</p>
              )}
            </div>

            {error && token && (
              <p class="hint">Showing the last token that generated cleanly.</p>
            )}
          </div>

          {/* S19: both of these are real testing needs. They are gated behind an
              explanation rather than removed — a dev who cannot make a bad token
              here will make one somewhere with less warning attached. */}
          <div class="panel">
            <p class="panel__title">Testing your rejection path</p>

            <label class="btn-row" style="font-weight:400">
              <input
                type="checkbox"
                checked={tamper}
                disabled={isNone}
                onChange={(event) => setTamper(event.currentTarget.checked)}
                style="width:auto"
              />
              <span>
                Emit a <b>tampered</b> token — signature deliberately corrupted
              </span>
            </label>
            <p class="hint">
              The token still parses, but every correct verifier must reject it. Use it to
              prove your server actually checks the signature.
            </p>

            <details style="margin-top:12px">
              <summary style="cursor:pointer;font-weight:600">
                Generate an <code>alg:none</code> token
              </summary>
              <p class="hint" style="margin-top:8px">
                An <code>alg:none</code> token carries no signature at all. Historically,
                libraries that trusted the header's <code>alg</code> would accept these as
                valid — the attacker rewrites the payload, sets{" "}
                <code>&quot;alg&quot;:&quot;none&quot;</code>, and drops the signature.
                Your server should reject it outright. Generate one here to prove that it does.
              </p>
              <div class="btn-row" style="margin-top:8px">
                <button
                  type="button"
                  onClick={() => {
                    setAllowNone(true);
                    setAlg("none");
                    setTamper(false);
                  }}
                >
                  Enable alg:none
                </button>
                {isNone && (
                  <button type="button" onClick={() => setAlg("HS256")}>
                    Back to HS256
                  </button>
                )}
              </div>
              {isNone && (
                <div style="margin-top:10px">
                  <StatusBar
                    tone="red"
                    label="UNSECURED"
                    note="This token has no signature. Anyone can alter its claims."
                  />
                </div>
              )}
            </details>
          </div>
        </div>
      </div>
    </div>
  );
}
