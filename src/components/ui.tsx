import { useCallback, useState } from "preact/hooks";
import type { JSX } from "preact";
import { JsonView } from "./JsonView";
import type { Lint } from "@lib/jwt/lint";
import { describeTimestamp } from "@lib/jwt/decode";
import type { DecodedJwt, JwtPayload, TimeVerdict } from "@lib/jwt/types";

export function CopyButton({
  value,
  label = "Copy",
  what,
}: {
  value: string;
  label?: string;
  what?: string;
}): JSX.Element {
  const [copied, setCopied] = useState(false);

  const copy = useCallback(() => {
    void navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    });
  }, [value, what]);

  return (
    <button type="button" onClick={copy} disabled={value === ""}>
      {copied ? "Copied ✓" : label}
    </button>
  );
}

/** The three-segment colouring devs already recognise from jwt.io. */
export function TokenSegments({ token }: { token: string }): JSX.Element {
  const [header = "", payload = "", signature = ""] = token.split(".");
  return (
    <pre class="code wrap">
      <span class="seg-header">{header}</span>
      <span class="seg-dot">.</span>
      <span class="seg-payload">{payload}</span>
      <span class="seg-dot">.</span>
      <span class="seg-signature">{signature}</span>
    </pre>
  );
}

export function StatusBar({
  tone,
  label,
  note,
}: {
  tone: "valid" | "invalid" | "amber" | "info" | "red";
  label: string;
  note?: string;
}): JSX.Element {
  return (
    <div class={`status status--${tone}`} role="status">
      <strong>{label}</strong>
      {note && <span class="status__note">{note}</span>}
    </div>
  );
}

export function TimeStatus({ verdict }: { verdict: TimeVerdict }): JSX.Element {
  const tone =
    verdict.status === "expired"
      ? "invalid"
      : verdict.status === "not-yet-valid"
        ? "amber"
        : "valid";

  // S3: a token that is merely early is usually a clock-skew problem, not a bug.
  const note =
    verdict.status === "not-yet-valid"
      ? "If this is unexpected, check for clock skew between the issuer and this machine."
      : undefined;

  return <StatusBar tone={tone} label={verdict.summary} note={note} />;
}

export function LintPanel({ lints }: { lints: Lint[] }): JSX.Element | null {
  if (lints.length === 0) {
    return (
      <div class="panel">
        <p class="panel__title">Security lint</p>
        <StatusBar tone="valid" label="No issues found" note="Nothing this tool checks for is wrong with this token." />
      </div>
    );
  }

  return (
    <div class="panel">
      <p class="panel__title">Security lint · {lints.length}</p>
      {lints.map((lint) => (
        <div key={lint.id} class={`lint lint--${lint.level}`}>
          <div>
            <div class="lint__title">{lint.title}</div>
            <div class="lint__detail">{lint.detail}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

/** Human-readable meanings for the registered claims (S1). */
const CLAIM_MEANINGS: Record<string, string> = {
  iss: "Issuer — who minted this token",
  sub: "Subject — who the token is about",
  aud: "Audience — who is meant to accept it",
  exp: "Expires",
  nbf: "Not valid before",
  iat: "Issued at",
  jti: "Token ID — for replay/revocation tracking",
};

const TIME_CLAIMS = new Set(["exp", "nbf", "iat"]);

export function ClaimsTable({ payload }: { payload: JwtPayload }): JSX.Element {
  const entries = Object.entries(payload);

  if (entries.length === 0) {
    return <p class="hint">This token has no claims.</p>;
  }

  return (
    <table class="claims">
      <thead class="sr-only">
        <tr>
          <th>Claim</th>
          <th>Meaning</th>
          <th>Value</th>
        </tr>
      </thead>
      <tbody>
        {entries.map(([claim, value]) => (
          <tr key={claim}>
            <th scope="row">{claim}</th>
            <td class="meaning">{CLAIM_MEANINGS[claim] ?? ""}</td>
            <td class="value">
              {TIME_CLAIMS.has(claim) && typeof value === "number"
                ? describeTimestamp(value)
                : typeof value === "string"
                  ? value
                  : JSON.stringify(value)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** Header / payload / signature, the three panes of S1. */
export function DecodedPanes({ decoded }: { decoded: DecodedJwt }): JSX.Element {
  return (
    <div class="grid-3">
      <div class="panel">
        <p class="panel__title" style="color:var(--red)">Header</p>
        <JsonView value={decoded.header} />
      </div>
      <div class="panel">
        <p class="panel__title" style="color:var(--info)">Payload</p>
        <JsonView value={decoded.payload} />
      </div>
      <div class="panel">
        <p class="panel__title" style="color:var(--green)">Signature</p>
        <pre class="code wrap">{decoded.signature || "(none)"}</pre>
        {decoded.unsecured && (
          <p class="warn-note">
            This token carries no signature. Its contents can be rewritten by anyone.
          </p>
        )}
      </div>
    </div>
  );
}
