import { useCallback, useEffect, useState } from "preact/hooks";
import type { JSX } from "preact";
import { trackOnce } from "@lib/analytics";
import {
  SECRET_BITS,
  SECRET_FORMATS,
  formatSecret,
  randomBytes,
  type SecretBits,
  type SecretFormat,
} from "@lib/jwt/secret";
import { CopyButton } from "./ui";

export default function SecretGenerator(): JSX.Element {
  const [bits, setBits] = useState<SecretBits>(256);
  const [format, setFormat] = useState<SecretFormat>("base64");
  const [bytes, setBytes] = useState<Uint8Array>(() => new Uint8Array());

  const regenerate = useCallback((length: SecretBits) => {
    setBytes(randomBytes(length));
    trackOnce("tool_used", { tool: "secret_generator" });
  }, []);

  // Generated after mount: crypto.getRandomValues is a browser API, and the page
  // itself is prerendered to static HTML.
  useEffect(() => regenerate(bits), [bits, regenerate]);

  const secret = bytes.length > 0 ? formatSecret(bytes, format) : "";

  return (
    <div class="panel">
      <div class="btn-row" style="margin-bottom:14px">
        <div class="segmented">
          {SECRET_BITS.map((option) => (
            <button
              key={option}
              type="button"
              aria-pressed={bits === option}
              onClick={() => setBits(option)}
            >
              {option}-bit
            </button>
          ))}
        </div>

        <div class="segmented" style="margin-left:auto">
          {SECRET_FORMATS.map((option) => (
            <button
              key={option}
              type="button"
              aria-pressed={format === option}
              onClick={() => setFormat(option)}
            >
              {option}
            </button>
          ))}
        </div>
      </div>

      <label for="secret">
        {bits}-bit secret, {format}
      </label>
      <pre id="secret" class="code wrap" style="font-size:0.95rem;padding:16px">
        {secret}
      </pre>

      <div class="btn-row" style="margin-top:12px">
        <span>
          <CopyButton value={secret} label="Copy secret" what="secret" />
        </span>
        <button type="button" class="primary" onClick={() => regenerate(bits)}>
          Regenerate
        </button>
        <span class="hint" style="margin:0 0 0 auto">
          From <code>crypto.getRandomValues()</code>. Generated on your machine; never sent
          anywhere.
        </span>
      </div>
    </div>
  );
}
