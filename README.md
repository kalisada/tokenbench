# TokenBench

A client-side JWT workbench: decoder, validator, generator and secret-key generator.
Every token, secret and key is processed in the browser via WebCrypto. Nothing is
uploaded, nothing is stored, and the point of publishing this repo is so that you can
check both claims rather than trust them.

Live at **[tokenbench.dev](https://tokenbench.dev)**:

- [JWT Decoder](https://tokenbench.dev/jwt-decoder) — read header, payload and claims, including expired tokens
- [JWT Validator](https://tokenbench.dev/jwt-validator) — verify a signature against a secret, PEM, JWK or JWKS; signature and expiry judged separately
- [JWT Generator](https://tokenbench.dev/jwt-generator) — mint test tokens for any algorithm, including deliberately invalid ones
- [JWT Secret Key Generator](https://tokenbench.dev/jwt-secret-key-generator) — cryptographically random HMAC secrets at 256/384/512 bits

Built to the spec in `docs/confidential/jwt-workbench-build-spec.md` (not in this repo).

## Running it

Requires Node 20+ (`.nvmrc` pins 22).

```sh
npm install
npm run dev          # http://localhost:4321
npm run build        # → dist/
```

## Tests

The build spec's scenarios (S1–S35) are the requirements, so they are also the tests —
each test is named for the scenario it covers.

```sh
npm test             # 78 unit tests: crypto, key parsing, decoding, lints
npm run test:e2e     # 28 browser checks against the built site
```

The mobile performance gate (S32 requires ≥95) is run on demand. Lighthouse is
deliberately **not** a dependency — it pulls in a Sentry/OpenTelemetry chain that
accounted for every `npm audit` finding in this repo. None could reach a visitor, but on
a site whose pitch is "audit us", a noisy audit is a real cost. `npm audit` reports zero
vulnerabilities, and it should stay that way.

```sh
npm run build
npm i --no-save lighthouse && node scripts/lighthouse.mjs
```

The unit suite covers the parts most likely to be quietly wrong: base64url tolerance,
PEM/DER/JWK parsing (including the PKCS#1, SEC1 and X.509 forms WebCrypto refuses to
import), and a sign/verify round-trip for all thirteen algorithms.

The e2e suite exists to check the claims the unit tests can't: that a `<script>` in a
claim value renders as text rather than executing, that pasting a token produces **zero**
network requests, and that nothing lands in localStorage, sessionStorage or a cookie.
It drives the system Chrome; override with `CHROME_PATH` if yours lives elsewhere.

## Architecture

- **`src/lib/jwt/`** — the whole crypto core, dependency-free. WebCrypto only; no JS
  crypto libraries. `der.ts` and `keys.ts` are the fiddly part and carry the most tests.
- **`src/components/`** — Preact islands, hydrated per page. `JsonView.tsx` renders JSON
  from JSX nodes and must never use `innerHTML` — XSS in a security tool is fatal.
- **`src/pages/`** — one Astro page per keyword, each with its own long-form content,
  FAQ schema and internal links.
- **`public/_headers`** — the CSP. `connect-src` is the only permissive directive, and
  only because of the user-initiated JWKS fetch.
- **`public/sw.js`** — offline support. Only ever touches same-origin GETs; the
  cross-origin JWKS fetch goes straight to the network, uncached.

## Analytics

There are none. An earlier design counted anonymous events (which lints fired, JWKS
CORS failure rates) in memory and flushed them in one first-party beacon on page close —
carefully allowlisted so no token content could pass. It was removed before launch
anyway: the site's headline claim is "paste a token, nothing is sent," and a claim that
needs a footnote is weaker than one that doesn't. Traffic comes from the host's
server-side request counts; nothing runs in the visitor's browser.

## Before launch

Live at **tokenbench.dev**.

- [ ] Re-verify the SERP for "jwt validator" before committing further effort.
      The spec's kill criterion: if 2+ more complete-suite entrants have appeared,
      downgrade to phase 1 only and reassess.

## Licence

MIT.
