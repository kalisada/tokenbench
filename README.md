# TokenBench

A client-side JWT workbench: decoder, validator, generator and secret-key generator.
Every token, secret and key is processed in the browser via WebCrypto. Nothing is
uploaded, nothing is stored, and the point of publishing this repo is so that you can
check both claims rather than trust them.

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
npm run test:e2e     # 23 browser checks against the built site
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

S33 wants to know which lints fire and how often a JWKS fetch dies on CORS. S30 promises
the visitor that pasting a token sends nothing. Those pull against each other, because
the events S33 wants are triggered by pasting.

The reconciliation: **events are counted in memory and flushed in a single beacon when
the page closes.** A visitor's whole session makes zero analytics requests, so the
devtools demo survives being tested. There is no third-party script — the beacon goes to
`/api/event` on our own origin, and a Cloudflare Pages Function forwards it to Plausible
server-side, so no third-party host ever appears in a Network tab.

What can be transmitted is a **closed vocabulary** (`src/lib/analytics.ts`), enforced
again in the Function. Not a pattern — the first version used one, and the test suite
walked a 19-character secret and a base64url fragment straight through it. Adding a
metric means adding its permitted values by hand; that friction is the point.

Set `PLAUSIBLE_DOMAIN` (and optionally `PLAUSIBLE_HOST`) in the Pages environment.

## Before launch

Live at **tokenbench.dev**.

- [ ] Set `PLAUSIBLE_DOMAIN=tokenbench.dev` in the Cloudflare Pages environment, and add
      the site in Plausible. Without it the Function drops events silently.
- [ ] Re-verify the SERP for "jwt validator" before committing further effort.
      The spec's kill criterion: if 2+ more complete-suite entrants have appeared,
      downgrade to phase 1 only and reassess.

## Licence

MIT.
