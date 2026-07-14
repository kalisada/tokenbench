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

## Before launch

- [ ] Buy the domain, then set `site` in `astro.config.mjs` and the `Sitemap:` line in
      `public/robots.txt`. Both currently point at `tokenbench.example`.
- [ ] Set `REPO_URL` in `src/lib/site.ts` to the real repository.
- [ ] Wire up privacy-preserving analytics (counters only — the privacy page already
      documents exactly what may and may not be recorded; keep it honest).
- [ ] Re-verify the SERP for "jwt validator" before committing further effort.
      The spec's kill criterion: if 2+ more complete-suite entrants have appeared,
      downgrade to phase 1 only and reassess.

## Licence

MIT.
