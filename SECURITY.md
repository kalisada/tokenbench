# Security Policy

TokenBench is a client-side JWT toolkit whose entire premise is that your
tokens, secrets, and keys never leave your browser. A vulnerability here isn't
an inconvenience — it's a broken promise. We take reports seriously and want to
make them easy.

## Reporting a vulnerability

**Please report privately, not in a public issue.** A public issue on a security
tool is a disclosure before there's a fix.

Use GitHub's private vulnerability reporting:

**https://github.com/kalisada/tokenbench/security/advisories/new**

(If that link 404s, private reporting hasn't been enabled yet — open a regular
issue asking us to enable it, without vulnerability details, and we'll respond.)

What helps:

- What you found, and the security impact.
- Steps to reproduce — a token, a payload, or a sequence of actions.
- The page, browser, and version.

You'll get an acknowledgement within a few days. We'll confirm the issue, agree
a timeline, fix it, and credit you if you'd like.

## What we're most interested in

Because of what this tool claims, these matter most:

- **Anything that sends a token, secret, key, or claim off the machine** — a
  network request carrying user input, a leak into analytics, a write to
  storage. The privacy guarantee is the product.
- **XSS** — a token or claim value that executes rather than rendering as text.
- **Crypto and key-parsing flaws** — a signature reported valid when it isn't,
  or the reverse; a mishandled PEM/DER/JWK; algorithm-confusion the tool should
  catch but doesn't.
- **CSP or header weaknesses** that widen any of the above.

## Scope

- **In scope:** the live site (tokenbench.dev) and the code in this repository.
- **Out of scope:** findings that require a already-compromised browser or
  malicious extension; social engineering; volumetric/DoS testing against the
  host; reports from automated scanners with no demonstrated impact.

## Safe harbor

We won't pursue or support legal action against good-faith research that follows
this policy: stay within scope, don't access or modify other people's data,
don't degrade the service for others, and give us reasonable time to fix an
issue before disclosing it publicly.
