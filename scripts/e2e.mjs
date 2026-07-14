/**
 * End-to-end smoke test against the built site in a real browser.
 *
 * The unit suite proves the crypto is right. This proves the *product* is right:
 * that the islands hydrate, that a pasted token produces the display S1 asks
 * for, that an XSS payload in a claim does not execute (S5), and — the claim the
 * whole site rests on — that pasting a token transmits absolutely nothing (S30).
 *
 * Run: node scripts/e2e.mjs   (expects `astro build` to have run first)
 */
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const BASE = "http://localhost:4321";

const HS256_TOKEN =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
const HS256_SECRET = "your-256-bit-secret";

const RSA_PUBLIC = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+hMzTIfXLFLPN9l//GWa
Xf5eWMN8j2VY0FkWmjFDmeWPNxluzXrQxT4lotId958NPsvBF/8rGEey/PQo0YyZ
0BGiaias8VBXgYvuTW6LQWLVweWsu3bnzy2DPjIUS5t8vgIegKHIHldMrcHFq3jT
oe2TIyzKmkEIS5hnNdvsEUsiOkjGuQ5zEfl6yG0/+zIF/pEAB/bpgY7iE3yu8mb5
l3+veeJ2Ciw7LjKAvFzN1LCobDLIJnmp6vxbVBhrID48Owi/TS46q5am0Kkp+wyf
qvNxdjAhad6TafJK/F42r5LjU+LztJXcMG26gJZkh0JsYFCjhP9jIaSHHkF3MAUC
jQIDAQAB
-----END PUBLIC KEY-----`;

const b64url = (obj) =>
  Buffer.from(JSON.stringify(obj)).toString("base64url");

const unsignedToken = (payload, header = { alg: "HS256", typ: "JWT" }) =>
  `${b64url(header)}.${b64url(payload)}.c2ln`;

const results = [];
const check = (name, pass, detail = "") => {
  results.push({ name, pass, detail });
  console.log(`${pass ? "  ✓" : "  ✗"} ${name}${detail && !pass ? ` — ${detail}` : ""}`);
};

async function main() {
  const server = spawn("npx", ["astro", "preview", "--port", "4321"], {
    stdio: "ignore",
    env: process.env,
  });

  // Wait for the preview server to answer.
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(BASE);
      if (res.ok) break;
    } catch {
      /* not up yet */
    }
    await sleep(500);
  }

  // Use the system browser rather than a Playwright-managed download.
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_PATH ?? "/usr/bin/google-chrome",
  });
  const context = await browser.newContext();
  const page = await context.newPage();

  // Any dialog at all means a claim value executed. That is the one bug this
  // site cannot ship with.
  let dialogFired = false;
  page.on("dialog", async (dialog) => {
    dialogFired = true;
    await dialog.dismiss();
  });

  // Record every request the page makes, for the S30 assertion below.
  const requests = [];
  page.on("request", (req) => requests.push({ url: req.url(), body: req.postData() ?? "" }));

  try {
    // --- S1: decode -------------------------------------------------------
    console.log("\nDecoder");
    await page.goto(`${BASE}/jwt-decoder`, { waitUntil: "networkidle" });

    const requestsAfterLoad = requests.length;

    await page.fill("#token", HS256_TOKEN);
    await page.waitForSelector("table.claims", { timeout: 5000 });

    const body = await page.textContent("body");
    check("decodes header alg", body.includes("HS256"));
    check("decodes payload claims", body.includes("John Doe") && body.includes("1234567890"));
    check("renders the claims table", body.includes("Issued at"));

    // --- S30: the whole premise -------------------------------------------
    const newRequests = requests.slice(requestsAfterLoad);
    const crossOrigin = newRequests.filter((r) => !r.url.startsWith(BASE));
    const leaks = requests.filter(
      (r) =>
        r.url.includes(HS256_TOKEN.slice(0, 30)) || r.body.includes(HS256_TOKEN.slice(0, 30)),
    );

    console.log("\nPrivacy (S30)");
    check("no cross-origin request after load", crossOrigin.length === 0,
      crossOrigin.map((r) => r.url).join(", "));
    check("the token appears in zero requests", leaks.length === 0,
      `${leaks.length} request(s) carried it`);

    // --- S2: expired ------------------------------------------------------
    console.log("\nExpiry (S2/S3)");
    const expired = unsignedToken({ sub: "x", exp: Math.floor(Date.now() / 1000) - 3 * 86400 });
    await page.fill("#token", expired);
    await page.waitForFunction(
      () => document.body.textContent.includes("EXPIRED"),
      { timeout: 5000 },
    );
    check("expired token still decodes, banner shown",
      (await page.textContent("body")).includes("EXPIRED 3 days ago"));

    // --- S5: XSS ----------------------------------------------------------
    console.log("\nHostile payload (S5)");
    const xss = unsignedToken({ name: "<script>alert(1)</script>", sub: "x" });
    await page.fill("#token", xss);
    await page.waitForTimeout(400);

    check("script in a claim value does not execute", !dialogFired);

    const renderedLiteral = (await page.textContent("body")).includes("<script>alert(1)</script>");
    check("script in a claim value renders as text", renderedLiteral);

    // The payload must never become markup. Counting <script> tags would just
    // count Astro's own; what matters is that none of them came from the token.
    const injected = await page.evaluate(() =>
      [...document.querySelectorAll("script")].filter((s) =>
        s.textContent.includes("alert(1)"),
      ).length,
    );
    check("the claim value did not become a script element", injected === 0,
      `${injected} script(s) carried the payload`);

    // --- S6: JWE ----------------------------------------------------------
    await page.fill("#token", "a.b.c.d.e");
    await page.waitForTimeout(300);
    check("5-segment token explained as JWE",
      (await page.textContent("body")).includes("encrypted JWT (JWE)"));

    // --- S8/S9/S14: validate ---------------------------------------------
    console.log("\nValidator");
    await page.goto(`${BASE}/jwt-validator`, { waitUntil: "networkidle" });
    await page.fill("#token", HS256_TOKEN);
    await page.fill("#key", HS256_SECRET);
    await page.waitForFunction(
      () => document.body.textContent.includes("Signature VALID"),
      { timeout: 5000 },
    );
    check("correct secret → VALID", true);

    await page.fill("#key", "wrong-secret");
    await page.waitForFunction(
      () => document.body.textContent.includes("Signature INVALID"),
      { timeout: 5000 },
    );
    check("wrong secret → INVALID", true);

    // S14 — the attack this tool refuses to perform.
    await page.fill("#key", RSA_PUBLIC);
    await page.waitForFunction(
      () => document.body.textContent.includes("algorithm-confusion attack"),
      { timeout: 5000 },
    );
    check("HS256 + public key → refused with the algorithm-confusion explainer", true);

    // --- S16/S19: generate ------------------------------------------------
    console.log("\nGenerator");
    await page.goto(`${BASE}/jwt-generator`, { waitUntil: "networkidle" });
    await page.waitForSelector("pre.code", { timeout: 5000 });

    const generated = (await page.textContent("pre.code"))?.trim() ?? "";
    check("a working token is present on load (S16)", generated.split(".").length === 3,
      generated.slice(0, 40));

    // The generated token must actually verify against the shown secret.
    const secret = await page.inputValue("#secret");
    const verified = await page.evaluate(
      async ([token, key]) => {
        const [h, p, s] = token.split(".");
        const cryptoKey = await crypto.subtle.importKey(
          "raw",
          new TextEncoder().encode(key),
          { name: "HMAC", hash: "SHA-256" },
          false,
          ["verify"],
        );
        const sig = Uint8Array.from(
          atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(s.length + ((4 - (s.length % 4)) % 4), "=")),
          (c) => c.charCodeAt(0),
        );
        return crypto.subtle.verify("HMAC", cryptoKey, sig, new TextEncoder().encode(`${h}.${p}`));
      },
      [generated, secret],
    );
    check("the generated token verifies against its own secret", verified === true);

    // S19 — tampered token.
    await page.check('input[type="checkbox"]');
    await page.waitForTimeout(400);
    const tampered = (await page.textContent("pre.code"))?.trim() ?? "";
    check("tamper toggle changes the signature", tampered !== generated);
    check("tampered token still has 3 segments (it must parse, then fail)",
      tampered.split(".").length === 3);

    // --- S20: secrets -----------------------------------------------------
    console.log("\nSecret generator");
    await page.goto(`${BASE}/jwt-secret-key-generator`, { waitUntil: "networkidle" });
    await page.waitForSelector("#secret", { timeout: 5000 });

    const first = (await page.textContent("#secret"))?.trim() ?? "";
    check("a 256-bit base64 secret is generated on load", first.length >= 40, first);

    await page.click("button:has-text('Regenerate')");
    await page.waitForTimeout(200);
    const second = (await page.textContent("#secret"))?.trim() ?? "";
    check("regenerate produces a different secret", first !== second);

    await page.click("button:has-text('hex')");
    await page.waitForTimeout(200);
    const hex = (await page.textContent("#secret"))?.trim() ?? "";
    check("hex format is 64 chars for 256 bits", /^[0-9a-f]{64}$/.test(hex), hex);

    // --- S31: no persistence ---------------------------------------------
    console.log("\nPersistence (S31)");
    await page.goto(`${BASE}/jwt-decoder`, { waitUntil: "networkidle" });
    await page.fill("#token", HS256_TOKEN);
    await page.waitForTimeout(300);

    const stored = await page.evaluate(() => ({
      local: JSON.stringify(localStorage),
      session: JSON.stringify(sessionStorage),
      cookies: document.cookie,
    }));
    check("nothing written to localStorage", stored.local === "{}", stored.local);
    check("nothing written to sessionStorage", stored.session === "{}", stored.session);
    check("no cookies set", stored.cookies === "", stored.cookies);
  } finally {
    await browser.close();
    server.kill();
  }

  const failed = results.filter((r) => !r.pass);
  console.log(
    `\n${results.length - failed.length}/${results.length} checks passed`,
  );
  if (failed.length > 0) {
    console.log("\nFAILED:");
    for (const f of failed) console.log(`  ✗ ${f.name} — ${f.detail}`);
    process.exit(1);
  }
}

await main();
