/**
 * Mobile Lighthouse run against the built site. S32 sets the bar at >= 95
 * performance, and treats speed as a feature rather than a nice-to-have: the
 * visitor is mid-debugging and will leave.
 *
 * Run: node scripts/lighthouse.mjs   (expects `astro build` first)
 */
import lighthouse from "lighthouse";
import { launch } from "chrome-launcher";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const BASE = "http://localhost:4321";
const PAGES = [
  "/",
  "/jwt-decoder",
  "/jwt-validator",
  "/jwt-generator",
  "/jwt-secret-key-generator",
];

const THRESHOLDS = { performance: 95, accessibility: 95, "best-practices": 95, seo: 95 };

const server = spawn("npx", ["astro", "preview", "--port", "4321"], { stdio: "ignore" });
for (let i = 0; i < 60; i++) {
  try {
    if ((await fetch(BASE)).ok) break;
  } catch {
    /* not up yet */
  }
  await sleep(500);
}

const chrome = await launch({
  chromePath: process.env.CHROME_PATH ?? "/usr/bin/google-chrome",
  chromeFlags: ["--headless=new", "--no-sandbox"],
});

const failures = [];

try {
  for (const path of PAGES) {
    const { lhr } = await lighthouse(
      `${BASE}${path}`,
      { port: chrome.port, output: "json", logLevel: "error" },
      // Default config is mobile: slow 4G, 4x CPU throttle.
    );

    const scores = Object.fromEntries(
      Object.entries(lhr.categories).map(([id, cat]) => [id, Math.round(cat.score * 100)]),
    );

    const row = Object.entries(THRESHOLDS)
      .map(([id, min]) => `${id} ${scores[id]}${scores[id] < min ? " ✗" : ""}`)
      .join("  ·  ");
    console.log(`${path.padEnd(28)} ${row}`);

    for (const [id, min] of Object.entries(THRESHOLDS)) {
      if (scores[id] < min) failures.push(`${path}: ${id} ${scores[id]} < ${min}`);
    }

    const lcp = lhr.audits["largest-contentful-paint"].displayValue;
    const cls = lhr.audits["cumulative-layout-shift"].displayValue;
    const tbt = lhr.audits["total-blocking-time"].displayValue;
    console.log(`${" ".repeat(28)} LCP ${lcp}  ·  CLS ${cls}  ·  TBT ${tbt}\n`);

    // Surface whatever is actually costing points, so the number is actionable.
    const opportunities = lhr.categories.performance.auditRefs
      .map((ref) => lhr.audits[ref.id])
      .filter((a) => a && a.score !== null && a.score < 0.9 && a.details?.overallSavingsMs > 50);
    for (const o of opportunities) {
      console.log(`${" ".repeat(28)} → ${o.title}: ${o.displayValue ?? ""}`);
    }
  }
} finally {
  await chrome.kill();
  server.kill();
}

if (failures.length > 0) {
  console.log("\nBelow threshold:");
  for (const f of failures) console.log(`  ✗ ${f}`);
  process.exit(1);
}
console.log("All pages meet the S32 bar (>= 95 on mobile).");
