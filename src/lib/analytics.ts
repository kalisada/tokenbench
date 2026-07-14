/**
 * Analytics, built so that leaking a token is not merely unintended but
 * structurally impossible.
 *
 * Two constraints, from two scenarios that pull against each other:
 *
 *   S33 wants to know which lints fire, which algorithms people paste, and how
 *   often a JWKS fetch dies on CORS. All of that is derived from the token.
 *
 *   S30 promises the visitor: open devtools, paste a token, watch nothing be
 *   sent. If a paste fires a beacon, that demo fails in front of the reader and
 *   the entire privacy position — the whole wedge against jwt.io — dies with it.
 *
 * The reconciliation: nothing is ever sent *while the user works*. Events are
 * counted in memory and flushed in a single beacon when the page is closed. So
 * the Network tab stays empty for the entire session, and we still get the data.
 *
 * The defence against leaking content is the vocabulary below: a property is
 * dropped unless its key is declared for that event AND its value appears in a
 * closed, enumerated list. Nothing derived from user input can pass, because
 * nothing that isn't already a known constant can pass. Enforced in one place,
 * again server-side, and tested adversarially.
 */

import { SUPPORTED_ALGS } from "./jwt/algorithms";
import { LINT_IDS } from "./jwt/lint";

export type EventName =
  | "pageview"
  | "tool_used"
  | "verify_result"
  | "lint_shown"
  | "jwks_fetch"
  | "token_generated"
  | "copy";

/**
 * Every value this site can ever send, enumerated.
 *
 * The first version of this used a pattern — short, no dots, no base64 padding —
 * and the test suite promptly walked a 19-character secret and a token fragment
 * straight through it. A pattern describes what a bad value *usually* looks
 * like; an enum describes what a good value *is*. Only the second one can hold.
 *
 * Adding a property means adding its permitted values here. That friction is the
 * feature: it makes "we cannot transmit your token" a fact about the code rather
 * than a claim about our intentions.
 */
const VOCABULARY = {
  tool: ["decoder", "validator", "generator", "secret_generator"],
  result: ["valid", "invalid", "unsecured", "error", "decoded"],
  alg: [...SUPPORTED_ALGS, "none"],
  // Derived, not restated: a new lint is then reportable by construction.
  lint: LINT_IDS,
  outcome: ["ok", "cors_blocked", "failed"],
  tamper: ["true", "false"],
  what: ["token", "secret", "public_key"],
} as const satisfies Record<string, readonly string[]>;

type PropKey = keyof typeof VOCABULARY;

/** The only property keys that may ever be transmitted, per event. */
const ALLOWED_PROPS: Record<EventName, readonly PropKey[]> = {
  pageview: [],
  tool_used: ["tool"],
  verify_result: ["result", "alg"],
  lint_shown: ["lint"],
  jwks_fetch: ["outcome"],
  token_generated: ["alg", "tamper"],
  copy: ["what"],
};

export type Props = Record<string, string | number | boolean>;

/**
 * Strip anything not explicitly permitted. Exported for the test whose whole job
 * is to try to smuggle a token, a secret and a private key past it.
 */
export function sanitize(name: EventName, props: Props = {}): Record<string, string> {
  const allowed = ALLOWED_PROPS[name];
  if (!allowed) return {};

  const out: Record<string, string> = {};
  for (const [key, rawValue] of Object.entries(props)) {
    if (!allowed.includes(key as PropKey)) continue;

    const value = String(rawValue);
    const vocabulary = VOCABULARY[key as PropKey] as readonly string[];
    if (!vocabulary.includes(value)) continue;

    out[key] = value;
  }
  return out;
}

interface QueuedEvent {
  name: EventName;
  props: Record<string, string>;
  count: number;
}

const queue = new Map<string, QueuedEvent>();
let installed = false;

/**
 * Record an event. This never touches the network — it increments a counter in
 * memory. Nothing leaves until the page is closed.
 */
export function track(name: EventName, props: Props = {}): void {
  record(name, props, false);
}

/**
 * Record an event at most once per page view, however many times it is called.
 *
 * This is the right shape for most of what S33 wants. The useful figure for a
 * sponsor is "14% of visitors debug JWKS endpoints" — a proportion of visitors,
 * not a count of keystrokes. Decoding is re-run on every character typed, so a
 * plain counter here would measure typing speed.
 */
export function trackOnce(name: EventName, props: Props = {}): void {
  record(name, props, true);
}

function record(name: EventName, props: Props, once: boolean): void {
  if (typeof window === "undefined") return;

  const clean = sanitize(name, props);
  const key = `${name}:${JSON.stringify(clean)}`;

  const existing = queue.get(key);
  if (existing) {
    if (!once) existing.count += 1;
  } else {
    queue.set(key, { name, props: clean, count: 1 });
  }

  install();
}

function install(): void {
  if (installed) return;
  installed = true;

  // pagehide fires on desktop navigation away; visibilitychange covers mobile
  // task-switching, where pagehide frequently never fires at all.
  //
  // visibilitychange is dispatched *at the document*, not the window. It reaches
  // a window listener only by bubbling, which is fragile and silently drops
  // non-bubbling dispatches — bind it where it is actually fired.
  addEventListener("pagehide", flush);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") flush();
  });
}

function flush(): void {
  if (queue.size === 0) return;

  const events = [...queue.values()];
  queue.clear();

  const body = JSON.stringify({
    url: location.origin + location.pathname, // never location.search or .hash
    referrer: document.referrer || null,
    events,
  });

  // sendBeacon survives the page being torn down. Same-origin: the request goes
  // to tokenbench.dev, which forwards it onward. No third-party host is ever
  // contacted from the browser.
  //
  // A plain string, not a Blob. Both work, but a string body is inspectable —
  // in devtools by a visitor auditing us, and by the test that asserts this
  // payload contains no token. A guarantee nobody can look at is worth less.
  navigator.sendBeacon?.("/api/event", body);
}

/**
 * Queued, not sent. Deferring even the pageview means a visitor's whole session
 * makes zero analytics requests — the Network tab is empty from load to close,
 * not merely empty from paste onward.
 */
export function trackPageview(): void {
  trackOnce("pageview");
}

/** Test seam. */
export function _drain(): QueuedEvent[] {
  const events = [...queue.values()];
  queue.clear();
  return events;
}
