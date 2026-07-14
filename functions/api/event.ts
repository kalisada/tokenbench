/**
 * Cloudflare Pages Function: the analytics proxy.
 *
 * The browser posts here — to tokenbench.dev, its own origin — and this forwards
 * to Plausible server-side. The point is that no third-party host ever appears
 * in a visitor's Network tab, and no third-party script ever runs on the page.
 *
 * This is also the last line of defence on content: the allowlist in
 * src/lib/analytics.ts runs client-side, and a client-side check is a check an
 * attacker (or a future refactor) can skip. So it is enforced again, here, on
 * data we control. Anything unrecognised is dropped, not forwarded.
 */

interface Env {
  /** e.g. "tokenbench.dev" — the site as registered in Plausible. */
  PLAUSIBLE_DOMAIN: string;
  /** Defaults to Plausible Cloud; set for a self-hosted instance. */
  PLAUSIBLE_HOST?: string;
}

/**
 * Deliberately duplicated from src/lib/analytics.ts rather than imported: this
 * runs on our infrastructure and must hold even if the client bundle is modified
 * or bypassed entirely. A closed vocabulary, not a pattern — a pattern lets a
 * short secret or a token fragment through, which is exactly what the client-side
 * test caught.
 */
const VOCABULARY: Record<string, readonly string[]> = {
  tool: ["decoder", "validator", "generator", "secret_generator"],
  result: ["valid", "invalid", "unsecured", "error", "decoded"],
  alg: [
    "HS256", "HS384", "HS512",
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512",
    "EdDSA", "none",
  ],
  lint: [
    "alg-none", "alg-unknown", "weak-secret", "short-secret",
    "no-exp", "long-lived", "no-timestamps", "kid",
  ],
  outcome: ["ok", "cors_blocked", "failed"],
  tamper: ["true", "false"],
  what: ["token", "secret", "public_key"],
};

const ALLOWED_PROPS: Record<string, readonly string[]> = {
  pageview: [],
  tool_used: ["tool"],
  verify_result: ["result", "alg"],
  lint_shown: ["lint"],
  jwks_fetch: ["outcome"],
  token_generated: ["alg", "tamper"],
  copy: ["what"],
};

interface IncomingEvent {
  name?: unknown;
  props?: unknown;
  count?: unknown;
}

function clean(event: IncomingEvent): { name: string; props: Record<string, string> } | null {
  const name = typeof event.name === "string" ? event.name : "";
  const allowed = ALLOWED_PROPS[name];
  if (!allowed) return null;

  const props: Record<string, string> = {};
  const incoming = (event.props ?? {}) as Record<string, unknown>;

  for (const key of allowed) {
    const value = incoming[key];
    if (typeof value !== "string") continue;
    if (!VOCABULARY[key]?.includes(value)) continue;
    props[key] = value;
  }

  return { name, props };
}

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  let payload: { url?: unknown; referrer?: unknown; events?: unknown };
  try {
    payload = await request.json();
  } catch {
    return new Response(null, { status: 400 });
  }

  const events = Array.isArray(payload.events) ? payload.events.slice(0, 50) : [];
  if (events.length === 0) return new Response(null, { status: 204 });

  // Only ever trust our own origin for the URL. A client-supplied URL could
  // otherwise carry a query string, and a query string could carry anything.
  const origin = new URL(request.url).origin;
  const path =
    typeof payload.url === "string" && payload.url.startsWith(origin)
      ? new URL(payload.url).pathname
      : "/";
  const url = origin + path;

  const referrer = typeof payload.referrer === "string" ? payload.referrer : null;
  const host = env.PLAUSIBLE_HOST ?? "https://plausible.io";

  // Plausible attributes country and device from these; they must be forwarded
  // or every visit looks like it came from a Cloudflare datacentre.
  const headers = {
    "content-type": "application/json",
    "user-agent": request.headers.get("user-agent") ?? "",
    "x-forwarded-for": request.headers.get("cf-connecting-ip") ?? "",
  };

  const sends: Promise<unknown>[] = [];

  for (const raw of events as IncomingEvent[]) {
    const event = clean(raw);
    if (!event) continue;

    // Counts are collapsed client-side; replay them so Plausible sees each one.
    const count = Math.min(
      Math.max(Number.parseInt(String(raw.count ?? 1), 10) || 1, 1),
      20,
    );

    for (let i = 0; i < count; i++) {
      sends.push(
        fetch(`${host}/api/event`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            name: event.name,
            domain: env.PLAUSIBLE_DOMAIN,
            url,
            referrer,
            props: event.props,
          }),
        }),
      );
    }
  }

  await Promise.allSettled(sends);

  // The beacon's response is never read by the browser. Say nothing.
  return new Response(null, { status: 204 });
};
