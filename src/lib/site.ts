/** Single source of truth for site-wide strings and the internal link graph. */

export const SITE = {
  name: "TokenBench",
  owner: "Kalisada LLC",
  domain: "tokenbench.dev",
} as const;

/** S30b: the privacy claim is only credible if the code is readable. */
export const REPO_URL = "https://github.com/kalisada/tokenbench";

export interface Tool {
  path: string;
  nav: string;
  title: string;
  blurb: string;
}

/** S34 requires every tool page to link to every other one. */
export const TOOLS: Tool[] = [
  {
    path: "/jwt-decoder",
    nav: "Decoder",
    title: "JWT Decoder",
    blurb:
      "Read a token's header, payload and claims — including expired ones. Nothing is uploaded.",
  },
  {
    path: "/jwt-validator",
    nav: "Validator",
    title: "JWT Validator",
    blurb:
      "Verify a signature against a secret, PEM, JWK or JWKS. Signature and expiry are judged separately.",
  },
  {
    path: "/jwt-generator",
    nav: "Generator",
    title: "JWT Generator",
    blurb:
      "Mint a test token for any algorithm — including deliberately invalid ones, to test your rejection path.",
  },
  {
    path: "/jwt-secret-key-generator",
    nav: "Secret Key",
    title: "JWT Secret Key Generator",
    blurb:
      "Generate a cryptographically random HMAC secret at 256, 384 or 512 bits.",
  },
];

export function otherTools(currentPath: string): Tool[] {
  return TOOLS.filter((tool) => tool.path !== currentPath);
}
