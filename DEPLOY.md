# Deploy checklist

Plain steps to get tokenbench.dev live. Do them in order. Stop at the end of Part 1
if you want — the site is live and working at that point. Parts 2 and 3 are optional
extras you can do any time later.

---

## Part 1 — Put the site on the internet

### 1. Get the code onto GitHub

The code is currently only on this laptop. It needs to be on GitHub before Cloudflare
can see it.

Ask Claude to push it, or run:

```sh
git push -u origin main
```

Check it worked: open https://github.com/kalisada/tokenbench and you should see the
files.

### 2. Make a Cloudflare account

Go to https://dash.cloudflare.com and sign up (free).

### 3. Point the domain at Cloudflare

You bought tokenbench.dev somewhere (Namecheap, Porkbun, wherever). Cloudflare needs
to be in charge of it.

- In Cloudflare, click **Add a domain**, type `tokenbench.dev`, choose the **Free** plan.
- Cloudflare shows you two "nameservers" — long addresses like `xyz.ns.cloudflare.com`.
- Go to wherever you bought the domain, find the nameserver setting, and replace what's
  there with Cloudflare's two.
- Wait. This takes anywhere from 15 minutes to a few hours. Cloudflare emails you when
  it's done.

### 4. Create the site in Cloudflare

- In Cloudflare, go to **Compute (Workers & Pages)** in the left sidebar.
- Click **Create** → choose the **Pages** tab → **Connect to Git**.
- Authorise GitHub, then pick the `tokenbench` repo.
- It asks for build settings. Fill in exactly:

  | Field | Value |
  |---|---|
  | Framework preset | `Astro` |
  | Build command | `npm run build` |
  | Build output directory | `dist` |

- Before clicking deploy, find **Environment variables** and add one:

  | Name | Value |
  |---|---|
  | `NODE_VERSION` | `22` |

  (Without this it may try to build with an old version of Node and fail.)

- Click **Save and Deploy**. Wait ~2 minutes.

It gives you a temporary address like `tokenbench-abc.pages.dev`. Open it. **The site
should be working.**

### 5. Attach the real domain

- In your new Pages project, go to the **Custom domains** tab.
- Click **Set up a custom domain**, enter `tokenbench.dev`, confirm.
- Do it again for `www.tokenbench.dev` if you want that to work too.

Wait a few minutes, then open **https://tokenbench.dev**.

**Done. The site is live.**

---

## Part 2 — Tell Google it exists

Optional, but this is the only number that matters for the first 90 days. Your spec's
kill criterion depends on it.

- Go to https://search.google.com/search-console
- Click **Add property** → **Domain** → type `tokenbench.dev`.
- It asks you to prove you own it by adding a DNS record. It gives you a value to copy.
- In Cloudflare: **DNS** → **Add record** → type `TXT`, name `@`, paste the value → Save.
- Back in Search Console, click **Verify**.
- Once verified: **Sitemaps** in the left menu → type `sitemap.xml` → **Submit**.

Now Google knows the site exists and you can watch whether people find it.

---

## Part 3 — Visitor counting

The site has no analytics by design — nothing runs in the visitor's browser, and there
is nothing to configure. Traffic numbers (page views per page, requests, countries)
come from Cloudflare: dashboard → tokenbench.dev → **Analytics**. That's it.

---

## If something goes wrong

- **The build fails in Cloudflare.** Almost always the `NODE_VERSION` variable is
  missing or wrong. It must be `22`.
- **tokenbench.dev shows an error or the wrong thing.** The nameserver change from step 3
  probably hasn't finished. Give it a few more hours.
- **Anything else.** Copy the error message and paste it to Claude.
