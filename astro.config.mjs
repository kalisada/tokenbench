import { defineConfig } from "astro/config";
import preact from "@astrojs/preact";

export default defineConfig({
  integrations: [preact()],
  // Drives canonical URLs and the sitemap.
  site: "https://tokenbench.dev",
  build: {
    inlineStylesheets: "auto",
    // Emit /jwt-decoder.html instead of /jwt-decoder/index.html so the served
    // URL matches the canonical exactly (no trailing slash). Cloudflare Pages
    // then 308s the slashed form to the canonical one, instead of the reverse.
    format: "file",
  },
  trailingSlash: "never",
  vite: {
    resolve: {
      alias: {
        "@lib": new URL("./src/lib", import.meta.url).pathname,
      },
    },
  },
});
