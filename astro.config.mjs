import { defineConfig } from "astro/config";
import preact from "@astrojs/preact";

export default defineConfig({
  integrations: [preact()],
  // Domain is not purchased yet (spec: buy at build time). Set before launch —
  // sitemap/canonical generation depends on it.
  site: "https://tokenbench.example",
  build: {
    inlineStylesheets: "auto",
  },
  vite: {
    resolve: {
      alias: {
        "@lib": new URL("./src/lib", import.meta.url).pathname,
      },
    },
  },
});
