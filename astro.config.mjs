import { defineConfig } from "astro/config";
import preact from "@astrojs/preact";

export default defineConfig({
  integrations: [preact()],
  // Drives canonical URLs and the sitemap.
  site: "https://tokenbench.dev",
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
