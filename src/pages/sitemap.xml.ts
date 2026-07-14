import type { APIRoute } from "astro";
import { TOOLS } from "../lib/site";

const PATHS = ["/", ...TOOLS.map((tool) => tool.path), "/privacy", "/terms"];

export const GET: APIRoute = ({ site }) => {
  const origin = (site ?? new URL("https://tokenbench.dev")).origin;
  const today = new Date().toISOString().slice(0, 10);

  const urls = PATHS.map(
    (path) => `  <url>
    <loc>${origin}${path}</loc>
    <lastmod>${today}</lastmod>
    <priority>${path === "/" ? "1.0" : path.startsWith("/jwt") ? "0.9" : "0.3"}</priority>
  </url>`,
  ).join("\n");

  return new Response(
    `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls}
</urlset>
`,
    { headers: { "content-type": "application/xml; charset=utf-8" } },
  );
};
