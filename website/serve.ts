import { serve } from "bun";
import { join } from "path";
import { existsSync, statSync } from "fs";

const PORT = Number(process.env.PORT) || 4321;
const DIST = join(import.meta.dir, "dist");

serve({
  port: PORT,
  hostname: "0.0.0.0",
  async fetch(req) {
    const url = new URL(req.url);
    let pathname = decodeURIComponent(url.pathname);

    // Friendly relative redirect from root to base path
    if (pathname === "" || pathname === "/") {
      return new Response(null, {
        status: 302,
        headers: { Location: "/duckJump/" },
      });
    }

    // Strip /duckJump prefix to find in dist/
    let relative = pathname.startsWith("/duckJump")
      ? pathname.slice("/duckJump".length)
      : pathname;

    if (relative === "" || relative === "/") {
      relative = "/index.html";
    }

    let filePath = join(DIST, relative);

    // Directory resolution with trailing index.html
    if (existsSync(filePath) && statSync(filePath).isDirectory()) {
      filePath = join(filePath, "index.html");
    } else if (!existsSync(filePath) && existsSync(`${filePath}.html`)) {
      filePath = `${filePath}.html`;
    } else if (!existsSync(filePath) && existsSync(join(filePath, "index.html"))) {
      filePath = join(filePath, "index.html");
    }

    if (existsSync(filePath) && !statSync(filePath).isDirectory()) {
      return new Response(Bun.file(filePath));
    }

    // Fallback: check directly in dist
    const directPath = join(DIST, pathname);
    if (existsSync(directPath) && !statSync(directPath).isDirectory()) {
      return new Response(Bun.file(directPath));
    }

    return new Response("duckJump — 404 Not Found", { 
      status: 404,
      headers: { "Content-Type": "text/plain" }
    });
  },
});

console.log(`duckJump website server listening on port ${PORT}`);
