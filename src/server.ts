import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { auditConfig, port, siteUrl } from "./config.ts";
import { ScanError } from "./safe-url.ts";
import { scanWebsite } from "./scanner.ts";

const rootDir = resolve(fileURLToPath(new URL("..", import.meta.url)));
const publicDir = resolve(rootDir, "public");
const MIME_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".png": "image/png",
  ".webp": "image/webp",
  ".txt": "text/plain; charset=utf-8",
  ".md": "text/markdown; charset=utf-8",
  ".xml": "application/xml; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".webmanifest": "application/manifest+json; charset=utf-8",
  ".rss": "application/rss+xml; charset=utf-8",
  ".atom": "application/atom+xml; charset=utf-8"
};

function setSecurityHeaders(response: ServerResponse): void {
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  response.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
  response.setHeader("Cache-Control", "no-store");
}

function sendJson(response: ServerResponse, status: number, value: unknown): void {
  setSecurityHeaders(response);
  response.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(value));
}

async function readBody(request: IncomingMessage, maxBytes = 10000): Promise<string> {
  return await new Promise<string>((resolveBody, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    request.on("data", (chunk: Buffer | string) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += buffer.length;
      if (size > maxBytes) {
        reject(new ScanError("Request body is too large.", 413));
        request.destroy();
        return;
      }
      chunks.push(buffer);
    });
    request.on("end", () => resolveBody(Buffer.concat(chunks).toString("utf8")));
    request.on("error", (error) => reject(error));
  });
}

async function serveStatic(pathname: string, response: ServerResponse): Promise<void> {
  let decoded: string;
  try { decoded = decodeURIComponent(pathname); }
  catch { sendJson(response, 400, { error: "Invalid request path." }); return; }
  const relativePath = decoded === "/" ? "index.html" : decoded.replace(/^\/+/, "");
  const filePath = resolve(publicDir, relativePath);
  if (filePath !== publicDir && !filePath.startsWith(`${publicDir}${sep}`)) {
    sendJson(response, 403, { error: "Forbidden." });
    return;
  }
  try {
    const file = await readFile(filePath);
    const extension = extname(filePath).toLowerCase();
    const body = [".html", ".txt", ".xml"].includes(extension)
      ? file.toString("utf8").replaceAll("{{SITE_URL}}", siteUrl)
      : file;
    setSecurityHeaders(response);
    const contentType = decoded === "/.well-known/traffic-advice"
      ? "application/trafficadvice+json; charset=utf-8"
      : decoded === "/.well-known/webfinger"
        ? "application/jrd+json; charset=utf-8"
        : decoded === "/.well-known/apple-app-site-association"
          ? "application/json; charset=utf-8"
          : decoded === "/feed.xml" || decoded === "/rss.xml"
            ? "application/rss+xml; charset=utf-8"
            : decoded === "/atom.xml"
              ? "application/atom+xml; charset=utf-8"
              : MIME_TYPES[extension] ?? "application/octet-stream";
    response.writeHead(200, { "Content-Type": contentType });
    response.end(body);
  } catch {
    try {
      const notFoundPage = await readFile(resolve(publicDir, "404.html"));
      setSecurityHeaders(response);
      response.writeHead(404, { "Content-Type": "text/html; charset=utf-8" });
      response.end(notFoundPage);
    } catch {
      sendJson(response, 404, { error: "Not found." });
    }
  }
}

const server = createServer(async (request, response) => {
  const requestUrl = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
  if ((request.method === "GET" || request.method === "HEAD") && requestUrl.pathname === "/.well-known/change-password") {
    response.writeHead(302, { Location: "/privacy.html#accounts", "Cache-Control": "no-store" });
    response.end();
    return;
  }
  if ((request.method === "GET" || request.method === "HEAD") && requestUrl.pathname === "/.well-known/webfinger") {
    setSecurityHeaders(response);
    response.writeHead(404, { "Content-Type": "application/jrd+json; charset=utf-8", "Cache-Control": "no-store" });
    response.end(JSON.stringify({ error: "not_found" }));
    return;
  }
  if ((request.method === "GET" || request.method === "HEAD") && requestUrl.pathname === "/.well-known/openid-configuration") {
    setSecurityHeaders(response);
    response.writeHead(404, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
    response.end(JSON.stringify({ error: "unsupported_service", error_description: "Outside In is not an OpenID Connect provider." }));
    return;
  }
  if (request.method === "GET" && requestUrl.pathname === "/api/health") {
    sendJson(response, 200, { status: "ok", limits: auditConfig });
    return;
  }
  if (request.method === "POST" && requestUrl.pathname === "/api/scan") {
    try {
      const raw = await readBody(request);
      let payload: unknown;
      try { payload = JSON.parse(raw); }
      catch { throw new ScanError("Send a valid JSON request body."); }
      const targetUrl = payload && typeof payload === "object" && "url" in payload ? payload.url : undefined;
      const report = await scanWebsite(targetUrl);
      sendJson(response, 200, report);
    } catch (error) {
      const status = error instanceof ScanError ? error.statusCode : 500;
      const message = error instanceof Error ? error.message : "The audit could not be completed.";
      sendJson(response, status, { error: message });
    }
    return;
  }
  if (request.method !== "GET" && request.method !== "HEAD") {
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  await serveStatic(requestUrl.pathname, response);
});

server.requestTimeout = auditConfig.scanTimeoutMs + 15000;
server.headersTimeout = 15000;
server.keepAliveTimeout = 5000;

server.listen(port, "127.0.0.1", () => {
  console.log(`Outside-in Website Audit is ready at http://127.0.0.1:${port}`);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
