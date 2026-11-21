import { auditConfig } from "../src/config.ts";

export const runtime = "nodejs";

const headers = {
  "Cache-Control": "no-store",
  "Content-Type": "application/json; charset=utf-8",
  "X-Content-Type-Options": "nosniff"
};

export default function handler(request: Request): Response {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return Response.json({ error: "Method not allowed." }, { status: 405, headers: { ...headers, Allow: "GET, HEAD" } });
  }
  return Response.json({ status: "ok", limits: auditConfig }, { headers });
}
