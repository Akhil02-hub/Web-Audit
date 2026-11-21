import { ScanError } from "../src/safe-url.ts";
import { scanWebsite } from "../src/scanner.ts";

const jsonHeaders = {
  "Cache-Control": "no-store",
  "Content-Type": "application/json; charset=utf-8",
  "X-Content-Type-Options": "nosniff"
};

function jsonError(status: number, error: string): Response {
  return Response.json({ error }, { status, headers: jsonHeaders });
}

export default {
  async fetch(request: Request): Promise<Response> {
    if (request.method !== "POST") {
      return Response.json({ error: "Method not allowed." }, { status: 405, headers: { ...jsonHeaders, Allow: "POST" } });
    }

    const length = Number(request.headers.get("content-length") ?? 0);
    if (length > 10000) return jsonError(413, "Request body is too large.");

    try {
      const raw = await request.text();
      if (Buffer.byteLength(raw, "utf8") > 10000) return jsonError(413, "Request body is too large.");
      let payload: unknown;
      try { payload = JSON.parse(raw); }
      catch { throw new ScanError("Send a valid JSON request body."); }
      const targetUrl = payload && typeof payload === "object" && "url" in payload ? payload.url : undefined;
      const report = await scanWebsite(targetUrl);
      return Response.json(report, { headers: jsonHeaders });
    } catch (error) {
      if (error instanceof ScanError) return jsonError(error.statusCode, error.message);
      return jsonError(500, "The audit could not be completed. Please try again.");
    }
  }
};
