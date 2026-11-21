export default function handler(request: Request): Response {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return Response.json({ error: "unsupported_service" }, {
      status: 405,
      headers: { Allow: "GET, HEAD", "Cache-Control": "no-store" }
    });
  }

  return Response.json({
    error: "unsupported_service",
    error_description: "Outside In is not an OpenID Connect provider."
  }, { status: 404, headers: { "Cache-Control": "no-store" } });
}
