export default function handler(request: Request): Response {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return Response.json({ error: "method_not_allowed" }, {
      status: 405,
      headers: { Allow: "GET, HEAD", "Cache-Control": "no-store", "Content-Type": "application/jrd+json; charset=utf-8" }
    });
  }

  return Response.json({ error: "not_found" }, {
    status: 404,
    headers: { "Cache-Control": "no-store", "Content-Type": "application/jrd+json; charset=utf-8" }
  });
}
