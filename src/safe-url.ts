import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";
import type { LookupFunction } from "node:net";
import type { IncomingHttpHeaders } from "node:http";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { performance } from "node:perf_hooks";
import type { FetchedPage } from "./types.ts";

const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);

export class ScanError extends Error {
  public readonly statusCode: number;

  constructor(message: string, statusCode = 400) {
    super(message);
    this.name = "ScanError";
    this.statusCode = statusCode;
  }
}

export function normalizeUrl(value: unknown): URL {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new ScanError("Enter a website URL to start the audit.");
  }
  if (value.length > 2048) throw new ScanError("The URL is too long.");

  let url: URL;
  try {
    url = new URL(/^https?:\/\//iu.test(value.trim()) ? value.trim() : `https://${value.trim()}`);
  } catch {
    throw new ScanError("Enter a valid website URL, such as https://example.com.");
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new ScanError("Only public HTTP and HTTPS websites can be scanned.");
  }
  if (url.username || url.password) throw new ScanError("URLs containing a username or password are not allowed.");
  if (!url.hostname || url.hostname.length > 253) throw new ScanError("The URL does not contain a valid hostname.");
  if (isBlockedHostname(url.hostname)) throw new ScanError("Local and private network addresses cannot be scanned.");
  url.hash = "";
  return url;
}

function isBlockedHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/gu, "").replace(/\.$/u, "");
  return host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal");
}

function isPublicAddress(address: string): boolean {
  const version = isIP(address);
  if (version === 4) {
    const parts = address.split(".").map(Number);
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
    const [a = 0, b = 0] = parts;
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && (b === 168 || b === 0 || b === 2)) return false;
    if (a === 198 && (b === 18 || b === 19 || b === 51)) return false;
    if (a === 203 && b === 0) return false;
    return true;
  }
  if (version === 6) {
    const normalized = address.toLowerCase();
    if (normalized === "::1" || normalized === "::" || normalized.startsWith("fc") || normalized.startsWith("fd") || normalized.startsWith("fe8") || normalized.startsWith("fe9") || normalized.startsWith("fea") || normalized.startsWith("feb")) return false;
    if (normalized.startsWith("::ffff:")) return false;
    // Public IPv6 unicast addresses are within 2000::/3. This excludes mapped, local and reserved ranges.
    const firstHextet = Number.parseInt(normalized.split(":")[0] ?? "0", 16);
    return firstHextet >= 0x2000 && firstHextet <= 0x3fff && normalized !== "2001:db8::" && !normalized.startsWith("2001:db8:");
  }
  return false;
}

async function resolvePublic(hostname: string): Promise<Array<{ address: string; family: number }>> {
  const bare = hostname.replace(/^\[|\]$/gu, "");
  if (isIP(bare)) {
    if (!isPublicAddress(bare)) throw new ScanError("Local and private network addresses cannot be scanned.");
    return [{ address: bare, family: isIP(bare) }];
  }
  if (isBlockedHostname(bare)) throw new ScanError("Local and private network addresses cannot be scanned.");

  let addresses: Array<{ address: string; family: number }>;
  try {
    addresses = await dnsLookup(bare, { all: true, verbatim: true });
  } catch {
    throw new ScanError(`Could not resolve ${bare}. Check the hostname and try again.`, 422);
  }
  if (addresses.length === 0 || addresses.some(({ address }) => !isPublicAddress(address))) {
    throw new ScanError("The website resolves to a local or private network address and cannot be scanned.");
  }
  return addresses;
}

function headersToRecord(headers: IncomingHttpHeaders): Record<string, string | string[] | undefined> {
  return { ...headers };
}

async function requestOnce(url: URL, timeoutMs: number, maxBytes: number): Promise<FetchedPage> {
  const addresses = await resolvePublic(url.hostname);
  const address = addresses[0];
  if (!address) throw new ScanError("The website did not resolve to a public address.", 422);
  const start = performance.now();

  return await new Promise<FetchedPage>((resolve, reject) => {
    let settled = false;
    const finishError = (error: Error): void => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    const pinnedLookup: LookupFunction = (_hostname, _options, callback) => {
      if (_options.all) callback(null, [address]);
      else callback(null, address.address, address.family);
    };
    const requestFn = url.protocol === "https:" ? httpsRequest : httpRequest;
    const request = requestFn({
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port || undefined,
      path: `${url.pathname || "/"}${url.search}`,
      method: "GET",
      headers: {
        "User-Agent": "OutsideInAudit/1.0 (+public website audit)",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.7",
        "Accept-Encoding": "identity",
        Connection: "close"
      },
      lookup: pinnedLookup,
      servername: isIP(url.hostname) ? undefined : url.hostname,
      rejectUnauthorized: true
    }, (response) => {
      const chunks: Buffer[] = [];
      let total = 0;
      response.on("data", (chunk: Buffer | string) => {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        total += buffer.length;
        if (total > maxBytes) {
          request.destroy(new ScanError("The page is larger than the configured scan limit.", 413));
          return;
        }
        chunks.push(buffer);
      });
      response.on("error", (error) => finishError(error));
      response.on("end", () => {
        if (settled) return;
        settled = true;
        const bodyBuffer = Buffer.concat(chunks);
        const contentType = String(response.headers["content-type"] ?? "");
        resolve({
          url,
          statusCode: response.statusCode ?? 0,
          headers: headersToRecord(response.headers),
          body: contentType.toLowerCase().includes("charset=iso-8859-1") ? bodyBuffer.toString("latin1") : bodyBuffer.toString("utf8"),
          bytes: total,
          responseTimeMs: Math.round(performance.now() - start),
          contentType
        });
      });
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error("The website took too long to respond.")));
    request.on("error", (error) => finishError(error));
    request.end();
  });
}

export async function fetchPublicPage(startUrl: URL, timeoutMs: number, maxBytes: number): Promise<FetchedPage> {
  let current = new URL(startUrl);
  const visited = new Set<string>();
  for (let redirects = 0; redirects <= 5; redirects += 1) {
    if (visited.has(current.href)) throw new ScanError("The website is stuck in a redirect loop.", 422);
    visited.add(current.href);
    const response = await requestOnce(current, timeoutMs, maxBytes);
    if (!REDIRECT_CODES.has(response.statusCode)) return response;
    const location = response.headers.location;
    const locationValue = Array.isArray(location) ? location[0] : location;
    if (!locationValue) return response;
    try {
      current = normalizeUrl(new URL(locationValue, current).href);
    } catch (error) {
      if (error instanceof ScanError) throw error;
      throw new ScanError("The website returned an invalid redirect.", 422);
    }
  }
  throw new ScanError("The website redirected too many times.", 422);
}
