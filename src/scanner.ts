import { load } from "cheerio";
import { performance } from "node:perf_hooks";
import { auditConfig } from "./config.ts";
import { fetchPublicPage, normalizeUrl, ScanError } from "./safe-url.ts";
import type { AuditReport, Finding, FindingStatus, FetchedPage, PageResult } from "./types.ts";

interface QueueItem { url: URL; depth: number }
interface ScannedPage { response: FetchedPage; $: ReturnType<typeof load>; depth: number }

const ADDITIONAL_LIMITATIONS = [
  "The audit is limited to pages visible without signing in. Private routes, analytics, transactions, and server-side behavior cannot be verified.",
  "Core Web Vitals, rendered layout, color contrast, and JavaScript-only interactions need a real browser run and are reported as not tested by this lightweight scanner.",
  "A scan is a point-in-time review, not a penetration test, compliance certification, or guarantee that a site is secure."
];

function addFinding(findings: Finding[], finding: Omit<Finding, "id">): void {
  findings.push({ ...finding, id: `${finding.category.toLowerCase().replace(/[^a-z0-9]+/gu, "-")}-${findings.length + 1}` });
}

function statusSummary(findings: Finding[]): AuditReport["summary"] {
  return findings.reduce<AuditReport["summary"]>((counts, finding) => {
    if (finding.status === "not-tested") counts.notTested += 1;
    else if (finding.status === "pass" || finding.status === "warning" || finding.status === "fail" || finding.status === "info") counts[finding.status] += 1;
    return counts;
  }, { pass: 0, warning: 0, fail: 0, info: 0, notTested: 0 });
}

function check(
  findings: Finding[], category: string, title: string, status: FindingStatus, summary: string,
  recommendation?: string, evidence?: string
): void {
  addFinding(findings, { category, title, status, summary, ...(recommendation ? { recommendation } : {}), ...(evidence ? { evidence } : {}) });
}

function textOf($: ReturnType<typeof load>, selector: string): string {
  return $(selector).first().text().replace(/\s+/gu, " ").trim();
}

function attrOf($: ReturnType<typeof load>, selector: string, attr: string): string {
  return String($(selector).first().attr(attr) ?? "").trim();
}

function statusFromResponse(statusCode: number): FindingStatus {
  if (statusCode >= 200 && statusCode < 300) return "pass";
  if (statusCode >= 300 && statusCode < 400) return "warning";
  return "fail";
}

function toPageResult(page: ScannedPage): PageResult {
  return {
    url: page.response.url.href,
    statusCode: page.response.statusCode,
    contentType: page.response.contentType,
    bytes: page.response.bytes,
    responseTimeMs: page.response.responseTimeMs
  };
}

function collectLinks(page: ScannedPage): URL[] {
  const links = new Map<string, URL>();
  const base = page.response.url;
  page.$("a[href]").each((_index, element) => {
    const href = page.$(element).attr("href")?.trim();
    if (!href || href.startsWith("#") || href.startsWith("mailto:") || href.startsWith("tel:") || href.startsWith("javascript:")) return;
    try {
      const url = new URL(href, base);
      if ((url.protocol === "http:" || url.protocol === "https:") && url.origin === base.origin) {
        url.hash = "";
        if (!url.pathname.match(/\.(?:pdf|zip|png|jpe?g|gif|svg|webp|woff2?|css|js|mp[34])$/iu)) links.set(url.href, url);
      }
    } catch { /* malformed links are ignored and counted in the link check separately */ }
  });
  return [...links.values()];
}

function analyzeHtml(findings: Finding[], root: ScannedPage, pages: ScannedPage[], allLinks: URL[]): void {
  const $ = root.$;
  const title = textOf($, "title");
  const description = attrOf($, 'meta[name="description"]', "content");
  const h1Count = $("h1").length;
  const documentLang = attrOf($, "html", "lang");
  const viewport = attrOf($, 'meta[name="viewport"]', "content");
  const canonical = attrOf($, 'link[rel="canonical"]', "href");
  const robotsMeta = `${attrOf($, 'meta[name="robots"]', "content")} ${attrOf($, 'meta[name="googlebot"]', "content")}`.toLowerCase();
  const imageCount = $("img").length;
  let missingAlt = 0;
  $("img").each((_index, element) => { if ($(element).attr("alt") === undefined) missingAlt += 1; });
  let unnamedLinks = 0;
  $("a[href]").each((_index, element) => {
    const anchor = $(element);
    const label = (anchor.text().trim() || anchor.attr("aria-label") || anchor.find("img[alt]").attr("alt") || "").trim();
    if (!label || /^(?:click here|here|read more|learn more|more)$/iu.test(label)) unnamedLinks += 1;
  });
  let unlabelledInputs = 0;
  $("input:not([type=hidden]), select, textarea").each((_index, element) => {
    const input = $(element);
    const id = input.attr("id");
    const hasLabel = Boolean(input.attr("aria-label") || input.attr("aria-labelledby") || (id && $(`label[for="${id.replace(/["\\]/gu, "\\$&")}"]`).length) || input.closest("label").length);
    if (!hasLabel) unlabelledInputs += 1;
  });
  let unnamedButtons = 0;
  $("button, input[type=button], input[type=submit]").each((_index, element) => {
    const button = $(element);
    if (!(button.text().trim() || button.attr("aria-label") || button.attr("title") || button.attr("value"))) unnamedButtons += 1;
  });
  let untitledFrames = 0;
  $("iframe, frame").each((_index, element) => { if (!$(element).attr("title") && !$(element).attr("aria-label")) untitledFrames += 1; });
  const headingLevels = $("h1,h2,h3,h4,h5,h6").map((_index, element) => Number(element.tagName.slice(1))).get();
  const headingJump = headingLevels.some((level, index) => index > 0 && level > (headingLevels[index - 1] ?? level) + 1);
  const pageCount = pages.length;
  const failedPages = pages.filter((page) => page.response.statusCode >= 400);

  check(findings, "Search", "Page title", title ? (title.length <= 65 ? "pass" : "warning") : "fail",
    title ? `Found a ${title.length}-character title.` : "No document title was found.",
    "Give every page a unique, descriptive title that is concise enough to show in search results.", title || undefined);
  check(findings, "Search", "Meta description", description ? (description.length >= 50 && description.length <= 170 ? "pass" : "warning") : "fail",
    description ? `Found a ${description.length}-character description.` : "No meta description was found.",
    "Add a useful summary of the page in a meta description.", description || undefined);
  check(findings, "Search", "Primary heading", h1Count === 1 ? "pass" : h1Count === 0 ? "fail" : "warning",
    h1Count === 1 ? "The page has one H1 heading." : `The page has ${h1Count} H1 headings.`,
    "Use one clear H1 heading to describe the page content.");
  check(findings, "Search", "Canonical URL", canonical ? "pass" : "warning",
    canonical ? "A canonical URL is declared." : "No canonical URL was found.",
    "Add a canonical link when this page can be reached through multiple URLs.", canonical || undefined);
  check(findings, "Search", "Robots indexing directive", /\bnoindex\b/u.test(robotsMeta) ? "warning" : "pass",
    /\bnoindex\b/u.test(robotsMeta) ? "A robots meta tag asks search engines not to index this page." : "No noindex directive was found in the page markup.",
    "Remove noindex only if this public page should appear in search results.");
  check(findings, "Search", "Structured data", $("script[type='application/ld+json']").length ? "pass" : "info",
    $("script[type='application/ld+json']").length ? "JSON-LD structured data was found." : "No JSON-LD structured data was found.",
    "Add structured data only when it accurately describes the page.");

  check(findings, "Accessibility", "Document language", documentLang ? "pass" : "fail",
    documentLang ? `The document declares language “${documentLang}”.` : "The HTML element has no language attribute.",
    "Set the html lang attribute so assistive technology can choose the right pronunciation.");
  check(findings, "Accessibility", "Viewport setup", /width\s*=\s*device-width/iu.test(viewport) ? "pass" : "warning",
    viewport ? "A viewport meta tag is present." : "No viewport meta tag was found.",
    "Use a responsive viewport meta tag for mobile browsers.");
  check(findings, "Accessibility", "Image alternatives", missingAlt === 0 ? "pass" : "fail",
    imageCount === 0 ? "No images were found." : `${missingAlt} of ${imageCount} images have no alt attribute.`,
    'Add useful alt text to informative images and alt="" to decorative images.');
  check(findings, "Accessibility", "Form control labels", unlabelledInputs === 0 ? "pass" : "fail",
    unlabelledInputs === 0 ? "All detected form controls have an accessible label." : `${unlabelledInputs} form controls have no detected associated label.`,
    "Associate each form control with a visible label or an appropriate accessible name.");
  check(findings, "Accessibility", "Link names", unnamedLinks === 0 ? "pass" : "warning",
    unnamedLinks === 0 ? "No empty or generic link names were found." : `${unnamedLinks} links are empty or use a generic label.`,
    "Use link text that explains the destination or action.");
  check(findings, "Accessibility", "Button names", unnamedButtons === 0 ? "pass" : "fail",
    unnamedButtons === 0 ? "Detected buttons have accessible names." : `${unnamedButtons} buttons have no detected accessible name.`,
    "Give every button a visible label or an appropriate accessible name.");
  check(findings, "Accessibility", "Frame titles", untitledFrames === 0 ? "pass" : "warning",
    untitledFrames === 0 ? "Embedded frames have descriptive labels or titles." : `${untitledFrames} frames have no title or accessible label.`,
    "Give each iframe a concise title describing its contents.");
  check(findings, "Accessibility", "Heading order", headingJump ? "warning" : "pass",
    headingJump ? "A heading level is skipped in the document outline." : "No skipped heading levels were detected.",
    "Nest headings in order so the outline reflects the page structure.");
  check(findings, "Accessibility", "Page landmarks", $("main").length > 0 && $("nav").length > 0 ? "pass" : "warning",
    $("main").length > 0 && $("nav").length > 0 ? "Main and navigation landmarks were found." : "A main or navigation landmark was not detected.",
    "Use semantic landmarks such as main and nav to make page regions easier to navigate.");
  check(findings, "Accessibility", "Color contrast and keyboard flow", "not-tested",
    "Static HTML cannot reliably measure rendered contrast or keyboard interaction.",
    "Run a browser based accessibility scan and manually check the page with a keyboard.");

  const htmlSize = root.response.bytes;
  check(findings, "Performance", "HTML transfer size", htmlSize <= 500000 ? "pass" : "warning",
    `The HTML response was ${Math.round(htmlSize / 1024)} KB.`, "Reduce large HTML payloads where possible.");
  check(findings, "Performance", "Server response time", root.response.responseTimeMs < 800 ? "pass" : root.response.responseTimeMs < 1800 ? "warning" : "fail",
    `The first page responded in ${root.response.responseTimeMs} ms.`, "Reduce server response time, especially for uncached requests.");
  check(findings, "Performance", "Core Web Vitals", "not-tested",
    "Largest Contentful Paint, Interaction to Next Paint, and Cumulative Layout Shift need a rendered browser session.",
    "Measure real-user Core Web Vitals or run Lighthouse in a browser environment.");
  const imageSources = $("img[src]").map((_index, element) => $(element).attr("src")).get();
  const oversizedUnoptimized = $("img:not([loading='lazy'])").length;
  check(findings, "Performance", "Image loading hints", oversizedUnoptimized === 0 ? "pass" : "info",
    imageSources.length === 0 ? "No images were found." : `${oversizedUnoptimized} images do not declare loading="lazy".`,
    "Lazy-load below-the-fold images and size images for their display dimensions.");

  const externalBlankTargets = $("a[target='_blank']:not([rel*='noopener'])").length;
  check(findings, "Security", "New-tab link isolation", externalBlankTargets === 0 ? "pass" : "warning",
    externalBlankTargets === 0 ? "No target=_blank links without noopener were found." : `${externalBlankTargets} links open a new tab without rel=noopener.`,
    'Use rel="noopener" on links that open a new tab.');
  const anchorsWithHref = $("a[href]").length;
  check(findings, "Content", "Crawlable links", anchorsWithHref > 0 ? "pass" : "warning",
    `${anchorsWithHref} links were found on the first page.`, "Use standard anchor elements for links users and crawlers need to follow.");
  check(findings, "Content", "Public page coverage", "info",
    `Scanned ${pageCount} page${pageCount === 1 ? "" : "s"} within the configured crawl budget${allLinks.length ? `; found ${allLinks.length} same-site links` : ""}.`,
    "Increase MAX_PAGES to inspect more of a large website.");
  check(findings, "Availability", "Crawled page responses", failedPages.length === 0 ? "pass" : "fail",
    failedPages.length === 0 ? `All ${pageCount} crawled page${pageCount === 1 ? "" : "s"} responded below HTTP 400.` : `${failedPages.length} crawled pages returned an error status.`,
    "Fix broken routes or remove links to pages that should not be public.", failedPages.map((page) => `${page.response.statusCode} ${page.response.url.href}`).join("; ") || undefined);
}

function checkSecurityHeaders(findings: Finding[], response: FetchedPage): void {
  const headers = response.headers;
  const getHeader = (name: string): string => {
    const value = headers[name.toLowerCase()];
    return (Array.isArray(value) ? value.join(", ") : value ?? "").trim();
  };
  const csp = getHeader("content-security-policy");
  const hsts = getHeader("strict-transport-security");
  const xcto = getHeader("x-content-type-options");
  const frame = getHeader("x-frame-options") || (csp.match(/frame-ancestors[^;]*/iu)?.[0] ?? "");
  const referrer = getHeader("referrer-policy");
  const permissions = getHeader("permissions-policy");
  const server = getHeader("server");
  const powered = getHeader("x-powered-by");
  const cors = getHeader("access-control-allow-origin");
  const setCookie = headers["set-cookie"];
  const cookies = Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [];

  check(findings, "Security", "Content Security Policy", csp ? "pass" : "warning",
    csp ? "A Content-Security-Policy response header is present." : "No Content-Security-Policy response header was found.",
    "Add a Content Security Policy suited to the resources this site needs.");
  check(findings, "Security", "HTTP Strict Transport Security", response.url.protocol !== "https:" ? "not-tested" : hsts ? "pass" : "warning",
    response.url.protocol !== "https:" ? "HSTS is only meaningful on HTTPS; the final page is not HTTPS." : hsts ? "An HSTS response header is present." : "No HSTS response header was found.",
    "Serve the site over HTTPS and consider a suitable Strict-Transport-Security policy.");
  check(findings, "Security", "MIME sniffing protection", xcto.toLowerCase() === "nosniff" ? "pass" : "warning",
    xcto ? `X-Content-Type-Options is “${xcto}”.` : "No X-Content-Type-Options response header was found.",
    "Set X-Content-Type-Options: nosniff.");
  check(findings, "Security", "Clickjacking protection", frame ? "pass" : "warning",
    frame ? "A frame restriction was found in X-Frame-Options or Content-Security-Policy." : "No frame restriction was detected.",
    "Set frame-ancestors in CSP or use X-Frame-Options when embedding is not required.");
  check(findings, "Security", "Referrer policy", referrer ? "pass" : "warning",
    referrer ? `Referrer-Policy is set to “${referrer}”.` : "No Referrer-Policy response header was found.",
    "Choose a Referrer-Policy that limits unnecessary URL disclosure.");
  check(findings, "Security", "Permissions policy", permissions ? "pass" : "info",
    permissions ? "A Permissions-Policy response header is present." : "No Permissions-Policy response header was found.",
    "Restrict browser features the site does not need.");
  check(findings, "Security", "Server technology disclosure", server || powered ? "warning" : "pass",
    server || powered ? `Response identifies server technology${server ? ` (${server})` : ""}${powered ? ` (${powered})` : ""}.` : "No common server-identifying headers were found.",
    "Remove version and framework details from response headers where practical.");
  check(findings, "Security", "Wildcard CORS", cors === "*" ? "warning" : "pass",
    cors === "*" ? "The page allows cross-origin reads from any origin." : "No wildcard Access-Control-Allow-Origin header was found.",
    "Restrict CORS to trusted origins when cross-origin access is needed.");
  const insecureCookieNames = cookies.filter((cookie) => !/;\s*secure(?:;|$)/iu.test(cookie) || !/;\s*httponly(?:;|$)/iu.test(cookie));
  check(findings, "Security", "Cookie flags", cookies.length === 0 ? "info" : insecureCookieNames.length === 0 ? "pass" : "warning",
    cookies.length === 0 ? "The page did not set cookies in this response." : insecureCookieNames.length === 0 ? `${cookies.length} cookies include Secure and HttpOnly flags.` : `${insecureCookieNames.length} of ${cookies.length} cookies lack Secure or HttpOnly.`,
    "Set Secure and HttpOnly on sensitive cookies, and choose an appropriate SameSite value.");
}

async function checkSupportingFiles(findings: Finding[], rootUrl: URL): Promise<void> {
  const paths = ["/robots.txt", "/sitemap.xml"];
  const results = await Promise.all(paths.map(async (path) => {
    try {
      return await fetchPublicPage(new URL(path, rootUrl), auditConfig.requestTimeoutMs, 250000);
    } catch { return null; }
  }));
  const robots = results[0];
  const sitemap = results[1];
  check(findings, "Search", "robots.txt", robots && robots.statusCode >= 200 && robots.statusCode < 400 ? "pass" : "warning",
    robots && robots.statusCode >= 200 && robots.statusCode < 400 ? "A public robots.txt file was found." : "No public robots.txt file was found at the site root.",
    "Add robots.txt to describe crawler access preferences; it is not an access-control mechanism.");
  check(findings, "Search", "XML sitemap", sitemap && sitemap.statusCode >= 200 && sitemap.statusCode < 400 ? "pass" : "warning",
    sitemap && sitemap.statusCode >= 200 && sitemap.statusCode < 400 ? "A sitemap.xml file was found at the site root." : "No sitemap.xml file was found at the site root.",
    "Publish a sitemap and reference it from robots.txt when search discovery matters.");
}

export async function scanWebsite(input: unknown): Promise<AuditReport> {
  const startTime = performance.now();
  const startedAt = new Date().toISOString();
  const target = normalizeUrl(input);
  const deadline = Date.now() + auditConfig.scanTimeoutMs;
  const pages: ScannedPage[] = [];
  const results: PageResult[] = [];
  const findings: Finding[] = [];
  const queue: QueueItem[] = [{ url: target, depth: 0 }];
  const enqueued = new Set([target.href]);
  let root: ScannedPage | undefined;
  const sameSiteLinks = new Map<string, URL>();

  while (queue.length > 0 && pages.length < auditConfig.maxPages) {
    if (Date.now() >= deadline) break;
    const item = queue.shift();
    if (!item) break;
    try {
      const response = await fetchPublicPage(item.url, auditConfig.requestTimeoutMs, auditConfig.maxResponseBytes);
      const isHtml = /(?:text\/html|application\/xhtml\+xml)/iu.test(response.contentType);
      const page: ScannedPage = { response, $: load(isHtml ? response.body : ""), depth: item.depth };
      results.push(toPageResult(page));
      if (!root) root = page;
      pages.push(page);
      if (isHtml && item.depth < 2 && response.statusCode < 400) {
        for (const link of collectLinks(page)) {
          sameSiteLinks.set(link.href, link);
          if (!enqueued.has(link.href) && queue.length + pages.length < auditConfig.maxPages) {
            enqueued.add(link.href);
            queue.push({ url: link, depth: item.depth + 1 });
          }
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unable to fetch this page.";
      results.push({ url: item.url.href, statusCode: null, contentType: "", bytes: 0, responseTimeMs: null, error: message });
      if (!root) throw error instanceof ScanError ? error : new ScanError(message, 422);
    }
  }

  if (!root) throw new ScanError("The website did not return a page that could be audited.", 422);

  check(findings, "Availability", "Homepage availability", statusFromResponse(root.response.statusCode),
    `The final page returned HTTP ${root.response.statusCode}.`, "Ensure the public homepage responds successfully.", root.response.url.href);
  check(findings, "Availability", "TLS certificate", root.response.url.protocol === "https:" ? "pass" : "warning",
    root.response.url.protocol === "https:" ? "The final URL uses HTTPS and its TLS certificate was accepted by the scanner." : "The final URL uses plain HTTP.",
    "Serve the website over HTTPS with a valid certificate.");
  if (target.protocol === "http:") {
    try {
      const httpsUrl = new URL(target.href);
      httpsUrl.protocol = "https:";
      const httpsResponse = await fetchPublicPage(httpsUrl, auditConfig.requestTimeoutMs, auditConfig.maxResponseBytes);
      check(findings, "Availability", "HTTPS version", httpsResponse.statusCode < 400 ? "pass" : "warning",
        httpsResponse.statusCode < 400 ? "The HTTPS version of the provided URL responded successfully." : `The HTTPS version returned HTTP ${httpsResponse.statusCode}.`,
        "Redirect visitors from HTTP to HTTPS.");
    } catch {
      check(findings, "Availability", "HTTPS version", "warning", "The HTTPS version of the provided URL could not be reached.", "Enable HTTPS and redirect HTTP visitors to it.");
    }
  } else {
    check(findings, "Availability", "HTTPS version", "pass", "The supplied URL already uses HTTPS.");
  }

  checkSecurityHeaders(findings, root.response);
  analyzeHtml(findings, root, pages, [...sameSiteLinks.values()]);
  await checkSupportingFiles(findings, root.response.url);

  const discovered = [...sameSiteLinks.values()].slice(0, auditConfig.maxLinkChecks);
  if (discovered.length > 0 && Date.now() < deadline) {
    const linkResults = await Promise.all(discovered.map(async (url) => {
      try {
        const response = await fetchPublicPage(url, Math.min(auditConfig.requestTimeoutMs, 7000), 250000);
        return { url, code: response.statusCode, error: "" };
      } catch (error) {
        return { url, code: null, error: error instanceof Error ? error.message : "Request failed" };
      }
    }));
    const broken = linkResults.filter((item) => item.code === null || item.code >= 400);
    check(findings, "Availability", "Same-site link health", broken.length === 0 ? "pass" : "warning",
      broken.length === 0 ? `Checked ${linkResults.length} same-site links; none returned an error.` : `${broken.length} of ${linkResults.length} checked same-site links could not be reached or returned an error.`,
      "Update or remove broken links.", broken.slice(0, 8).map((item) => `${item.code ?? "unreachable"} ${item.url.href}`).join("; ") || undefined);
  } else {
    check(findings, "Availability", "Same-site link health", "info", "No same-site links were available within the scan budget.");
  }

  if (Date.now() >= deadline) {
    check(findings, "Coverage", "Scan time budget", "warning", "The scan reached its configured time limit before all checks finished.", "Increase SCAN_TIMEOUT_MS or reduce page/link budgets.");
  }
  const summary = statusSummary(findings);
  const scored = summary.pass + summary.warning + summary.fail;
  const score = scored > 0 ? Math.round((summary.pass / scored) * 100) : 0;

  return {
    targetUrl: target.href,
    finalUrl: root.response.url.href,
    scannedAt: startedAt,
    durationMs: Math.round(performance.now() - startTime),
    score,
    summary,
    pages: results,
    findings,
    limitations: ADDITIONAL_LIMITATIONS
  };
}
