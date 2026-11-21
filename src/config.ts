import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { AuditConfig } from "./types.ts";

function loadDotEnv(): void {
  try {
    const content = readFileSync(resolve(process.cwd(), ".env"), "utf8");
    for (const line of content.split(/\r?\n/u)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const separator = trimmed.indexOf("=");
      if (separator < 1) continue;
      const key = trimmed.slice(0, separator).trim();
      let value = trimmed.slice(separator + 1).trim();
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      if (process.env[key] === undefined) process.env[key] = value;
    }
  } catch {
    // .env is optional; deployment environments can provide variables directly.
  }
}

function readInteger(name: string, fallback: number, min: number, max: number): number {
  const parsed = Number.parseInt(process.env[name] ?? "", 10);
  return Number.isFinite(parsed) ? Math.min(max, Math.max(min, parsed)) : fallback;
}

loadDotEnv();

export const port = readInteger("PORT", 4173, 1, 65535);

function readSiteUrl(): string {
  const configured = process.env.SITE_URL?.trim();
  if (!configured) return "https://outside.vercel.app";
  try {
    const url = new URL(configured);
    if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
      throw new Error();
    }
    return url.origin;
  } catch {
    throw new Error("SITE_URL must be an HTTP or HTTPS origin, such as https://outside.vercel.app");
  }
}

export const siteUrl = readSiteUrl();

export const auditConfig: AuditConfig = {
  maxPages: readInteger("MAX_PAGES", 8, 1, 20),
  maxLinkChecks: readInteger("MAX_LINK_CHECKS", 16, 0, 40),
  requestTimeoutMs: readInteger("REQUEST_TIMEOUT_MS", 10000, 1000, 30000),
  maxResponseBytes: readInteger("MAX_RESPONSE_BYTES", 1500000, 100000, 5000000),
  scanTimeoutMs: readInteger("SCAN_TIMEOUT_MS", 90000, 10000, 180000)
};
