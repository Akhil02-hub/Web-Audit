export type FindingStatus = "pass" | "warning" | "fail" | "info" | "not-tested";

export interface Finding {
  id: string;
  category: string;
  title: string;
  status: FindingStatus;
  summary: string;
  recommendation?: string;
  evidence?: string;
}

export interface PageResult {
  url: string;
  statusCode: number | null;
  contentType: string;
  bytes: number;
  responseTimeMs: number | null;
  error?: string;
}

export interface AuditReport {
  targetUrl: string;
  finalUrl: string;
  scannedAt: string;
  durationMs: number;
  score: number;
  summary: {
    pass: number;
    warning: number;
    fail: number;
    info: number;
    notTested: number;
  };
  pages: PageResult[];
  findings: Finding[];
  limitations: string[];
}

export interface AuditConfig {
  maxPages: number;
  maxLinkChecks: number;
  requestTimeoutMs: number;
  maxResponseBytes: number;
  scanTimeoutMs: number;
}

export interface FetchedPage {
  url: URL;
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  bytes: number;
  responseTimeMs: number;
  contentType: string;
}
