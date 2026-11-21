const form = document.querySelector("#scan-form");
const input = document.querySelector("#url-input");
const button = document.querySelector("#scan-button");
const errorBox = document.querySelector("#form-error");
const progressPanel = document.querySelector("#progress-panel");
const progressTitle = document.querySelector("#progress-title");
const progressCopy = document.querySelector("#progress-copy");
const results = document.querySelector("#results");

const progressSteps = [
  ["Connecting to the site…", "Checking the public URL and response headers."],
  ["Following public pages…", "Sampling same-site pages and links."],
  ["Reviewing page signals…", "Looking at search, accessibility, and security basics."],
  ["Putting the report together…", "Separating measured results from checks that need a browser."]
];

if ("serviceWorker" in navigator && window.isSecureContext) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/sw.js").catch(() => {
      // Auditing remains available if offline support cannot be installed.
    });
  });
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/gu, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[character]);
}

function statusLabel(status) {
  return status === "not-tested" ? "Not tested" : status;
}

function renderFinding(finding) {
  const statusClass = `status-${finding.status}`;
  return `<article class="finding" data-category="${escapeHtml(finding.category)}" data-status="${escapeHtml(finding.status)}">
    <div><span class="status-pill ${statusClass}">${escapeHtml(statusLabel(finding.status))}</span></div>
    <div><p class="finding-category">${escapeHtml(finding.category)}</p><h3>${escapeHtml(finding.title)}</h3></div>
    <div><p class="finding-summary">${escapeHtml(finding.summary)}</p>${finding.recommendation ? `<p class="finding-recommendation">${escapeHtml(finding.recommendation)}</p>` : ""}${finding.evidence ? `<p class="finding-evidence">${escapeHtml(finding.evidence)}</p>` : ""}</div>
  </article>`;
}

function renderReport(report) {
  const categories = ["All", ...new Set(report.findings.map((finding) => finding.category))];
  const summary = report.summary;
  const reportJson = JSON.stringify(report, null, 2);
  results.innerHTML = `<div class="result-header">
    <div><p class="result-kicker">Audit report · ${new Date(report.scannedAt).toLocaleString()}</p><h2>${escapeHtml(new URL(report.finalUrl).hostname)}</h2><p class="result-meta">${escapeHtml(report.finalUrl)} · ${report.pages.length} page${report.pages.length === 1 ? "" : "s"} · ${(report.durationMs / 1000).toFixed(1)} sec</p></div>
    <div class="result-actions"><button class="small-button" id="download-report" type="button">Download JSON ↓</button><button class="small-button" id="new-scan" type="button">New audit ↗</button></div>
  </div>
  <div class="overview"><div class="score-ring" data-score="${report.score}"><div class="score-value">${report.score}<span>Site score</span></div></div><div><p class="result-caveat">A quick score based on observed public checks. It summarizes this sample; it is not a certification or a complete quality measure.</p><div class="summary-counts"><span class="count-item pass"><b>${summary.pass}</b> pass</span><span class="count-item warning"><b>${summary.warning}</b> review</span><span class="count-item fail"><b>${summary.fail}</b> issue</span><span class="count-item info"><b>${summary.info + summary.notTested}</b> informational</span></div></div></div>
  <div class="filter-row"><span class="filter-label">Filter findings</span>${categories.map((category, index) => `<button class="filter-button${index === 0 ? " active" : ""}" type="button" data-filter="${escapeHtml(category)}">${escapeHtml(category)}</button>`).join("")}</div>
  <div class="finding-list">${report.findings.map(renderFinding).join("")}</div>
  <section class="pages-panel"><h3>Pages checked</h3>${report.pages.map((page) => `<div class="page-row"><span>${escapeHtml(page.url)}</span><span>${page.statusCode ?? "failed"}${page.responseTimeMs === null ? "" : ` · ${page.responseTimeMs} ms`}</span></div>`).join("")}</section>
  <section class="limitations-panel"><h3>What this scan cannot tell you</h3><ul>${report.limitations.map((limitation) => `<li>${escapeHtml(limitation)}</li>`).join("")}</ul></section>`;
  results.hidden = false;
  results.querySelector(".score-ring").style.setProperty("--score-angle", `${Math.round(report.score * 3.6)}deg`);
  results.querySelectorAll(".filter-button").forEach((filterButton) => {
    filterButton.addEventListener("click", () => {
      results.querySelectorAll(".filter-button").forEach((item) => item.classList.remove("active"));
      filterButton.classList.add("active");
      const selected = filterButton.dataset.filter;
      results.querySelectorAll(".finding").forEach((finding) => {
        finding.classList.toggle("hidden", selected !== "All" && finding.dataset.category !== selected);
      });
    });
  });
  results.querySelector("#download-report").addEventListener("click", () => {
    const blob = new Blob([reportJson], { type: "application/json" });
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = `outside-in-audit-${new URL(report.finalUrl).hostname}.json`;
    anchor.click();
    URL.revokeObjectURL(href);
  });
  results.querySelector("#new-scan").addEventListener("click", () => {
    input.focus();
    window.scrollTo({ top: 0, behavior: "smooth" });
  });
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorBox.hidden = true;
  errorBox.textContent = "";
  results.hidden = true;
  button.disabled = true;
  progressPanel.hidden = false;
  let step = 0;
  progressTitle.textContent = progressSteps[0][0];
  progressCopy.textContent = progressSteps[0][1];
  const timer = window.setInterval(() => {
    step = Math.min(step + 1, progressSteps.length - 1);
    progressTitle.textContent = progressSteps[step][0];
    progressCopy.textContent = progressSteps[step][1];
  }, 5000);

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: input.value.trim() })
    });
    const responseText = await response.text();
    let payload;
    try {
      payload = JSON.parse(responseText);
    } catch {
      throw new Error(response.ok
        ? "The audit returned an invalid response. Please try again."
        : `The audit server returned an error (${response.status}). Please try again.`);
    }
    if (!response.ok) throw new Error(payload.error || "The audit could not be completed.");
    renderReport(payload);
  } catch (error) {
    errorBox.textContent = error instanceof Error ? error.message : "The audit could not be completed.";
    errorBox.hidden = false;
  } finally {
    window.clearInterval(timer);
    button.disabled = false;
    progressPanel.hidden = true;
  }
});
