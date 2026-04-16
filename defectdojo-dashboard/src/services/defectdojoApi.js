// DefectDojo API Service
// All requests use relative paths (/api/v2/...) so the
// Vite dev-server proxy forwards them to localhost DefectDojo.

const headers = (token) => ({
  "Authorization": `Token ${token}`,
  "Content-Type": "application/json",
});

async function apiFetch(path, token) {
  const res = await fetch(path, { headers: headers(token) });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HTTP ${res.status} — ${text.slice(0, 300)}`);
  }
  return res.json();
}

async function fetchAllPages(path, token, params = {}) {
  const query = new URLSearchParams({ limit: 100, offset: 0, ...params }).toString();
  let url = `${path}?${query}`;
  let all = [];

  while (url) {
    const data = await apiFetch(url, token);
    all = all.concat(data.results || []);
    if (data.next) {
      const next = new URL(data.next);
      url = next.pathname + next.search;
    } else {
      url = null;
    }
  }

  return all;
}

export async function checkConnection(token) {
  await apiFetch("/api/v2/users/?limit=1", token);
  return true;
}

// ── Findings ──────────────────────────────────────────────────────────────────
export async function fetchFindings(token, filters = {}) {
  // Exclude duplicates and false positives at the API level — this is the
  // first and most impactful dedup pass. DefectDojo flags known duplicates
  // server-side; we never need to fetch them.
  const params = {
    active:    true,
    duplicate: false,  // drop findings DefectDojo already marked as dupes
    false_p:   false,  // drop confirmed false positives
  };
  if (filters.severity) params.severity = filters.severity;

  const raw        = await fetchAllPages("/api/v2/findings", token, params);
  const normalized = raw.map(normalizeFinding);
  const deduped    = deduplicateFindings(normalized);

  // ── ML Risk Score : appel au backend FastAPI ──────────────────────────────
  // Fallback silencieux sur le score rule-based si le backend est indisponible.
  try {
    const mlPayload = {
      findings: deduped.map(f => ({
        id:                 f.id,
        severity:           f.severity,
        cvss_score:         f.cvss_score,
        cwe:                f.cwe,
        age_days:           f.date
          ? Math.floor((Date.now() - new Date(f.date)) / 86_400_000)
          : 90,
        has_mitigation:     f.mitigation ? 1 : 0,
        verified:           f.verified   ? 1 : 0,
        scanner_confidence: f.scanner_confidence || 3,
        risk_accepted:      f.risk_accepted       ? 1 : 0,
      })),
    };
    // Send in chunks of 200 to stay well within limits
    const CHUNK = 200;
    const allMLResults = [];
    const findingsList = mlPayload.findings;
    for (let i = 0; i < findingsList.length; i += CHUNK) {
      const chunk = findingsList.slice(i, i + CHUNK);
      const mlRes = await fetch("http://localhost:8000/predict/batch", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ findings: chunk }),
      });
      if (!mlRes.ok) {
        const errBody = await mlRes.text();
        console.error("[ML Backend] chunk error:", mlRes.status, errBody);
        throw new Error("ML batch failed: " + mlRes.status);
      }
      const { results } = await mlRes.json();
      allMLResults.push(...results);
    }
    const scoreMap = Object.fromEntries(allMLResults.map(r => [r.id, r]));
    return deduped.map(f => ({
      ...f,
      risk_score:   scoreMap[f.id]?.risk_score    ?? f.risk_score,
      risk_label:   scoreMap[f.id]?.risk_name     ?? null,
      risk_probas:  scoreMap[f.id]?.probabilities ?? null,
      ml_scored:    true,
    }));
  } catch (_) {
    // Backend ML non disponible — on utilise le score rule-based JS
    console.warn("[ML Backend] indisponible, fallback sur rule-based score.");
  }

  return deduped;
}

// ── Products ──────────────────────────────────────────────────────────────────
export async function fetchProducts(token) {
  const raw = await fetchAllPages("/api/v2/products", token);
  return raw.map((p) => ({ id: p.id, name: p.name }));
}

// ── PATCH a finding ───────────────────────────────────────────────────────────
export async function patchFinding(token, findingId, fields) {
  const res = await fetch(`/api/v2/findings/${findingId}/`, {
    method: "PATCH",
    headers: headers(token),
    body: JSON.stringify(fields),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`PATCH failed: HTTP ${res.status} — ${text.slice(0, 200)}`);
  }
  return res.json();
}

// ── Deduplication ─────────────────────────────────────────────────────────────
//
// A finding is considered a duplicate of another if they share the same
// "fingerprint" — built from the fields that uniquely identify a vulnerability:
//
//   title (normalized) + severity + cwe + cve + component_name + file_path
//
// When duplicates are found, we keep the MOST SEVERE / MOST RECENT one and
// attach a `duplicateCount` so the UI can show "X similar findings merged".
//
function buildFingerprint(f) {
  const severity = f.severity || "";
  const cwe      = f.cwe || "0";

  // ── Priority 1: CVE in the dedicated field ───────────────────────────────
  // Same CVE ID = same vulnerability, regardless of package/version/scanner
  if (f.cve) return "cve:" + f.cve;

  // ── Priority 2: CVE embedded in title ────────────────────────────────────
  // Many scanners write "CVE-2022-27943 gcc-12-base 12.2.0-14" as the title
  // and leave the cve field empty. Extract just the CVE ID.
  const cveInTitle = f.title.match(/CVE-\d{4}-\d{4,7}/i);
  if (cveInTitle) return "cve:" + cveInTitle[0].toUpperCase();

  // ── Priority 3: Generic vuln title (ZAP, Burp, etc.) ────────────────────
  // Strip scanner noise: "(CWE-79)", version strings, trailing punctuation
  const title = f.title
    .toLowerCase()
    .trim()
    .replace(/\s*\(cwe-\d+\)/gi, "")   // "(CWE-79)"
    .replace(/\s+\d+\.\d+[\d.]*$/g, "") // trailing version "1.2.3"
    .replace(/[.:!?]+$/, "")
    .replace(/\s+/g, " ");

  const component = f.component_name?.toLowerCase().trim() || "";

  // For web scanner findings (no component, no file) group purely by title+severity+cwe
  // — same alert on multiple URLs should collapse into one
  if (!component && !f.file_path) {
    return "title:" + title + "__sev:" + severity + "__cwe:" + cwe;
  }

  // For SCA/container findings include component but NOT version or file path
  // — same vuln in different versions of same package = same issue
  return "title:" + title + "__sev:" + severity + "__cwe:" + cwe + "__comp:" + component;
}

// Priority order: keep the finding with the highest severity & newest date
const SEV_ORDER = { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 };

function pickBest(a, b) {
  const sa = SEV_ORDER[a.severity] ?? 0;
  const sb = SEV_ORDER[b.severity] ?? 0;
  if (sa !== sb) return sa > sb ? a : b;
  // Same severity → keep the newer one
  const da = a.date ? new Date(a.date) : new Date(0);
  const db = b.date ? new Date(b.date) : new Date(0);
  return da >= db ? a : b;
}

function deduplicateFindings(findings) {
  // Step 1 — drop findings already flagged as duplicates by DefectDojo itself
  const notFlagged = findings.filter((f) => !f.duplicate);

  // Step 2 — group by fingerprint
  const groups = new Map(); // fingerprint → [finding, ...]

  for (const f of notFlagged) {
    const key = buildFingerprint(f);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(f);
  }

  // Step 3 — from each group keep the "best" finding, attach metadata
  const unique = [];
  for (const [, group] of groups) {
    const best = group.reduce(pickBest);
    unique.push({
      ...best,
      duplicateCount: group.length,          // how many were merged
      duplicateIds:   group.map((f) => f.id).filter((id) => id !== best.id),
    });
  }

  // Step 4 — sort by risk_score descending so the worst come first
  unique.sort((a, b) => b.risk_score - a.risk_score);

  // DEBUG — open browser DevTools Console to see this report
  var _totalMerged = findings.length - unique.length;
  console.group("[DefectDojo Dedup Report]");
  console.log("Raw findings fetched:", findings.length);
  console.log("After dedup (unique):", unique.length);
  console.log("Merged/removed      :", _totalMerged);
  console.log("--- Sample fingerprints (first 20) ---");
  findings.slice(0, 20).forEach(function(f) {
    console.log(buildFingerprint(f) + " | " + f.title.slice(0, 60));
  });
  console.log("--- Groups with duplicates ---");
  var _shown = 0;
  groups.forEach(function(group, key) {
    if (group.length > 1 && _shown < 10) {
      console.log("x" + group.length + " | " + key.slice(0, 80));
      _shown++;
    }
  });
  if (_shown === 0) console.warn("NO groups had more than 1 finding — every fingerprint is unique!");
  console.groupEnd();

  return unique;
}

// ── Normalize ─────────────────────────────────────────────────────────────────
function normalizeFinding(f) {
  return {
    id:                f.id,
    title:             f.title || "",
    severity:          f.severity || "Info",
    cvss_score:        f.cvssv3_score ?? f.cvss ?? null,
    cvss_vector:       f.cvssv3 || null,
    cwe:               f.cwe || 0,
    cve:               f.cve || null,
    component_name:    f.component_name || "",
    component_version: f.component_version || "",
    description:       f.description || "",
    mitigation:        f.mitigation || "",
    impact:            f.impact || "",
    references:        f.references || "",
    file_path:         f.file_path || "",
    line:              f.line || null,
    date:              f.date || null,
    active:            !!f.active,
    verified:          !!f.verified,
    false_positive:    !!f.false_p,
    duplicate:         !!f.duplicate,
    risk_accepted:     !!f.risk_accepted,
    tags:              Array.isArray(f.tags) ? f.tags : [],
    scanner_confidence: f.scanner_confidence || null,
    test:              f.test || null,
    found_by:          f.found_by || [],
    risk_score:        computeRiskScore(f),
    // dedup fields added later by deduplicateFindings()
    duplicateCount: 1,
    duplicateIds:   [],
  };
}

// ── Risk Score ────────────────────────────────────────────────────────────────
const SEV_WEIGHT  = { Critical: 10, High: 8, Medium: 5, Low: 2, Info: 1 };
const CWE_HIGH_RISK = new Set([22, 78, 79, 89, 94, 119, 120, 134, 190, 287, 327, 330, 400, 476, 787]);
const CWE_MED_RISK  = new Set([20, 74, 176, 248, 674, 754, 908]);

function computeRiskScore(f) {
  const sevW    = SEV_WEIGHT[f.severity] || 2;
  const cvss    = f.cvssv3_score ?? f.cvss ?? sevW * 0.9;
  const cwe     = f.cwe;
  const cweRisk = CWE_HIGH_RISK.has(cwe) ? 3 : CWE_MED_RISK.has(cwe) ? 2 : 1;
  const noFix   = f.mitigation ? 0 : 1;
  const daysOld = f.date
    ? Math.min((Date.now() - new Date(f.date)) / 86_400_000, 365)
    : 90;
  const ageRisk = (Math.log1p(daysOld) / Math.log1p(365)) * 10;

  const raw =
    (cvss    / 10) * 35 +
    (sevW    / 10) * 25 +
    (cweRisk /  3) * 15 +
    (ageRisk / 10) * 10 +
    noFix          *  5;

  return Math.min(100, Math.max(0, raw));
}
