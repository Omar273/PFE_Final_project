import { useState, useRef, useEffect } from "react";

// ─── CONFIG ────────────────────────────────────────────────────────────────
const GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions";
const GROQ_MODEL   = "llama-3.1-8b-instant";

// ─── GROQ CALL ─────────────────────────────────────────────────────────────
async function groqCall(apiKey, systemPrompt, userPrompt) {
  const res = await fetch(GROQ_API_URL, {
    method: "POST",
    headers: { "Authorization": "Bearer " + apiKey, "Content-Type": "application/json" },
    body: JSON.stringify({
      model: GROQ_MODEL,
      temperature: 0.2,
      max_tokens: 2048,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user",   content: userPrompt   },
      ],
    }),
  });
  if (!res.ok) throw new Error("Groq API error " + res.status + ": " + await res.text());
  const data = await res.json();
  return data.choices[0].message.content;
}

// ─── SYSTEM PROMPT ──────────────────────────────────────────────────────────
const AGENT_SYSTEM = `You are a senior application security engineer and code remediation expert.
You specialize in fixing vulnerabilities found by CodeQL static analysis in the OWASP Juice Shop Node.js application.

When given a CodeQL finding you MUST respond with a JSON object (no markdown, no extra text) in this exact shape:
{
  "summary": "one sentence describing the vulnerability",
  "severity": "Critical|High|Medium|Low",
  "cwe": "CWE-XXX: Name",
  "attack_scenario": "2-3 sentences on how an attacker would exploit this",
  "fix_explanation": "clear explanation of what needs to change and why",
  "vulnerable_code": "the original vulnerable snippet (from the finding context)",
  "fixed_code": "the corrected code with inline comments explaining each change",
  "additional_hardening": ["tip 1", "tip 2", "tip 3"]
}`;

// ─── CODEQL RESULT SHAPE EXPECTED ──────────────────────────────────────────
// {
//   ruleId: "js/sql-injection",
//   message: "...",
//   severity: "error|warning|note",
//   location: { file: "routes/Login.js", startLine: 42, endLine: 44 },
//   snippet: "...",  ← optional raw code snippet
// }

// ─── SAMPLE CODEQL RESULTS (used when user hasn't uploaded a real SARIF) ───
const SAMPLE_FINDINGS = [
  {
    ruleId: "js/sql-injection",
    message: "SQL query built from user-controlled data in 'req.body.email'.",
    severity: "error",
    location: { file: "routes/Login.js", startLine: 40, endLine: 46 },
    snippet: `models.sequelize.query(
  "SELECT * FROM Users WHERE email = '" + req.body.email + 
  "' AND password = '" + req.body.password + "' AND deletedAt IS NULL",
  { model: UserModel, plain: true }
)`,
  },
  {
    ruleId: "js/xss",
    message: "Cross-site scripting: user-controlled data flows into innerHTML.",
    severity: "error",
    location: { file: "frontend/src/app/search-result/search-result.component.ts", startLine: 58, endLine: 58 },
    snippet: `this.ngZone.run(() => { this.searchValue.nativeElement.innerHTML = this.search; });`,
  },
  {
    ruleId: "js/path-traversal",
    message: "Uncontrolled data used in path expression from 'req.params.file'.",
    severity: "error",
    location: { file: "routes/fileServer.js", startLine: 19, endLine: 19 },
    snippet: `res.sendFile(path.join(__dirname, '../', req.params.file))`,
  },
  {
    ruleId: "js/hardcoded-credentials",
    message: "Hardcoded JWT secret used for token signing.",
    severity: "warning",
    location: { file: "lib/insecurity.js", startLine: 8, endLine: 8 },
    snippet: `const JWT_SECRET = 'this is my secret phrase'`,
  },
  {
    ruleId: "js/missing-rate-limiting",
    message: "No rate limiting on authentication endpoint — brute force possible.",
    severity: "warning",
    location: { file: "routes/Login.js", startLine: 1, endLine: 5 },
    snippet: `router.post('/', async (req, res, next) => {\n  // No rate limiting middleware applied\n  const user = await models.User.findOne(...)`,
  },
  {
    ruleId: "js/prototype-pollution",
    message: "User input merged into object without prototype check.",
    severity: "error",
    location: { file: "routes/updateUserProfile.js", startLine: 22, endLine: 22 },
    snippet: `Object.assign(user, req.body)`,
  },
];

// ─── SARIF PARSER ──────────────────────────────────────────────────────────
function parseSarif(sarif) {
  try {
    const results = [];
    for (const run of sarif.runs || []) {
      const rules = {};
      for (const rule of run.tool?.driver?.rules || []) {
        rules[rule.id] = rule;
      }
      for (const result of run.results || []) {
        const loc = result.locations?.[0]?.physicalLocation;
        results.push({
          ruleId:   result.ruleId || "unknown",
          message:  result.message?.text || "",
          severity: result.level || "warning",
          location: {
            file:      loc?.artifactLocation?.uri || "unknown",
            startLine: loc?.region?.startLine    || 0,
            endLine:   loc?.region?.endLine      || 0,
          },
          snippet: result.locations?.[0]?.physicalLocation?.contextRegion?.snippet?.text || "",
        });
      }
    }
    return results;
  } catch (e) {
    throw new Error("Invalid SARIF file: " + e.message);
  }
}

// ─── MAIN PAGE ──────────────────────────────────────────────────────────────
export default function AgentPage() {
  const [apiKey, setApiKey]         = useState("");
  const [keyConfirmed, setKeyConfirmed] = useState(false);
  const [findings, setFindings]     = useState(SAMPLE_FINDINGS);
  const [selected, setSelected]     = useState(null);
  const [analysis, setAnalysis]     = useState(null);
  const [loading, setLoading]       = useState(false);
  const [error, setError]           = useState(null);
  const [usingSample, setUsingSample] = useState(true);
  const fileRef = useRef(null);
  const analysisRef = useRef(null);

  useEffect(() => {
    if (analysis) analysisRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [analysis]);

  function handleSarif(e) {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const sarif = JSON.parse(ev.target.result);
        const parsed = parseSarif(sarif);
        if (parsed.length === 0) { setError("No results found in SARIF file."); return; }
        setFindings(parsed);
        setSelected(null);
        setAnalysis(null);
        setUsingSample(false);
        setError(null);
      } catch (err) {
        setError(err.message);
      }
    };
    reader.readAsText(file);
  }

  async function analyze(finding) {
    if (!apiKey.trim()) return;
    setSelected(finding);
    setAnalysis(null);
    setLoading(true);
    setError(null);

    const prompt = `Analyze this CodeQL finding from OWASP Juice Shop and provide a complete security fix.

Rule ID  : ${finding.ruleId}
File     : ${finding.location.file}
Line     : ${finding.location.startLine}${finding.location.endLine !== finding.location.startLine ? "-" + finding.location.endLine : ""}
Severity : ${finding.severity}
Message  : ${finding.message}

Vulnerable code snippet:
\`\`\`javascript
${finding.snippet || "(no snippet available — infer from rule and message)"}
\`\`\`

Provide your full analysis and fix in the JSON format specified.`;

    try {
      const raw = await groqCall(apiKey, AGENT_SYSTEM, prompt);
      const clean = raw.replace(/```json|```/g, "").trim();
      const parsed = JSON.parse(clean);
      setAnalysis(parsed);
    } catch (e) {
      setError("Agent error: " + e.message);
    } finally {
      setLoading(false);
    }
  }

  if (!keyConfirmed) {
    return <ApiKeyGate apiKey={apiKey} setApiKey={setApiKey} onConfirm={() => setKeyConfirmed(true)} />;
  }

  const SEV_COLOR = { error: "#dc2626", warning: "#d97706", note: "#2563eb" };
  const SEV_LABEL = { error: "HIGH", warning: "MEDIUM", note: "LOW" };

  return (
    <div style={styles.page}>
      {/* Header */}
      <div style={styles.header}>
        <div style={styles.headerLeft}>
          <span style={{ fontSize: 26 }}>🛡️</span>
          <div>
            <div style={styles.headerTitle}>AI Security Agent</div>
            <div style={styles.headerSub}>CodeQL + Llama 3.1 · Juice Shop Vulnerability Fixer</div>
          </div>
        </div>
        <div style={styles.headerRight}>
          <div style={styles.codeqlBadge}>
            <span>🔍</span> CodeQL
          </div>
          <div style={styles.llamaBadge}>
            <span>🦙</span> Llama 3.1
          </div>
          <button style={styles.uploadBtn} onClick={() => fileRef.current.click()}>
            📁 Upload SARIF
          </button>
          <input ref={fileRef} type="file" accept=".sarif,.json" style={{ display: "none" }} onChange={handleSarif} />
          <button style={styles.changeKeyBtn} onClick={() => setKeyConfirmed(false)}>
            🔑 Change key
          </button>
        </div>
      </div>

      {usingSample && (
        <div style={styles.sampleBanner}>
          <span>📋</span>
          <span>
            Using <strong>built-in Juice Shop CodeQL findings</strong> as demo. Run CodeQL on Juice Shop and upload the <code>.sarif</code> file to analyze your own results.
            See the <strong>setup guide</strong> below.
          </span>
        </div>
      )}

      {error && <div style={styles.errorBanner}>⚠ {error}</div>}

      <div style={styles.body}>
        {/* Left panel: findings list */}
        <div style={styles.leftPanel}>
          <div style={styles.panelTitle}>
            CodeQL Findings
            <span style={styles.countBadge}>{findings.length}</span>
          </div>

          {findings.map((f, i) => (
            <button
              key={i}
              style={{
                ...styles.findingCard,
                ...(selected === f ? styles.findingCardActive : {}),
              }}
              onClick={() => analyze(f)}
            >
              <div style={styles.findingTop}>
                <span style={{ ...styles.sevDot, background: SEV_COLOR[f.severity] || "#6b7280" }} />
                <span style={styles.ruleId}>{f.ruleId}</span>
                <span style={{ ...styles.sevBadge, color: SEV_COLOR[f.severity] || "#6b7280", background: (SEV_COLOR[f.severity] || "#6b7280") + "18" }}>
                  {SEV_LABEL[f.severity] || f.severity}
                </span>
              </div>
              <div style={styles.findingMsg}>{f.message}</div>
              <div style={styles.findingLoc}>
                📄 {f.location.file.split("/").pop()}:{f.location.startLine}
              </div>
            </button>
          ))}

          {/* CodeQL setup guide */}
          <div style={styles.guideBox}>
            <div style={styles.guideTitle}>🔍 How to run CodeQL on Juice Shop</div>
            <div style={styles.guideStep}><span style={styles.guideNum}>1</span>Install CodeQL CLI</div>
            <code style={styles.guideCode}>{"# Download from github.com/github/codeql-action/releases"}</code>
            <div style={styles.guideStep}><span style={styles.guideNum}>2</span>Create database</div>
            <code style={styles.guideCode}>{"codeql database create juice-db --language=javascript \\\n  --source-root=./juice-shop"}</code>
            <div style={styles.guideStep}><span style={styles.guideNum}>3</span>Run analysis</div>
            <code style={styles.guideCode}>{"codeql database analyze juice-db \\\n  javascript-security-extended.qls \\\n  --format=sarif-latest \\\n  --output=juice-shop.sarif"}</code>
            <div style={styles.guideStep}><span style={styles.guideNum}>4</span>Upload <code>juice-shop.sarif</code> above ↑</div>
          </div>
        </div>

        {/* Right panel: AI analysis */}
        <div style={styles.rightPanel}>
          {!selected && !loading && (
            <div style={styles.emptyState}>
              <div style={{ fontSize: 48, marginBottom: 12 }}>🤖</div>
              <div style={styles.emptyTitle}>Select a finding to analyze</div>
              <div style={styles.emptySub}>
                The AI agent will explain the vulnerability, show the attack scenario,
                and provide a fixed version of the code.
              </div>
            </div>
          )}

          {loading && (
            <div style={styles.loadingState}>
              <div style={styles.spinner} />
              <div style={styles.loadingText}>Agent is analyzing the vulnerability…</div>
              <div style={styles.loadingSub}>Llama 3.1 is reviewing the code and generating a fix</div>
            </div>
          )}

          {analysis && !loading && (
            <div ref={analysisRef}>
              <AnalysisView analysis={analysis} finding={selected} />
            </div>
          )}
        </div>
      </div>

      <style>{spinnerStyle}</style>
    </div>
  );
}

// ─── ANALYSIS VIEW ──────────────────────────────────────────────────────────
function AnalysisView({ analysis, finding }) {
  const [copied, setCopied] = useState(false);

  function copyFix() {
    navigator.clipboard.writeText(analysis.fixed_code || "");
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const SEV_COLORS = { Critical: "#dc2626", High: "#d97706", Medium: "#2563eb", Low: "#16a34a" };
  const sevColor = SEV_COLORS[analysis.severity] || "#6b7280";

  return (
    <div style={styles.analysis}>
      {/* Top summary bar */}
      <div style={{ ...styles.summaryBar, borderLeft: "4px solid " + sevColor }}>
        <div style={{ flex: 1 }}>
          <div style={styles.summaryTitle}>{analysis.summary}</div>
          <div style={styles.summaryMeta}>
            <span style={{ ...styles.metaTag, color: sevColor, background: sevColor + "18" }}>
              {analysis.severity}
            </span>
            <span style={styles.metaTag}>{analysis.cwe}</span>
            <span style={styles.metaTag}>📄 {finding.location.file.split("/").pop()}:{finding.location.startLine}</span>
          </div>
        </div>
      </div>

      {/* Attack scenario */}
      <Section icon="⚠️" title="Attack Scenario" color="#fef3c7" borderColor="#f59e0b">
        <p style={styles.prose}>{analysis.attack_scenario}</p>
      </Section>

      {/* Fix explanation */}
      <Section icon="💡" title="How to Fix" color="#ecfdf5" borderColor="#10b981">
        <p style={styles.prose}>{analysis.fix_explanation}</p>
      </Section>

      {/* Vulnerable vs Fixed code */}
      <div style={styles.codeGrid}>
        <div style={styles.codePanel}>
          <div style={{ ...styles.codePanelHeader, background: "#fef2f2", color: "#991b1b" }}>
            ❌ Vulnerable Code
          </div>
          <pre style={{ ...styles.codeBlock, borderTop: "2px solid #fca5a5" }}>
            {analysis.vulnerable_code}
          </pre>
        </div>
        <div style={styles.codePanel}>
          <div style={{ ...styles.codePanelHeader, background: "#ecfdf5", color: "#065f46", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span>✅ Fixed Code</span>
            <button style={styles.copyBtn} onClick={copyFix}>
              {copied ? "✓ Copied!" : "Copy"}
            </button>
          </div>
          <pre style={{ ...styles.codeBlock, borderTop: "2px solid #6ee7b7" }}>
            {analysis.fixed_code}
          </pre>
        </div>
      </div>

      {/* Additional hardening */}
      {analysis.additional_hardening?.length > 0 && (
        <Section icon="🔒" title="Additional Hardening" color="#eff6ff" borderColor="#3b82f6">
          <ul style={{ margin: 0, paddingLeft: 20, display: "flex", flexDirection: "column", gap: 6 }}>
            {analysis.additional_hardening.map((tip, i) => (
              <li key={i} style={styles.prose}>{tip}</li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}

function Section({ icon, title, color, borderColor, children }) {
  return (
    <div style={{ background: color, border: "1px solid " + borderColor + "55", borderRadius: 10, padding: "14px 16px", marginBottom: 12 }}>
      <div style={{ fontSize: 13, fontWeight: 700, color: "#111", marginBottom: 8 }}>
        {icon} {title}
      </div>
      {children}
    </div>
  );
}

// ─── API KEY GATE ───────────────────────────────────────────────────────────
function ApiKeyGate({ apiKey, setApiKey, onConfirm }) {
  return (
    <div style={styles.gatePage}>
      <div style={styles.gateCard}>
        <div style={{ fontSize: 36, textAlign: "center" }}>🛡️</div>
        <div style={{ fontSize: 18, fontWeight: 700, textAlign: "center", color: "#111" }}>AI Security Agent</div>
        <p style={{ fontSize: 14, color: "#6b7280", textAlign: "center", margin: 0 }}>
          Enter your <strong>Groq API key</strong> to enable Llama 3.1 powered code remediation.
        </p>
        <input
          style={styles.gateInput}
          type="password"
          placeholder="gsk_..."
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && apiKey.trim() && onConfirm()}
          autoFocus
        />
        <button
          style={{ ...styles.gateBtn, opacity: apiKey.trim() ? 1 : 0.5 }}
          disabled={!apiKey.trim()}
          onClick={onConfirm}
        >
          Start Agent →
        </button>
        <p style={{ fontSize: 12, color: "#9ca3af", textAlign: "center", margin: 0 }}>
          Get your key at <strong>console.groq.com</strong>
        </p>
      </div>
    </div>
  );
}

// ─── STYLES ─────────────────────────────────────────────────────────────────
const spinnerStyle = `
@keyframes spin { to { transform: rotate(360deg); } }
`;

const styles = {
  page: { maxWidth: 1400, margin: "0 auto", padding: "1.25rem 1.5rem", display: "flex", flexDirection: "column", minHeight: "calc(100vh - 56px)", boxSizing: "border-box" },
  header: { display: "flex", alignItems: "center", justifyContent: "space-between", background: "#fff", border: "1px solid #e8eaf0", borderRadius: 12, padding: "12px 16px", marginBottom: "1rem", flexWrap: "wrap", gap: 12 },
  headerLeft: { display: "flex", alignItems: "center", gap: 12 },
  headerTitle: { fontSize: 16, fontWeight: 700, color: "#111" },
  headerSub: { fontSize: 12, color: "#9ca3af", marginTop: 2 },
  headerRight: { display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" },
  codeqlBadge: { display: "flex", alignItems: "center", gap: 5, fontSize: 12, fontWeight: 600, color: "#1a56db", background: "#eff6ff", border: "1.5px solid #bfdbfe", borderRadius: 20, padding: "4px 10px" },
  llamaBadge: { display: "flex", alignItems: "center", gap: 5, fontSize: 12, fontWeight: 600, color: "#7c3aed", background: "#f5f3ff", border: "1.5px solid #ddd6fe", borderRadius: 20, padding: "4px 10px" },
  uploadBtn: { height: 34, padding: "0 14px", fontSize: 13, borderRadius: 8, border: "1.5px solid #d1d5db", background: "#fff", cursor: "pointer", fontWeight: 500 },
  changeKeyBtn: { height: 34, padding: "0 12px", fontSize: 12, borderRadius: 8, border: "1.5px solid #e5e7eb", background: "#fff", color: "#9ca3af", cursor: "pointer" },
  sampleBanner: { display: "flex", alignItems: "flex-start", gap: 10, background: "#fffbeb", border: "1px solid #fcd34d", borderRadius: 10, padding: "10px 14px", fontSize: 13, color: "#92400e", marginBottom: "1rem" },
  errorBanner: { background: "#fef2f2", border: "1px solid #fca5a5", borderRadius: 10, padding: "10px 14px", fontSize: 13, color: "#991b1b", marginBottom: "1rem" },
  body: { display: "grid", gridTemplateColumns: "340px 1fr", gap: "1rem", flex: 1, alignItems: "start" },
  // Left panel
  leftPanel: { display: "flex", flexDirection: "column", gap: 8 },
  panelTitle: { fontSize: 13, fontWeight: 700, color: "#374151", textTransform: "uppercase", letterSpacing: ".05em", display: "flex", alignItems: "center", gap: 8, marginBottom: 4 },
  countBadge: { background: "#1a56db", color: "#fff", fontSize: 11, fontWeight: 700, borderRadius: 20, padding: "1px 8px" },
  findingCard: { textAlign: "left", background: "#fff", border: "1.5px solid #e8eaf0", borderRadius: 10, padding: "10px 12px", cursor: "pointer", transition: "all 0.15s", width: "100%", fontFamily: "inherit" },
  findingCardActive: { border: "1.5px solid #1a56db", background: "#eff6ff", boxShadow: "0 0 0 3px #bfdbfe44" },
  findingTop: { display: "flex", alignItems: "center", gap: 6, marginBottom: 5 },
  sevDot: { width: 8, height: 8, borderRadius: "50%", flexShrink: 0 },
  ruleId: { fontSize: 11, fontWeight: 700, color: "#374151", fontFamily: "monospace", flex: 1 },
  sevBadge: { fontSize: 10, fontWeight: 700, borderRadius: 4, padding: "1px 6px" },
  findingMsg: { fontSize: 12, color: "#6b7280", lineHeight: 1.5, marginBottom: 5 },
  findingLoc: { fontSize: 11, color: "#9ca3af", fontFamily: "monospace" },
  // Guide box
  guideBox: { background: "#1e293b", borderRadius: 10, padding: "14px", marginTop: 8 },
  guideTitle: { fontSize: 12, fontWeight: 700, color: "#e2e8f0", marginBottom: 10 },
  guideStep: { display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: "#94a3b8", marginBottom: 4, marginTop: 8 },
  guideNum: { width: 18, height: 18, borderRadius: "50%", background: "#1a56db", color: "#fff", fontSize: 10, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 },
  guideCode: { display: "block", fontSize: 10, color: "#7dd3fc", background: "#0f172a", borderRadius: 6, padding: "6px 10px", marginTop: 2, whiteSpace: "pre-wrap", fontFamily: "monospace", lineHeight: 1.6 },
  // Right panel
  rightPanel: { background: "#fff", border: "1px solid #e8eaf0", borderRadius: 12, padding: "1.25rem", minHeight: 400 },
  emptyState: { display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "4rem 2rem", textAlign: "center" },
  emptyTitle: { fontSize: 16, fontWeight: 600, color: "#374151", marginBottom: 8 },
  emptySub: { fontSize: 14, color: "#9ca3af", maxWidth: 360, lineHeight: 1.6 },
  loadingState: { display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "4rem 2rem", gap: 16 },
  spinner: { width: 36, height: 36, border: "3px solid #e5e7eb", borderTopColor: "#1a56db", borderRadius: "50%", animation: "spin 0.8s linear infinite" },
  loadingText: { fontSize: 15, fontWeight: 600, color: "#374151" },
  loadingSub: { fontSize: 13, color: "#9ca3af" },
  // Analysis
  analysis: { display: "flex", flexDirection: "column", gap: 12 },
  summaryBar: { background: "#f9fafb", borderRadius: 10, padding: "12px 16px", display: "flex", alignItems: "flex-start", gap: 12 },
  summaryTitle: { fontSize: 14, fontWeight: 600, color: "#111", marginBottom: 8 },
  summaryMeta: { display: "flex", gap: 6, flexWrap: "wrap" },
  metaTag: { fontSize: 11, fontWeight: 600, borderRadius: 4, padding: "2px 8px", background: "#f3f4f6", color: "#6b7280" },
  prose: { fontSize: 14, color: "#374151", lineHeight: 1.7, margin: 0 },
  codeGrid: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 },
  codePanel: { border: "1px solid #e5e7eb", borderRadius: 10, overflow: "hidden" },
  codePanelHeader: { padding: "8px 12px", fontSize: 12, fontWeight: 700 },
  codeBlock: { background: "#1e293b", color: "#e2e8f0", padding: "14px", fontSize: 12, fontFamily: "monospace", lineHeight: 1.7, margin: 0, overflowX: "auto", whiteSpace: "pre-wrap", wordBreak: "break-word" },
  copyBtn: { fontSize: 11, padding: "2px 8px", borderRadius: 5, border: "1px solid #6ee7b7", background: "#fff", color: "#065f46", cursor: "pointer", fontWeight: 600 },
  // Gate
  gatePage: { minHeight: "calc(100vh - 56px)", display: "flex", alignItems: "center", justifyContent: "center" },
  gateCard: { background: "#fff", borderRadius: 14, padding: "2.5rem", width: "100%", maxWidth: 400, boxShadow: "0 4px 24px rgba(0,0,0,0.08)", border: "1px solid #e8eaf0", display: "flex", flexDirection: "column", gap: 16 },
  gateInput: { height: 44, padding: "0 14px", fontSize: 14, borderRadius: 9, border: "1.5px solid #d1d5db", outline: "none", color: "#111" },
  gateBtn: { height: 44, borderRadius: 9, background: "#1a56db", color: "#fff", border: "none", fontWeight: 700, fontSize: 15, cursor: "pointer" },
};
