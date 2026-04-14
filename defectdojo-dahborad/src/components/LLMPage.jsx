import { useState, useRef, useEffect } from "react";

// ─── CONFIG ────────────────────────────────────────────────────────────────
const GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions";
const GROQ_MODEL   = "llama-3.1-8b-instant";

const SYSTEM_CHAT = `You are a cybersecurity expert assistant specialized in DefectDojo vulnerability management.
You help security teams analyze findings, understand risks, prioritize remediation, and interpret vulnerability data.
Be concise, technical, and practical. When relevant, reference CVSS scores, CWE IDs, OWASP categories, and remediation best practices.`;

const SYSTEM_RISK = `You are a strict AI risk classifier. Return ONLY valid JSON, no markdown, no explanation outside the JSON.`;

// ─── GROQ CALL ─────────────────────────────────────────────────────────────
async function groqChat(apiKey, messages, systemPrompt) {
  const response = await fetch(GROQ_API_URL, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: GROQ_MODEL,
      temperature: 0,
      messages: [
        { role: "system", content: systemPrompt },
        ...messages,
      ],
    }),
  });
  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Groq API error ${response.status}: ${err}`);
  }
  const data = await response.json();
  return data.choices[0].message.content;
}

// ─── MAIN PAGE ─────────────────────────────────────────────────────────────
export default function LLMPage() {
  const [apiKey, setApiKey] = useState("");
  const [keyConfirmed, setKeyConfirmed] = useState(false);
  const [tab, setTab] = useState("chat"); // "chat" | "risk"

  if (!keyConfirmed) {
    return <ApiKeyGate apiKey={apiKey} setApiKey={setApiKey} onConfirm={() => setKeyConfirmed(true)} />;
  }

  return (
    <div style={styles.page}>
      {/* Header */}
      <div style={styles.header}>
        <div style={styles.headerLeft}>
          <div style={styles.headerIcon}>🦙</div>
          <div>
            <div style={styles.headerTitle}>LLM Analyzer</div>
            <div style={styles.headerSub}>Powered by Llama 3.1 · Groq</div>
          </div>
        </div>
        <div style={styles.tabBar}>
          <button
            style={{ ...styles.tab, ...(tab === "chat" ? styles.tabActive : {}) }}
            onClick={() => setTab("chat")}
          >
            💬 Chat
          </button>
          <button
            style={{ ...styles.tab, ...(tab === "risk" ? styles.tabActive : {}) }}
            onClick={() => setTab("risk")}
          >
            🛡️ Risk Classifier
          </button>
        </div>
        <button style={styles.changeKeyBtn} onClick={() => setKeyConfirmed(false)}>
          Change API key
        </button>
      </div>

      {tab === "chat"
        ? <ChatTab apiKey={apiKey} />
        : <RiskTab apiKey={apiKey} />
      }
    </div>
  );
}

// ─── API KEY GATE ──────────────────────────────────────────────────────────
function ApiKeyGate({ apiKey, setApiKey, onConfirm }) {
  return (
    <div style={styles.gatePage}>
      <div style={styles.gateCard}>
        <div style={styles.gateLogo}>
          <div style={styles.headerIcon}>🦙</div>
          <span style={styles.headerTitle}>LLM Analyzer</span>
        </div>
        <p style={styles.gateDesc}>
          Enter your <strong>Groq API key</strong> to use Llama 3.1 for security analysis and risk classification.
        </p>
        <label style={styles.label}>Groq API Key</label>
        <input
          style={styles.input}
          type="password"
          placeholder="gsk_..."
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && apiKey.trim() && onConfirm()}
          autoFocus
        />
        <button
          style={{ ...styles.confirmBtn, opacity: apiKey.trim() ? 1 : 0.5 }}
          disabled={!apiKey.trim()}
          onClick={onConfirm}
        >
          Continue →
        </button>
        <p style={styles.gateHint}>
          Get your key at <strong>console.groq.com</strong>
        </p>
      </div>
    </div>
  );
}

// ─── CHAT TAB ──────────────────────────────────────────────────────────────
function ChatTab({ apiKey }) {
  const [messages, setMessages] = useState([
    { role: "assistant", content: "Hello! I'm your security analyst powered by Llama 3.1. Ask me anything about vulnerabilities, findings, or remediation." },
  ]);
  const [input, setInput]   = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError]   = useState(null);
  const bottomRef  = useRef(null);
  const textareaRef = useRef(null);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages, loading]);

  async function send() {
    const text = input.trim();
    if (!text || loading) return;
    const userMsg = { role: "user", content: text };
    const history = [...messages, userMsg];
    setMessages(history);
    setInput("");
    setLoading(true);
    setError(null);
    try {
      const apiMsgs = history.map((m) => ({ role: m.role, content: m.content }));
      const reply = await groqChat(apiKey, apiMsgs.slice(1), SYSTEM_CHAT); // slice off the first assistant greeting
      setMessages((prev) => [...prev, { role: "assistant", content: reply }]);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={styles.chatWindow}>
      <div style={styles.messages}>
        {messages.map((m, i) => <Bubble key={i} msg={m} />)}
        {loading && (
          <div style={{ display: "flex", gap: 8, padding: 8 }}>
            <div style={styles.avatar}>AI</div>
            <div style={{ ...styles.bubble, ...styles.aiBubble }}>
              <TypingDots />
            </div>
          </div>
        )}
        {error && <div style={styles.errorMsg}>⚠ {error}</div>}
        <div ref={bottomRef} />
      </div>

      {messages.length <= 1 && (
        <div style={styles.suggestions}>
          {SUGGESTIONS.map((s) => (
            <button key={s} style={styles.suggestion}
              onClick={() => { setInput(s); textareaRef.current?.focus(); }}>
              {s}
            </button>
          ))}
        </div>
      )}

      <div style={styles.inputArea}>
        <textarea
          ref={textareaRef}
          style={styles.textarea}
          placeholder="Ask about findings, CVEs, remediation… (Enter to send)"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } }}
          rows={2}
          disabled={loading}
        />
        <button
          style={{ ...styles.sendBtn, opacity: !input.trim() || loading ? 0.5 : 1 }}
          onClick={send}
          disabled={!input.trim() || loading}
        >
          Send
        </button>
      </div>
      <style>{dotAnim}</style>
    </div>
  );
}

// ─── RISK CLASSIFIER TAB ───────────────────────────────────────────────────
function RiskTab({ apiKey }) {
  const [text, setText]       = useState("");
  const [result, setResult]   = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState(null);
  // Batch CSV mode
  const [csvRows, setCsvRows]       = useState([]);
  const [csvResults, setCsvResults] = useState([]);
  const [batchRunning, setBatchRunning] = useState(false);
  const [batchProgress, setBatchProgress] = useState(0);
  const fileRef = useRef(null);

  function buildRiskPrompt(content) {
    return `You are an AI risk detection system.

Classify the following content into:
- LOW
- MEDIUM
- HIGH

Return ONLY valid JSON with no extra text:
{
  "risk": "LOW" | "MEDIUM" | "HIGH",
  "reason": "one sentence explanation"
}

Content:
${content}`;
  }

  async function classify() {
    if (!text.trim() || loading) return;
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const reply = await groqChat(apiKey, [{ role: "user", content: buildRiskPrompt(text) }], SYSTEM_RISK);
      const clean = reply.replace(/```json|```/g, "").trim();
      setResult(JSON.parse(clean));
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  function handleCSV(e) {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const lines = ev.target.result.split("\n").filter(Boolean);
      const header = lines[0].split(",");
      const col = header.findIndex((h) => h.trim().toLowerCase().includes("issue_summary") || h.trim().toLowerCase() === "text");
      if (col === -1) { setError("CSV must have an 'Issue_Summary_Paragraphs' or 'text' column."); return; }
      const rows = lines.slice(1).map((l) => l.split(",")[col]?.replace(/^"|"$/g, "") ?? "");
      setCsvRows(rows);
      setCsvResults([]);
      setError(null);
    };
    reader.readAsText(file);
  }

  async function runBatch() {
    setBatchRunning(true);
    setBatchProgress(0);
    const results = [];
    for (let i = 0; i < csvRows.length; i++) {
      try {
        const reply = await groqChat(apiKey, [{ role: "user", content: buildRiskPrompt(csvRows[i]) }], SYSTEM_RISK);
        const clean = reply.replace(/```json|```/g, "").trim();
        results.push(JSON.parse(clean));
      } catch {
        results.push({ risk: "ERROR", reason: "API failed" });
      }
      setBatchProgress(i + 1);
      await new Promise((r) => setTimeout(r, 500)); // small delay
    }
    setCsvResults(results);
    setBatchRunning(false);
  }

  function downloadCSV() {
    const rows = csvRows.map((t, i) => ({
      text: t,
      ai_risk: csvResults[i]?.risk ?? "",
      reason: csvResults[i]?.reason ?? "",
    }));
    const header = "text,ai_risk,reason\n";
    const body = rows.map((r) => `"${r.text.replace(/"/g, '""')}","${r.ai_risk}","${r.reason.replace(/"/g, '""')}"`).join("\n");
    const blob = new Blob([header + body], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "results_with_risk.csv"; a.click();
    URL.revokeObjectURL(url);
  }

  const RISK_COLORS = { HIGH: "#991b1b", MEDIUM: "#92400e", LOW: "#065f46", ERROR: "#4b5563" };
  const RISK_BG     = { HIGH: "#fef2f2", MEDIUM: "#fffbeb", LOW: "#ecfdf5",  ERROR: "#f9fafb" };

  return (
    <div style={styles.riskPage}>
      {/* Single classifier */}
      <div style={styles.riskCard}>
        <div style={styles.riskCardTitle}>🔍 Single Issue Classifier</div>
        <textarea
          style={styles.riskTextarea}
          placeholder="Paste an issue summary or vulnerability description here…"
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={5}
        />
        <button
          style={{ ...styles.classifyBtn, opacity: !text.trim() || loading ? 0.5 : 1 }}
          disabled={!text.trim() || loading}
          onClick={classify}
        >
          {loading ? "Classifying…" : "Classify Risk"}
        </button>

        {result && (
          <div style={{ ...styles.resultBox, background: RISK_BG[result.risk], border: `1.5px solid ${RISK_COLORS[result.risk]}33` }}>
            <span style={{ ...styles.riskBadge, background: RISK_COLORS[result.risk] }}>
              {result.risk}
            </span>
            <p style={{ margin: 0, fontSize: 14, color: "#374151", marginTop: 10 }}>{result.reason}</p>
          </div>
        )}
        {error && <div style={styles.errorMsg}>⚠ {error}</div>}
      </div>

      {/* Batch CSV classifier */}
      <div style={styles.riskCard}>
        <div style={styles.riskCardTitle}>📊 Batch CSV Classifier</div>
        <p style={styles.riskDesc}>
          Upload a CSV with an <code>Issue_Summary_Paragraphs</code> column. The model will classify each row as LOW / MEDIUM / HIGH.
        </p>

        <div style={styles.uploadRow}>
          <input ref={fileRef} type="file" accept=".csv" style={{ display: "none" }} onChange={handleCSV} />
          <button style={styles.uploadBtn} onClick={() => fileRef.current.click()}>
            📁 Choose CSV
          </button>
          {csvRows.length > 0 && (
            <span style={styles.uploadInfo}>{csvRows.length} rows loaded</span>
          )}
        </div>

        {csvRows.length > 0 && (
          <>
            <button
              style={{ ...styles.classifyBtn, opacity: batchRunning ? 0.5 : 1 }}
              disabled={batchRunning}
              onClick={runBatch}
            >
              {batchRunning ? `Processing… (${batchProgress}/${csvRows.length})` : "Run Batch Classification"}
            </button>

            {batchRunning && (
              <div style={styles.progressBar}>
                <div style={{ ...styles.progressFill, width: `${(batchProgress / csvRows.length) * 100}%` }} />
              </div>
            )}

            {csvResults.length > 0 && (
              <>
                <div style={styles.batchTable}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                    <thead>
                      <tr style={{ background: "#f3f4f6" }}>
                        <th style={styles.th}>#</th>
                        <th style={styles.th}>Risk</th>
                        <th style={styles.th}>Reason</th>
                      </tr>
                    </thead>
                    <tbody>
                      {csvResults.map((r, i) => (
                        <tr key={i} style={{ borderBottom: "1px solid #e5e7eb" }}>
                          <td style={styles.td}>{i + 1}</td>
                          <td style={styles.td}>
                            <span style={{ ...styles.riskBadge, background: RISK_COLORS[r.risk] ?? "#6b7280", fontSize: 11 }}>
                              {r.risk}
                            </span>
                          </td>
                          <td style={{ ...styles.td, color: "#6b7280" }}>{r.reason}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <button style={styles.downloadBtn} onClick={downloadCSV}>
                  ⬇ Download results_with_risk.csv
                </button>
              </>
            )}
          </>
        )}
      </div>
    </div>
  );
}

// ─── SHARED COMPONENTS ─────────────────────────────────────────────────────
function Bubble({ msg }) {
  const isUser = msg.role === "user";
  return (
    <div style={{ display: "flex", justifyContent: isUser ? "flex-end" : "flex-start", marginBottom: 12 }}>
      {!isUser && <div style={styles.avatar}>AI</div>}
      <div style={{ ...styles.bubble, ...(isUser ? styles.userBubble : styles.aiBubble) }}>
        <span style={{ whiteSpace: "pre-wrap", lineHeight: 1.6 }}>{msg.content}</span>
      </div>
    </div>
  );
}

function TypingDots() {
  return (
    <div style={{ display: "flex", gap: 4 }}>
      {[0, 0.2, 0.4].map((d, i) => (
        <span key={i} style={{ ...styles.dot, animationDelay: `${d}s` }} />
      ))}
    </div>
  );
}

const SUGGESTIONS = [
  "What are the most critical findings I should fix first?",
  "Explain CVSS scoring and how to use it for prioritization",
  "What does a SQL Injection finding mean and how do I fix it?",
  "How should I handle false positives in DefectDojo?",
];

const dotAnim = `@keyframes bounce {
  0%, 80%, 100% { transform: translateY(0); opacity: 0.4; }
  40% { transform: translateY(-6px); opacity: 1; }
}`;

// ─── STYLES ─────────────────────────────────────────────────────────────────
const styles = {
  page: { maxWidth: 960, margin: "0 auto", padding: "1.5rem", display: "flex", flexDirection: "column", height: "calc(100vh - 56px)", boxSizing: "border-box" },
  header: { display: "flex", alignItems: "center", gap: 16, background: "#fff", border: "1px solid #e8eaf0", borderRadius: 12, padding: "12px 16px", marginBottom: "1rem", flexShrink: 0, flexWrap: "wrap" },
  headerLeft: { display: "flex", alignItems: "center", gap: 10 },
  headerIcon: { fontSize: 26 },
  headerTitle: { fontSize: 16, fontWeight: 700, color: "#111" },
  headerSub: { fontSize: 12, color: "#9ca3af", marginTop: 2 },
  tabBar: { display: "flex", gap: 4, flex: 1 },
  tab: { height: 34, padding: "0 14px", borderRadius: 8, border: "1.5px solid #e5e7eb", background: "#fff", fontSize: 13, fontWeight: 500, color: "#6b7280", cursor: "pointer" },
  tabActive: { background: "#eff6ff", borderColor: "#bfdbfe", color: "#1a56db", fontWeight: 600 },
  changeKeyBtn: { height: 32, padding: "0 12px", fontSize: 12, borderRadius: 7, border: "1.5px solid #e5e7eb", background: "#fff", color: "#9ca3af", cursor: "pointer" },
  // Gate
  gatePage: { minHeight: "calc(100vh - 56px)", display: "flex", alignItems: "center", justifyContent: "center", padding: "2rem" },
  gateCard: { background: "#fff", borderRadius: 14, padding: "2.5rem", width: "100%", maxWidth: 420, boxShadow: "0 2px 16px rgba(0,0,0,0.08)", border: "1px solid #e8eaf0", display: "flex", flexDirection: "column", gap: 12 },
  gateLogo: { display: "flex", alignItems: "center", gap: 10, marginBottom: 4 },
  gateDesc: { fontSize: 14, color: "#6b7280", margin: 0 },
  label: { fontSize: 13, fontWeight: 500, color: "#374151" },
  input: { height: 42, padding: "0 12px", fontSize: 14, borderRadius: 8, border: "1.5px solid #d1d5db", outline: "none", color: "#111" },
  confirmBtn: { height: 42, borderRadius: 8, background: "#1a56db", color: "#fff", border: "none", fontWeight: 600, fontSize: 15, cursor: "pointer" },
  gateHint: { fontSize: 12, color: "#9ca3af", textAlign: "center", margin: 0 },
  // Chat
  chatWindow: { flex: 1, background: "#fff", border: "1px solid #e8eaf0", borderRadius: 12, display: "flex", flexDirection: "column", overflow: "hidden" },
  messages: { flex: 1, overflowY: "auto", padding: "1.25rem", display: "flex", flexDirection: "column" },
  avatar: { width: 30, height: 30, borderRadius: "50%", background: "#1a56db", color: "#fff", fontSize: 11, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, marginRight: 8, alignSelf: "flex-end" },
  bubble: { maxWidth: "75%", padding: "10px 14px", borderRadius: 14, fontSize: 14, color: "#111", wordBreak: "break-word" },
  userBubble: { background: "#1a56db", color: "#fff", borderBottomRightRadius: 4 },
  aiBubble: { background: "#f3f4f6", borderBottomLeftRadius: 4 },
  dot: { width: 7, height: 7, borderRadius: "50%", background: "#9ca3af", display: "inline-block", animation: "bounce 1.2s infinite" },
  suggestions: { display: "flex", flexWrap: "wrap", gap: 8, padding: "0 16px 12px" },
  suggestion: { padding: "6px 12px", fontSize: 12, borderRadius: 20, border: "1.5px solid #bfdbfe", background: "#eff6ff", color: "#1e40af", cursor: "pointer", fontFamily: "inherit" },
  inputArea: { display: "flex", gap: 10, padding: "12px 16px", borderTop: "1px solid #e8eaf0", background: "#fafafa", alignItems: "flex-end" },
  textarea: { flex: 1, resize: "none", padding: "10px 14px", fontSize: 14, borderRadius: 10, border: "1.5px solid #d1d5db", outline: "none", fontFamily: "inherit", lineHeight: 1.5, color: "#111" },
  sendBtn: { height: 42, padding: "0 20px", borderRadius: 10, background: "#1a56db", color: "#fff", border: "none", fontWeight: 600, fontSize: 14, flexShrink: 0, cursor: "pointer" },
  errorMsg: { background: "#fef2f2", border: "1px solid #fca5a5", borderRadius: 8, padding: "8px 14px", fontSize: 13, color: "#991b1b", margin: "8px 0" },
  // Risk
  riskPage: { flex: 1, overflowY: "auto", display: "flex", flexDirection: "column", gap: "1rem" },
  riskCard: { background: "#fff", border: "1px solid #e8eaf0", borderRadius: 12, padding: "1.25rem", display: "flex", flexDirection: "column", gap: 12 },
  riskCardTitle: { fontSize: 15, fontWeight: 700, color: "#111" },
  riskDesc: { fontSize: 13, color: "#6b7280", margin: 0 },
  riskTextarea: { resize: "vertical", padding: "10px 14px", fontSize: 14, borderRadius: 10, border: "1.5px solid #d1d5db", outline: "none", fontFamily: "inherit", lineHeight: 1.5, color: "#111" },
  classifyBtn: { height: 40, padding: "0 20px", borderRadius: 9, background: "#1a56db", color: "#fff", border: "none", fontWeight: 600, fontSize: 14, cursor: "pointer", alignSelf: "flex-start" },
  resultBox: { borderRadius: 10, padding: "14px 16px" },
  riskBadge: { display: "inline-block", padding: "3px 10px", borderRadius: 20, color: "#fff", fontWeight: 700, fontSize: 13 },
  uploadRow: { display: "flex", alignItems: "center", gap: 12 },
  uploadBtn: { height: 38, padding: "0 16px", borderRadius: 8, border: "1.5px solid #d1d5db", background: "#f9fafb", fontSize: 13, cursor: "pointer", fontFamily: "inherit" },
  uploadInfo: { fontSize: 13, color: "#6b7280" },
  progressBar: { height: 6, background: "#e5e7eb", borderRadius: 99, overflow: "hidden" },
  progressFill: { height: "100%", background: "#1a56db", transition: "width 0.3s ease" },
  batchTable: { maxHeight: 300, overflowY: "auto", border: "1px solid #e5e7eb", borderRadius: 8 },
  th: { padding: "8px 12px", textAlign: "left", fontSize: 12, fontWeight: 600, color: "#6b7280", textTransform: "uppercase" },
  td: { padding: "8px 12px", fontSize: 13, color: "#111" },
  downloadBtn: { height: 38, padding: "0 16px", borderRadius: 8, border: "1.5px solid #bfdbfe", background: "#eff6ff", color: "#1e40af", fontSize: 13, fontWeight: 600, cursor: "pointer", alignSelf: "flex-start", fontFamily: "inherit" },
};
