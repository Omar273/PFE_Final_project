import { useState } from "react";
import { SeverityBadge, StatusBadge } from "./Badges";

const PAGE_SIZE = 15;

function RiskBar({ score }) {
  const color = score >= 75 ? "#dc2626" : score >= 50 ? "#d97706" : score >= 25 ? "#2563eb" : "#16a34a";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
      <div style={{ width: 56, height: 4, background: "#f3f4f6", borderRadius: 2, overflow: "hidden" }}>
        <div style={{ width: `${score}%`, height: "100%", background: color, borderRadius: 2 }} />
      </div>
      <span style={{ fontSize: 11, fontWeight: 600, color, minWidth: 28 }}>{score.toFixed(1)}</span>
    </div>
  );
}

// Shows "×3 merged" badge when duplicates were collapsed into this row
function MergedBadge({ count }) {
  if (!count || count <= 1) return null;
  return (
    <span
      title={`${count} similar findings were merged into this one`}
      style={{
        display: "inline-block",
        fontSize: 10,
        fontWeight: 600,
        color: "#7c3aed",
        background: "#f5f3ff",
        border: "1px solid #ddd6fe",
        borderRadius: 4,
        padding: "1px 5px",
        marginLeft: 5,
        verticalAlign: "middle",
        cursor: "default",
      }}
    >
      ×{count} merged
    </span>
  );
}

export default function FindingsTable({ findings }) {
  const [page, setPage] = useState(1);
  const total = Math.ceil(findings.length / PAGE_SIZE);
  const slice = findings.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  // Count how many were originally merged across all findings
  const totalMerged = findings.reduce((acc, f) => acc + ((f.duplicateCount ?? 1) - 1), 0);

  if (findings.length === 0) {
    return <div style={styles.empty}>No findings match the current filters.</div>;
  }

  return (
    <div>
      {/* Dedup summary banner */}
      {totalMerged > 0 && (
        <div style={styles.dedupBanner}>
          <span style={styles.dedupIcon}>🔀</span>
          <span>
            <strong>{totalMerged} duplicate finding{totalMerged > 1 ? "s" : ""}</strong> were
            merged — showing <strong>{findings.length} unique</strong> issues.
            Rows marked <span style={styles.inlinePill}>×N merged</span> collapsed similar reports.
          </span>
        </div>
      )}

      <div style={styles.wrap}>
        <table style={styles.table}>
          <thead>
            <tr>
              {["Title", "Severity", "CVSS", "Risk score", "Component", "Version", "Status", "Date"].map((h) => (
                <th key={h} style={styles.th}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {slice.map((f) => (
              <tr key={f.id} style={styles.tr}>
                <td style={{ ...styles.td, maxWidth: 280 }}>
                  <div style={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: 4 }}>
                    <span title={f.title} style={styles.titleCell}>{f.title}</span>
                    <MergedBadge count={f.duplicateCount} />
                  </div>
                  {f.cve && <span style={styles.cveTag}>{f.cve}</span>}
                </td>
                <td style={styles.td}><SeverityBadge severity={f.severity} /></td>
                <td style={styles.td}>{f.cvss_score != null ? parseFloat(f.cvss_score).toFixed(1) : "—"}</td>
                <td style={styles.td}><RiskBar score={f.risk_score} /></td>
                <td style={{ ...styles.td, maxWidth: 120 }}>
                  <span title={f.component_name} style={styles.clip}>{f.component_name || "—"}</span>
                </td>
                <td style={styles.td}>{f.component_version || "—"}</td>
                <td style={styles.td}><StatusBadge finding={f} /></td>
                <td style={{ ...styles.td, color: "#9ca3af" }}>{f.date || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div style={styles.pager}>
        <span style={{ fontSize: 13, color: "#9ca3af" }}>
          {findings.length} unique findings · page {page} of {total || 1}
        </span>
        <div style={{ display: "flex", gap: 4 }}>
          <PBtn disabled={page === 1}        onClick={() => setPage(1)}>«</PBtn>
          <PBtn disabled={page === 1}        onClick={() => setPage(p => p - 1)}>‹</PBtn>
          {Array.from({ length: Math.min(total, 7) }, (_, i) => {
            const p = total <= 7 ? i + 1 : page <= 4 ? i + 1 : page >= total - 3 ? total - 6 + i : page - 3 + i;
            return <PBtn key={p} active={p === page} onClick={() => setPage(p)}>{p}</PBtn>;
          })}
          <PBtn disabled={page === total}    onClick={() => setPage(p => p + 1)}>›</PBtn>
          <PBtn disabled={page === total}    onClick={() => setPage(total)}>»</PBtn>
        </div>
      </div>
    </div>
  );
}

function PBtn({ children, active, disabled, onClick }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        width: 30, height: 30, borderRadius: 7, fontSize: 13,
        border: active ? "none" : "1.5px solid #e5e7eb",
        background: active ? "#1a56db" : disabled ? "#f9fafb" : "#fff",
        color: active ? "#fff" : disabled ? "#d1d5db" : "#374151",
        cursor: disabled ? "default" : "pointer",
        fontWeight: active ? 600 : 400,
      }}
    >
      {children}
    </button>
  );
}

const styles = {
  dedupBanner: {
    display: "flex", alignItems: "flex-start", gap: 10,
    background: "#faf5ff", border: "1px solid #ddd6fe",
    borderRadius: 10, padding: "10px 14px",
    fontSize: 13, color: "#4c1d95", marginBottom: "0.75rem", lineHeight: 1.6,
  },
  dedupIcon: { fontSize: 16, flexShrink: 0, marginTop: 1 },
  inlinePill: {
    display: "inline-block", fontSize: 10, fontWeight: 600,
    color: "#7c3aed", background: "#ede9fe",
    borderRadius: 4, padding: "1px 5px", margin: "0 2px",
  },
  wrap: { overflowX: "auto", border: "1px solid #e8eaf0", borderRadius: 12, background: "#fff" },
  table: { width: "100%", borderCollapse: "collapse", fontSize: 13, tableLayout: "fixed" },
  th: {
    padding: "9px 14px", textAlign: "left", fontSize: 11, fontWeight: 600,
    color: "#9ca3af", borderBottom: "1px solid #f3f4f6", background: "#fafafa",
    whiteSpace: "nowrap", textTransform: "uppercase", letterSpacing: ".04em",
  },
  td: { padding: "10px 14px", borderBottom: "1px solid #f9fafb", verticalAlign: "middle", overflow: "hidden" },
  tr: { transition: "background .1s" },
  titleCell: { display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "#111", fontWeight: 500 },
  cveTag: { display: "inline-block", fontSize: 10, color: "#6b7280", background: "#f3f4f6", borderRadius: 4, padding: "1px 5px", marginTop: 2 },
  clip: { display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
  pager: { display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: 12, flexWrap: "wrap", gap: 8 },
  empty: { textAlign: "center", padding: "3rem", color: "#9ca3af", fontSize: 14, background: "#fff", borderRadius: 12, border: "1px solid #e8eaf0" },
};
