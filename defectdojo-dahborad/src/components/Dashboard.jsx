import { useState } from "react";
import { useFindings, useFilteredFindings } from "../hooks/useFindings";
import MetricsRow from "./MetricsRow";
import ChartsPanel from "./ChartsPanel";
import FiltersBar from "./FiltersBar";
import FindingsTable from "./FindingsTable";

const DEFAULT_FILTERS = { search: "", severity: "", status: "", component: "", sortBy: "sev" };

export default function Dashboard({ config, onDisconnect }) {
  const { findings, loading, error, lastFetched, reload } = useFindings(config);
  const [clientFilters, setClientFilters] = useState(DEFAULT_FILTERS);
  const [showCharts, setShowCharts] = useState(true);

  const filtered = useFilteredFindings(findings, clientFilters);

  return (
    <div style={styles.page}>
      {/* Header */}
      <div style={styles.header}>
        <div style={styles.headerLeft}>
          
          <div>
            <div style={styles.logoText}>DefectDojo Dashboard</div>
            <div style={styles.connUrl}>{config.url}</div>
          </div>
        </div>
        <div style={styles.headerRight}>
          {lastFetched && (
            <span style={styles.lastFetched}>
              Last updated {lastFetched.toLocaleTimeString()}
            </span>
          )}
          <button style={styles.headerBtn} onClick={() => reload()} disabled={loading}>
            {loading ? "Loading…" : "Refresh"}
          </button>
          <button style={{ ...styles.headerBtn, ...styles.headerBtnToggle }} onClick={() => setShowCharts(v => !v)}>
            {showCharts ? "Hide charts" : "Show charts"}
          </button>

        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div style={styles.errorBanner}>
          {error}
          <button style={styles.retryBtn} onClick={() => reload()}>Retry</button>
        </div>
      )}

      {/* Loading skeleton */}
      {loading && findings.length === 0 && (
        <div style={styles.loadingWrap}>
          <div style={styles.spinner} />
          <span style={{ color: "#6b7280", fontSize: 14 }}>Fetching findings from DefectDojo…</span>
        </div>
      )}

      {/* Main content */}
      {findings.length > 0 && (
        <>
          <MetricsRow findings={findings} />
          {showCharts && <ChartsPanel findings={findings} />}
          <FiltersBar findings={findings} filters={clientFilters} onChange={setClientFilters} />
          <FindingsTable findings={filtered} />
        </>
      )}
    </div>
  );
}

const styles = {
  page: { maxWidth: 1400, margin: "0 auto", padding: "1.25rem 1.5rem" },
  header: {
    display: "flex", alignItems: "center", justifyContent: "space-between",
    flexWrap: "wrap", gap: 12, marginBottom: "1.25rem",
    background: "#fff", border: "1px solid #e8eaf0", borderRadius: 12, padding: "12px 16px",
  },
  headerLeft: { display: "flex", alignItems: "center", gap: 12 },
  logoIcon: {
    width: 36, height: 36, borderRadius: 9, background: "#1a56db",
    display: "flex", alignItems: "center", justifyContent: "center",
    color: "#fff", fontSize: 13, fontWeight: 600, flexShrink: 0,
  },
  logoText: { fontSize: 16, fontWeight: 600, color: "#111" },
  connUrl: { fontSize: 12, color: "#9ca3af", marginTop: 1 },
  headerRight: { display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" },
  lastFetched: { fontSize: 12, color: "#9ca3af" },
  headerBtn: {
    height: 32, padding: "0 12px", fontSize: 13, borderRadius: 7,
    border: "1.5px solid #e5e7eb", background: "#fff", color: "#374151", cursor: "pointer",
  },
  headerBtnToggle: { background: "#eff6ff", borderColor: "#bfdbfe", color: "#1e40af" },
  headerBtnDanger: { background: "#fef2f2", borderColor: "#fca5a5", color: "#991b1b" },
  errorBanner: {
    display: "flex", alignItems: "center", justifyContent: "space-between",
    background: "#fef2f2", border: "1px solid #fca5a5", borderRadius: 10,
    padding: "10px 16px", fontSize: 13, color: "#991b1b", marginBottom: "1rem",
  },
  retryBtn: {
    height: 28, padding: "0 12px", fontSize: 12, borderRadius: 6,
    border: "1px solid #fca5a5", background: "#fff", color: "#991b1b", cursor: "pointer",
  },
  loadingWrap: {
    display: "flex", alignItems: "center", gap: 12,
    padding: "3rem", justifyContent: "center",
  },
  spinner: {
    width: 24, height: 24, border: "3px solid #e5e7eb",
    borderTopColor: "#1a56db", borderRadius: "50%",
    animation: "spin 0.8s linear infinite",
  },
};
