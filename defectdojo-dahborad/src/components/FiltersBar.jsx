export default function FiltersBar({ findings, filters, onChange }) {
  const components = [...new Set(findings.map((f) => f.component_name).filter(Boolean))].sort();

  const set = (key, val) => onChange({ ...filters, [key]: val });

  return (
    <div style={styles.bar}>
      <input
        style={styles.search}
        type="text"
        placeholder="Search title, component, CVE…"
        value={filters.search}
        onChange={(e) => set("search", e.target.value)}
      />

      <div style={styles.sep} />

      <select style={styles.sel} value={filters.severity} onChange={(e) => set("severity", e.target.value)}>
        <option value="">All severities</option>
        {["Critical", "High", "Medium", "Low", "Info"].map((s) => (
          <option key={s}>{s}</option>
        ))}
      </select>

      <select style={styles.sel} value={filters.status} onChange={(e) => set("status", e.target.value)}>
        <option value="">All statuses</option>
        <option value="active">Active</option>
        <option value="verified">Verified</option>
        <option value="fp">False positive</option>
        <option value="dup">Duplicate</option>
      </select>

      <select style={styles.sel} value={filters.component} onChange={(e) => set("component", e.target.value)}>
        <option value="">All components</option>
        {components.map((c) => <option key={c}>{c}</option>)}
      </select>

      <div style={styles.sep} />

      <select style={styles.sel} value={filters.sortBy} onChange={(e) => set("sortBy", e.target.value)}>
        <option value="sev">Sort: Severity ↓</option>
        <option value="risk">Sort: Risk score ↓</option>
        <option value="cvss">Sort: CVSS ↓</option>
        <option value="date">Sort: Date ↓</option>
        <option value="comp">Sort: Component A–Z</option>
      </select>

      <button
        style={styles.resetBtn}
        onClick={() => onChange({ search: "", severity: "", status: "", component: "", sortBy: "sev" })}
      >
        Reset
      </button>
    </div>
  );
}

const styles = {
  bar: {
    display: "flex", alignItems: "center", flexWrap: "wrap", gap: 8,
    background: "#fff", border: "1px solid #e8eaf0", borderRadius: 10,
    padding: "10px 14px", marginBottom: 12,
  },
  search: {
    flex: 1, minWidth: 180, height: 34, padding: "0 12px", fontSize: 13,
    borderRadius: 7, border: "1.5px solid #e5e7eb", outline: "none", color: "#111",
  },
  sel: {
    height: 34, padding: "0 8px", fontSize: 13, borderRadius: 7,
    border: "1.5px solid #e5e7eb", background: "#fff", color: "#374151", cursor: "pointer",
  },
  sep: { width: 1, height: 22, background: "#e5e7eb" },
  resetBtn: {
    height: 34, padding: "0 14px", fontSize: 13, borderRadius: 7,
    border: "1.5px solid #e5e7eb", background: "#f9fafb", color: "#6b7280", cursor: "pointer",
  },
};
