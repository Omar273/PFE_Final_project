const SEV_STYLES = {
  Critical: { background: "#fef2f2", color: "#991b1b", border: "1px solid #fca5a5" },
  High:     { background: "#fffbeb", color: "#92400e", border: "1px solid #fcd34d" },
  Medium:   { background: "#eff6ff", color: "#1e40af", border: "1px solid #93c5fd" },
  Low:      { background: "#f0fdf4", color: "#166534", border: "1px solid #86efac" },
  Info:     { background: "#f9fafb", color: "#374151", border: "1px solid #d1d5db" },
};

export function SeverityBadge({ severity }) {
  const s = SEV_STYLES[severity] || SEV_STYLES.Info;
  return (
    <span style={{ ...base, ...s }}>{severity}</span>
  );
}

export function StatusBadge({ finding }) {
  if (finding.false_positive) return <span style={{ ...base, background: "#fffbeb", color: "#92400e", border: "1px solid #fcd34d" }}>False Pos.</span>;
  if (finding.duplicate)      return <span style={{ ...base, background: "#f9fafb", color: "#6b7280", border: "1px solid #d1d5db" }}>Duplicate</span>;
  if (finding.risk_accepted)  return <span style={{ ...base, background: "#f5f3ff", color: "#5b21b6", border: "1px solid #c4b5fd" }}>Accepted</span>;
  if (finding.verified)       return <span style={{ ...base, background: "#eff6ff", color: "#1e40af", border: "1px solid #93c5fd" }}>Verified</span>;
  if (finding.active)         return <span style={{ ...base, background: "#f0fdf4", color: "#166534", border: "1px solid #86efac" }}>Active</span>;
  return <span style={{ ...base, background: "#f9fafb", color: "#9ca3af", border: "1px solid #e5e7eb" }}>Inactive</span>;
}

const base = {
  display: "inline-block", fontSize: 11, fontWeight: 600,
  padding: "2px 8px", borderRadius: 20, whiteSpace: "nowrap",
};
