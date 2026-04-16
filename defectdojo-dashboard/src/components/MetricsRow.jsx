const CARD_ACCENT = {
  Total:    "#1a56db",
  Critical: "#dc2626",
  High:     "#d97706",
  Medium:   "#2563eb",
  Low:      "#16a34a",
  Active:   "#0891b2",
};

export default function MetricsRow({ findings }) {
  const counts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    if (f.active) acc.Active++;
    return acc;
  }, { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0, Active: 0 });

  const avgRisk = findings.length
    ? (findings.reduce((s, f) => s + f.risk_score, 0) / findings.length).toFixed(1)
    : "—";

  const mlActive = findings.some(f => f.ml_scored);

  const cards = [
    { label: "Total",    value: findings.length },
    { label: "Critical", value: counts.Critical },
    { label: "High",     value: counts.High },
    { label: "Medium",   value: counts.Medium },
    { label: "Low",      value: counts.Low },
    { label: "Active",   value: counts.Active },
    { label: "Avg Risk", value: avgRisk },
  ];

  return (
    <div>
      {mlActive && (
        <div style={styles.mlBadge}>
          🤖 Risk scores calculés par le modèle <strong>ML (XGBoost/RandomForest)</strong> — backend autonome actif
        </div>
      )}
      <div style={styles.row}>
        {cards.map((c) => (
          <div key={c.label} style={styles.card}>
            <div style={styles.label}>{c.label}</div>
            <div style={{ ...styles.value, color: CARD_ACCENT[c.label] || "#111" }}>{c.value}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

const styles = {
  mlBadge: { fontSize: 12, color: "#065f46", background: "#ecfdf5", border: "1px solid #6ee7b7", borderRadius: 8, padding: "6px 14px", marginBottom: 10 },
  row: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(100px, 1fr))", gap: 10, marginBottom: "1.25rem" },
  card: { background: "#fff", border: "1px solid #e8eaf0", borderRadius: 10, padding: "12px 14px" },
  label: { fontSize: 11, color: "#6b7280", marginBottom: 4, fontWeight: 500, textTransform: "uppercase", letterSpacing: ".04em" },
  value: { fontSize: 24, fontWeight: 700, color: "#111" },
};
