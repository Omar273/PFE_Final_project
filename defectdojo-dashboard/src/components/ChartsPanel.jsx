import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, CartesianGrid, Legend,
} from "recharts";

const SEV_COLORS = {
  Critical: "#dc2626", High: "#d97706", Medium: "#2563eb", Low: "#16a34a", Info: "#9ca3af",
};

export default function ChartsPanel({ findings }) {
  // ── Severity pie data ───────────────────────────────────────────────────
  const sevCounts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});
  const pieData = Object.entries(sevCounts).map(([name, value]) => ({ name, value }));

  // ── Findings over time (monthly) ────────────────────────────────────────
  const monthMap = {};
  findings.forEach((f) => {
    if (!f.date) return;
    const month = f.date.slice(0, 7);
    monthMap[month] = (monthMap[month] || 0) + 1;
  });
  const timeData = Object.keys(monthMap)
    .sort()
    .slice(-12)
    .map((m) => ({ month: m.slice(5) + "/" + m.slice(2, 4), count: monthMap[m] }));

  // ── Top 8 components by finding count ──────────────────────────────────
  const compMap = {};
  findings.forEach((f) => {
    if (!f.component_name) return;
    if (!compMap[f.component_name]) compMap[f.component_name] = { total: 0, maxSev: 0 };
    compMap[f.component_name].total++;
    const sevOrder = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
    if ((sevOrder[f.severity] || 0) > compMap[f.component_name].maxSev) {
      compMap[f.component_name].maxSev = sevOrder[f.severity] || 0;
      compMap[f.component_name].severity = f.severity;
    }
  });
  const compData = Object.entries(compMap)
    .sort((a, b) => b[1].total - a[1].total)
    .slice(0, 8)
    .map(([name, d]) => ({ name: name.length > 16 ? name.slice(0, 14) + "…" : name, count: d.total, severity: d.severity }));

  return (
    <div style={styles.grid}>
      {/* Severity breakdown */}
      <div style={styles.card}>
        <h3 style={styles.title}>Severity breakdown</h3>
        <div style={styles.legend}>
          {pieData.map((d) => (
            <span key={d.name} style={styles.legItem}>
              <span style={{ ...styles.legDot, background: SEV_COLORS[d.name] || "#ccc" }} />
              {d.name} {d.value}
            </span>
          ))}
        </div>
        <ResponsiveContainer width="100%" height={160}>
          <PieChart>
            <Pie data={pieData} dataKey="value" innerRadius={45} outerRadius={70} paddingAngle={2}>
              {pieData.map((d) => <Cell key={d.name} fill={SEV_COLORS[d.name] || "#ccc"} />)}
            </Pie>
            <Tooltip formatter={(v, n) => [v, n]} />
          </PieChart>
        </ResponsiveContainer>
      </div>

      {/* Findings over time */}
      <div style={styles.card}>
        <h3 style={styles.title}>Findings over time</h3>
        <ResponsiveContainer width="100%" height={190}>
          <LineChart data={timeData} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
            <XAxis dataKey="month" tick={{ fontSize: 11, fill: "#9ca3af" }} />
            <YAxis tick={{ fontSize: 11, fill: "#9ca3af" }} />
            <Tooltip />
            <Line type="monotone" dataKey="count" stroke="#1a56db" strokeWidth={2} dot={{ r: 3 }} name="Findings" />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Top components */}
      <div style={{ ...styles.card, gridColumn: "1 / -1" }}>
        <h3 style={styles.title}>Top components by finding count</h3>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={compData} layout="vertical" margin={{ top: 0, right: 20, left: 20, bottom: 0 }}>
            <XAxis type="number" tick={{ fontSize: 11, fill: "#9ca3af" }} />
            <YAxis type="category" dataKey="name" tick={{ fontSize: 11, fill: "#374151" }} width={120} />
            <Tooltip />
            <Bar dataKey="count" radius={[0, 4, 4, 0]} name="Findings">
              {compData.map((d, i) => (
                <Cell key={i} fill={SEV_COLORS[d.severity] || "#9ca3af"} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

const styles = {
  grid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 12, marginBottom: "1.25rem" },
  card: { background: "#fff", border: "1px solid #e8eaf0", borderRadius: 12, padding: "16px" },
  title: { fontSize: 12, fontWeight: 600, color: "#6b7280", marginBottom: 10, textTransform: "uppercase", letterSpacing: ".04em" },
  legend: { display: "flex", flexWrap: "wrap", gap: 10, marginBottom: 8 },
  legItem: { display: "flex", alignItems: "center", gap: 5, fontSize: 12, color: "#6b7280" },
  legDot: { width: 9, height: 9, borderRadius: 2, flexShrink: 0 },
};
