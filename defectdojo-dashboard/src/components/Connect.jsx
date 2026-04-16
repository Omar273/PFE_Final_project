import { useState } from "react";
import { checkConnection } from "../services/defectdojoApi";

export default function Connect({ onConnect }) {
  const [token, setToken]     = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState(null);

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);
    const key = token.trim();
    if (!key) { setError("API token is required."); return; }
    setLoading(true);
    try {
      await checkConnection(key);
      onConnect({ token: key });
    } catch (err) {
      setError(`Connection failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={styles.page}>
      <div style={styles.card}>
        <div style={styles.logo}>
          <div style={styles.logoIcon}>DD</div>
          <span style={styles.logoText}>DefectDojo Dashboard</span>
        </div>

        <div style={styles.infoBanner}>
          <span style={styles.infoIcon}>ℹ</span>
          Connecting to <strong>localhost:8080</strong> via Vite proxy.<br />
          Make sure DefectDojo is running locally and <code>npm run dev</code> is active.
        </div>

        <form onSubmit={handleSubmit} style={styles.form}>
          <label style={styles.label}>API Token</label>
          <input
            style={styles.input}
            type="password"
            placeholder="Paste your DefectDojo API v2 token"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            autoFocus
          />

          {error && <div style={styles.error}>{error}</div>}

          <button
            style={{ ...styles.btn, opacity: loading ? 0.7 : 1 }}
            type="submit"
            disabled={loading}
          >
            {loading ? "Connecting…" : "Connect"}
          </button>
        </form>

        <p style={styles.hint}>
          Find your token: <strong>DefectDojo → Profile → API v2 Key</strong>
        </p>
      </div>
    </div>
  );
}

const styles = {
  page: {
    minHeight: "100vh", display: "flex", alignItems: "center",
    justifyContent: "center", background: "#f0f2f5", padding: "2rem",
  },
  card: {
    background: "#fff", borderRadius: 14, padding: "2.5rem",
    width: "100%", maxWidth: 420,
    boxShadow: "0 2px 16px rgba(0,0,0,0.08)", border: "1px solid #e8eaf0",
  },
  logo: { display: "flex", alignItems: "center", gap: 10, marginBottom: "1.5rem" },
  logoIcon: {
    width: 38, height: 38, borderRadius: 9, background: "#1a56db",
    display: "flex", alignItems: "center", justifyContent: "center",
    color: "#fff", fontSize: 13, fontWeight: 600,
  },
  logoText: { fontSize: 18, fontWeight: 600, color: "#111" },
  infoBanner: {
    fontSize: 13, color: "#1e40af", background: "#eff6ff",
    border: "1px solid #bfdbfe", borderRadius: 8,
    padding: "10px 14px", marginBottom: "1.5rem", lineHeight: 1.6,
  },
  infoIcon: { marginRight: 6, fontSize: 14 },
  form: { display: "flex", flexDirection: "column", gap: 12 },
  label: { fontSize: 13, fontWeight: 500, color: "#374151" },
  input: {
    height: 42, padding: "0 12px", fontSize: 14, borderRadius: 8,
    border: "1.5px solid #d1d5db", outline: "none", color: "#111",
  },
  error: {
    fontSize: 13, color: "#b91c1c", background: "#fef2f2",
    border: "1px solid #fca5a5", borderRadius: 7, padding: "8px 12px",
  },
  btn: {
    height: 42, borderRadius: 8, background: "#1a56db", color: "#fff",
    border: "none", fontWeight: 600, fontSize: 15, cursor: "pointer", marginTop: 4,
  },
  hint: { fontSize: 12, color: "#9ca3af", marginTop: "1.25rem", textAlign: "center" },
};

