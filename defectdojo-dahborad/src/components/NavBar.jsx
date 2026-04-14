import { NavLink } from "react-router-dom";

export default function NavBar({ onDisconnect }) {
  return (
    <nav style={styles.nav}>
      <div style={styles.inner}>
        {/* Logo */}
        <div style={styles.logo}>
          <div style={styles.logoIcon}>DD</div>
          <span style={styles.logoText}>DefectDojo</span>
        </div>

        {/* Nav Links */}
        <div style={styles.links}>
          <NavLink
            to="/dashboard"
            style={({ isActive }) => ({
              ...styles.link,
              ...(isActive ? styles.linkActive : {}),
            })}
          >
            <span style={styles.linkIcon}>📊</span>
            Dashboard
          </NavLink>

          <NavLink
            to="/llm"
            style={({ isActive }) => ({
              ...styles.link,
              ...(isActive ? styles.linkActive : {}),
            })}
          >
            <span style={styles.linkIcon}>🤖</span>
            LLM Analyzer
          </NavLink>

          <NavLink
            to="/agent"
            style={({ isActive }) => ({
              ...styles.link,
              ...(isActive ? styles.linkActive : {}),
            })}
          >
            <span style={styles.linkIcon}>🛡️</span>
            AI Agent
          </NavLink>
        </div>

        {/* Disconnect */}
        <button style={styles.disconnectBtn} onClick={onDisconnect}>
          Disconnect
        </button>
      </div>
    </nav>
  );
}

const styles = {
  nav: {
    background: "#fff",
    borderBottom: "1px solid #e8eaf0",
    position: "sticky",
    top: 0,
    zIndex: 100,
    boxShadow: "0 1px 6px rgba(0,0,0,0.05)",
  },
  inner: {
    maxWidth: 1400,
    margin: "0 auto",
    padding: "0 1.5rem",
    height: 56,
    display: "flex",
    alignItems: "center",
    gap: 24,
  },
  logo: {
    display: "flex",
    alignItems: "center",
    gap: 10,
    marginRight: 8,
    flexShrink: 0,
  },
  logoIcon: {
    width: 32,
    height: 32,
    borderRadius: 8,
    background: "#1a56db",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    color: "#fff",
    fontSize: 12,
    fontWeight: 700,
  },
  logoText: {
    fontSize: 15,
    fontWeight: 700,
    color: "#111",
  },
  links: {
    display: "flex",
    alignItems: "center",
    gap: 4,
    flex: 1,
  },
  link: {
    display: "flex",
    alignItems: "center",
    gap: 6,
    height: 36,
    padding: "0 14px",
    borderRadius: 8,
    fontSize: 14,
    fontWeight: 500,
    color: "#6b7280",
    textDecoration: "none",
    transition: "all 0.15s",
  },
  linkActive: {
    background: "#eff6ff",
    color: "#1a56db",
    fontWeight: 600,
  },
  linkIcon: {
    fontSize: 15,
  },
  disconnectBtn: {
    height: 32,
    padding: "0 12px",
    fontSize: 13,
    borderRadius: 7,
    border: "1.5px solid #fca5a5",
    background: "#fef2f2",
    color: "#991b1b",
    cursor: "pointer",
    marginLeft: "auto",
    flexShrink: 0,
  },
};
