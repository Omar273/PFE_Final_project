import { useState } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import Connect from "./components/Connect";
import Dashboard from "./components/Dashboard";
import LLMPage from "./components/LLMPage";
import AgentPage from "./components/AgentPage";
import NavBar from "./components/NavBar";

export default function App() {
  const [config, setConfig] = useState(null);

  return (
    <div style={{ minHeight: "100vh", background: "#f8f9fb", fontFamily: "Inter, system-ui, sans-serif" }}>
      {!config ? (
        <Connect onConnect={setConfig} />
      ) : (
        <>
          <NavBar onDisconnect={() => setConfig(null)} />
          <Routes>
            <Route path="/"          element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard config={config} onDisconnect={() => setConfig(null)} />} />
            <Route path="/llm"       element={<LLMPage config={config} />} />
            <Route path="/agent"     element={<AgentPage />} />
          </Routes>
        </>
      )}
    </div>
  );
}
