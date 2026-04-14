import { useState, useEffect, useCallback } from "react";
import { fetchFindings, fetchProducts } from "../services/defectdojoApi";

const SEVERITY_ORDER = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };

export function useFindings(config) {
  const [findings, setFindings]       = useState([]);
  const [products, setProducts]       = useState([]);
  const [loading, setLoading]         = useState(false);
  const [error, setError]             = useState(null);
  const [lastFetched, setLastFetched] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [data, prods] = await Promise.all([
        fetchFindings(config.token),
        fetchProducts(config.token),
      ]);
      setFindings(data);
      setProducts(prods);
      setLastFetched(new Date());
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [config.token]);

  useEffect(() => { load(); }, [load]);

  return { findings, products, loading, error, lastFetched, reload: load };
}

// ── Client-side filter + sort ─────────────────────────────────────────────────
export function useFilteredFindings(findings, clientFilters) {
  const { search, severity, status, component, sortBy } = clientFilters;

  const filtered = findings.filter((f) => {
    if (search) {
      const q = search.toLowerCase();
      if (
        !f.title.toLowerCase().includes(q) &&
        !f.component_name.toLowerCase().includes(q) &&
        !(f.cve || "").toLowerCase().includes(q)
      ) return false;
    }
    if (severity  && f.severity !== severity)   return false;
    if (component && f.component_name !== component) return false;
    if (status === "active"   && !f.active)          return false;
    if (status === "verified" && !f.verified)         return false;
    if (status === "fp"       && !f.false_positive)   return false;
    if (status === "dup"      && !f.duplicate)        return false;
    return true;
  });

  filtered.sort((a, b) => {
    switch (sortBy) {
      case "sev":  return (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0);
      case "cvss": return (b.cvss_score || 0) - (a.cvss_score || 0);
      case "risk": return b.risk_score - a.risk_score;
      case "date": return (b.date || "").localeCompare(a.date || "");
      case "comp": return (a.component_name || "").localeCompare(b.component_name || "");
      default:     return 0;
    }
  });

  return filtered;
}

