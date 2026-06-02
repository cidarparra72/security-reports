import { useMemo, useState } from "react";
import { SEVERITIES } from "../hooks/useScan";

export function FindingsTable({ rows }) {
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [query, setQuery] = useState("");

  const filteredRows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return rows.filter((v) => {
      const matchesSeverity = severityFilter === "ALL" || v.severity === severityFilter;
      const haystack = `${v.title ?? ""} ${v.category ?? ""} ${v.file ?? ""} ${v.recommendation ?? ""} ${v.endpoint ?? ""} ${v.api_url ?? ""} ${v.cwe_id ?? ""}`.toLowerCase();
      return matchesSeverity && (!q || haystack.includes(q));
    });
  }, [rows, severityFilter, query]);

  return (
    <section className="panel findings-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Hallazgos</p>
          <h2>Detalle técnico</h2>
        </div>
        <div className="table-tools">
          <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
            <option value="ALL">Todas</option>
            {SEVERITIES.map((sev) => <option key={sev} value={sev}>{sev}</option>)}
          </select>
          <input value={query} onChange={(e) => setQuery(e.target.value)}
            placeholder="Buscar título, archivo o recomendación" />
        </div>
      </div>

      {filteredRows.length > 0 ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Severidad</th>
                <th>Hallazgo</th>
                <th>Endpoint</th>
                <th>API URL</th>
                <th>CWE</th>
              </tr>
            </thead>
            <tbody>
              {filteredRows.map((v, i) => (
                <tr key={`${v.endpoint}-${v.api_url}-${v.title}-${i}`}>
                  <td>
                    <span className={`severity-badge ${(v.severity || "low").toLowerCase()}`}>
                      {v.severity}
                    </span>
                    {v.confidence === "low" && (
                      <span title="Posible falso positivo — revisar manualmente"
                        style={{ marginLeft: 6, fontSize: "0.72rem", color: "#b7860b" }}>⚠ FP?</span>
                    )}
                  </td>
                  <td>
                    <strong>{v.title}</strong>
                    <p>{v.category}</p>
                    {v.false_positive_note && (
                      <p style={{ color: "#9a7500", fontSize: "0.78rem", marginTop: 4 }}>
                        {v.false_positive_note}
                      </p>
                    )}
                  </td>
                  <td className="mono-cell">{v.endpoint || "N/A"}</td>
                  <td className="mono-cell">{v.api_url || "N/A"}</td>
                  <td>
                    {v.cwe_id ? (
                      <a href={`https://cwe.mitre.org/data/definitions/${v.cwe_id.replace("CWE-","")}.html`}
                        target="_blank" rel="noreferrer"
                        style={{ fontSize: "0.78rem", color: "#2980b9" }}>
                        {v.cwe_id}
                      </a>
                    ) : "N/A"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty-state wide">
          {rows.length ? "No hay hallazgos con esos filtros." : "Ejecuta un scan para ver hallazgos."}
        </div>
      )}
    </section>
  );
}
