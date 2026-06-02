"use client";

import { useCallback, useMemo, useState } from "react";
import Link from "next/link";
import { API_BASE, errorMessage } from "../hooks/useScan";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

function Metrics({ metrics }) {
  if (!metrics) return null;
  return (
    <div className="scan-api-metrics" aria-label="Resumen por severidad">
      <span className="metric metric--critical">
        <strong>{metrics.CRITICAL ?? 0}</strong> Críticos
      </span>
      <span className="metric metric--high">
        <strong>{metrics.HIGH ?? 0}</strong> Altos
      </span>
      <span className="metric metric--medium">
        <strong>{metrics.MEDIUM ?? 0}</strong> Medios
      </span>
      <span className="metric metric--low">
        <strong>{metrics.LOW ?? 0}</strong> Bajos
      </span>
    </div>
  );
}

function FindingsTable({ rows, severityFilter }) {
  const filtered = useMemo(() => {
    const list = Array.isArray(rows) ? rows : [];
    if (!severityFilter?.length) return list;
    const set = new Set(severityFilter);
    return list.filter((r) => set.has(r.severity));
  }, [rows, severityFilter]);

  if (!filtered.length) {
    return <p className="hint">Sin hallazgos para los filtros seleccionados.</p>;
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Severidad</th>
            <th>Endpoint</th>
            <th>Hallazgo</th>
            <th>Solución</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((row, i) => (
            <tr key={`${row.severity}-${row.endpoint}-${i}`}>
              <td>
                <span className={`sev-pill sev-${(row.severity || "").toLowerCase()}`}>
                  {row.severity}
                </span>
              </td>
              <td className="cell-url">{row.endpoint}</td>
              <td>{row.finding}</td>
              <td>{row.solution}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ScanApiAuditorView() {
  const [baseUrl, setBaseUrl] = useState("");
  const [collection, setCollection] = useState(null);
  const [fileName, setFileName] = useState("");
  const [error, setError] = useState(null);

  const [staticFindings, setStaticFindings] = useState([]);
  const [staticMetrics, setStaticMetrics] = useState(null);
  const [staticFilter, setStaticFilter] = useState([...SEVERITIES]);

  const [liveFindings, setLiveFindings] = useState([]);
  const [liveMetrics, setLiveMetrics] = useState(null);
  const [liveFilter, setLiveFilter] = useState([...SEVERITIES]);
  const [urlsProbed, setUrlsProbed] = useState(0);

  const [loadingStatic, setLoadingStatic] = useState(false);
  const [loadingLive, setLoadingLive] = useState(false);
  const [loadingPdf, setLoadingPdf] = useState(false);

  const canAnalyze = Boolean(collection && (baseUrl || "").trim().startsWith("http"));

  const handleFile = useCallback(async (e) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    setError(null);
    setStaticFindings([]);
    setStaticMetrics(null);
    setLiveFindings([]);
    setLiveMetrics(null);
    if (!file) {
      setCollection(null);
      setFileName("");
      return;
    }
    try {
      const text = await file.text();
      const data = JSON.parse(text);
      if (!data || typeof data !== "object" || !Array.isArray(data.item)) {
        throw new Error("El JSON debe ser una colección Postman v2.x (con «item»).");
      }
      setCollection(data);
      setFileName(file.name);
    } catch (err) {
      setCollection(null);
      setFileName("");
      setError(err?.message || "JSON inválido");
    }
  }, []);

  async function runStatic() {
    if (!canAnalyze) return;
    setError(null);
    setLoadingStatic(true);
    try {
      const res = await fetch(`${API_BASE}/scan-api/static`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ base_url: baseUrl.trim(), collection }),
      });
      if (!res.ok) throw new Error(await errorMessage(res));
      const data = await res.json();
      setStaticFindings(data.findings || []);
      setStaticMetrics(data.metrics || null);
    } catch (err) {
      setError(err?.message || String(err));
    } finally {
      setLoadingStatic(false);
    }
  }

  async function runLive() {
    if (!canAnalyze) return;
    setError(null);
    setLoadingLive(true);
    try {
      const res = await fetch(`${API_BASE}/scan-api/live`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ base_url: baseUrl.trim(), collection }),
      });
      if (!res.ok) throw new Error(await errorMessage(res));
      const data = await res.json();
      setLiveFindings(data.findings || []);
      setLiveMetrics(data.metrics || null);
      setUrlsProbed(data.urls_probed ?? 0);
    } catch (err) {
      setError(err?.message || String(err));
    } finally {
      setLoadingLive(false);
    }
  }

  async function downloadPdf() {
    setError(null);
    setLoadingPdf(true);
    try {
      const res = await fetch(`${API_BASE}/scan-api/report-pdf`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          static_findings: staticFindings,
          live_findings: liveFindings,
        }),
      });
      if (!res.ok) throw new Error(await errorMessage(res));
      const blob = await res.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "Auditoria_API.pdf";
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (err) {
      setError(err?.message || String(err));
    } finally {
      setLoadingPdf(false);
    }
  }

  function toggleSeverity(setter, value) {
    setter((prev) =>
      prev.includes(value) ? prev.filter((x) => x !== value) : [...prev, value]
    );
  }

  return (
    <main className="app-shell scan-api-shell">
      <section className="topbar">
        <div>
          <p className="eyebrow">Security reports</p>
          <h1>API Security Auditor</h1>
          <p className="subtitle">
            Análisis estático de diseño sobre colección Postman y health check live de cabeceras
            (integrado desde scanApi). Genera PDF con ambos bloques de hallazgos.
          </p>
        </div>
        <div className="topbar-actions">
          <Link className="button secondary" href="/">
            Volver al inicio
          </Link>
        </div>
      </section>

      {error && (
        <div className="alert" role="alert">
          {error}
          <button
            type="button"
            className="alert-dismiss"
            onClick={() => setError(null)}
            aria-label="Cerrar"
          >
            ✕
          </button>
        </div>
      )}

      <section className="panel control-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Entrada</p>
            <h2>Colección Postman</h2>
          </div>
        </div>

        <label className="field">
          <span>URL base real del API</span>
          <input
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="https://api.cliente.com"
            autoComplete="off"
          />
        </label>

        <label className="file-drop file-drop-collection">
          <span>Colección Postman (.json)</span>
          <input type="file" accept=".json,application/json" onChange={handleFile} />
          <small>{fileName || "Exporta Collection v2.1 desde Postman"}</small>
        </label>

        <button
          type="button"
          className="button primary full"
          disabled={!canAnalyze || loadingStatic}
          onClick={runStatic}
        >
          {loadingStatic ? "Analizando diseño…" : "1. Análisis estático (diseño)"}
        </button>
      </section>

      {staticFindings.length > 0 || staticMetrics ? (
        <section className="panel findings-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Estático</p>
              <h2>Hallazgos de diseño</h2>
            </div>
          </div>
          <Metrics metrics={staticMetrics} />
          <div className="severity-filter-row">
            {SEVERITIES.map((s) => (
              <label key={s} className="check-chip compact">
                <input
                  type="checkbox"
                  checked={staticFilter.includes(s)}
                  onChange={() => toggleSeverity(setStaticFilter, s)}
                />
                <span>{s}</span>
              </label>
            ))}
          </div>
          <FindingsTable rows={staticFindings} severityFilter={staticFilter} />
        </section>
      ) : null}

      <section className="panel control-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Live</p>
            <h2>Health check de producción</h2>
          </div>
        </div>
        <p className="hint">
          Hace <strong>GET</strong> a cada URL http(s) de la colección y revisa HSTS, CORS,
          cookies, etc. Solo entornos donde tengas permiso (QA/staging).
        </p>
        <button
          type="button"
          className="button primary full"
          disabled={!canAnalyze || loadingLive}
          onClick={runLive}
        >
          {loadingLive ? "Escaneando servidores…" : "2. Iniciar escaneo live"}
        </button>
        {urlsProbed > 0 && (
          <p className="hint" style={{ marginTop: 8 }}>
            URLs http(s) probadas: <strong>{urlsProbed}</strong>
          </p>
        )}
      </section>

      {liveFindings.length > 0 || liveMetrics ? (
        <section className="panel findings-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Dinámico</p>
              <h2>Hallazgos live</h2>
            </div>
          </div>
          <Metrics metrics={liveMetrics} />
          <div className="severity-filter-row">
            {SEVERITIES.map((s) => (
              <label key={s} className="check-chip compact">
                <input
                  type="checkbox"
                  checked={liveFilter.includes(s)}
                  onChange={() => toggleSeverity(setLiveFilter, s)}
                />
                <span>{s}</span>
              </label>
            ))}
          </div>
          <FindingsTable rows={liveFindings} severityFilter={liveFilter} />
        </section>
      ) : null}

      {(staticFindings.length > 0 || liveFindings.length > 0) && (
        <section className="panel">
          <button
            type="button"
            className="button secondary full"
            disabled={loadingPdf}
            onClick={downloadPdf}
          >
            {loadingPdf ? "Generando PDF…" : "Descargar reporte PDF"}
          </button>
        </section>
      )}
    </main>
  );
}
