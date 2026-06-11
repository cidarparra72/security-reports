import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { API_BASE, errorMessage, publicApiUrl } from "../hooks/useScan";

const DEFAULT_JSON = `[
  { "method": "GET", "path": "/api/health", "params": {} },
  { "method": "GET", "url": "https://httpbin.org/get" }
]`;

const DEFAULT_PATHS = `GET /api/health
GET /v1/status`;

/** Evita timeouts del proxy Next→FastAPI con muchos endpoints en una sola petición. */
const PROBE_BATCH_SIZE = 12;

function mergeProbeReports(chunks) {
  if (!chunks?.length) return null;
  if (chunks.length === 1) return chunks[0];
  const allResults = chunks.flatMap((c) => c.results || []);
  const allTable = chunks.flatMap((c) => c.table || []);
  const errors = allResults.filter((r) => r?.result?.error).length;
  const ok = allResults.filter(
    (r) =>
      !r?.result?.error &&
      typeof r?.result?.status_code === "number" &&
      r.result.status_code >= 200 &&
      r.result.status_code < 400
  ).length;
  const latencies = allResults
    .map((r) => r?.result?.elapsed_ms)
    .filter((n) => typeof n === "number");
  const avg =
    latencies.length > 0
      ? Math.round((latencies.reduce((a, b) => a + b, 0) / latencies.length) * 100) / 100
      : null;
  return {
    generated_at: chunks[chunks.length - 1].generated_at,
    summary: {
      total_probed: allResults.length,
      with_error: errors,
      http_2xx_or_3xx: ok,
      avg_elapsed_ms: avg,
    },
    table: allTable,
    results: allResults,
  };
}

function chunkIndices(indices, size) {
  const out = [];
  for (let i = 0; i < indices.length; i += size) {
    out.push(indices.slice(i, i + size));
  }
  return out;
}

export function EndpointProbeView() {
  const [inputMode, setInputMode] = useState("json"); // json | base_url
  const [jsonText, setJsonText] = useState(DEFAULT_JSON);
  const [baseUrl, setBaseUrl] = useState("https://httpbin.org");
  const [pathsText, setPathsText] = useState(DEFAULT_PATHS);
  const [timeoutSec, setTimeoutSec] = useState(15);

  const [endpoints, setEndpoints] = useState([]);
  const [prepareErrors, setPrepareErrors] = useState([]);
  const [selected, setSelected] = useState(() => new Set());
  const [preparing, setPreparing] = useState(false);
  const [running, setRunning] = useState(false);
  const [runProgress, setRunProgress] = useState({ done: 0, total: 0 });
  const [error, setError] = useState(null);
  const [report, setReport] = useState(null);
  const [jsonFileHint, setJsonFileHint] = useState(null);
  const [zapSpiderMinutes, setZapSpiderMinutes] = useState(2);
  const [zapLoading, setZapLoading] = useState(false);
  const [zapResult, setZapResult] = useState(null);

  const allSelected = useMemo(
    () => endpoints.length > 0 && selected.size === endpoints.length,
    [endpoints.length, selected.size]
  );

  const toggleOne = useCallback((idx) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  }, []);

  const selectAll = useCallback(() => {
    setSelected(new Set(endpoints.map((_, i) => i)));
  }, [endpoints]);

  const selectNone = useCallback(() => {
    setSelected(new Set());
  }, []);

  useEffect(() => {
    if (!report) return;
    document.getElementById("probe-http-report")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [report]);

  useEffect(() => {
    if (!zapResult) return;
    document.getElementById("probe-zap-report")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [zapResult]);

  const handleJsonFilePick = useCallback(async (e) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    setError(null);
    try {
      const text = await file.text();
      JSON.parse(text);
      setJsonText(text);
      setInputMode("json");
      setJsonFileHint(file.name);
      setEndpoints([]);
      setSelected(new Set());
      setReport(null);
      setPrepareErrors([]);
    } catch {
      setError(`El archivo «${file.name}» no es JSON válido.`);
      setJsonFileHint(null);
    }
  }, []);

  async function handlePrepare() {
    setError(null);
    setReport(null);
    setPreparing(true);
    setPrepareErrors([]);
    try {
      const body =
        inputMode === "json"
          ? { mode: "json", json_text: jsonText, base_url: baseUrl.trim() || null }
          : { mode: "base_url", base_url: baseUrl.trim(), paths_text: pathsText };

      const res = await fetch(`${API_BASE}/api-probe/prepare`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(await errorMessage(res));
      const data = await res.json();
      const eps = Array.isArray(data.endpoints) ? data.endpoints : [];
      const pErr = Array.isArray(data.parse_errors) ? data.parse_errors : [];
      const nErr = Array.isArray(data.normalize_errors) ? data.normalize_errors : [];
      setEndpoints(eps);
      setPrepareErrors([...pErr, ...nErr]);
      setSelected(new Set(eps.map((_, i) => i)));
      if (!eps.length) {
        const msgs = [...pErr, ...nErr].filter(Boolean);
        setError(
          msgs.length
            ? `No se pudo listar endpoints:\n${msgs.join("\n")}`
            : "No quedó ningún endpoint válido. Si el JSON es OpenAPI/Postman, debe incluir paths o requests; si usas solo path, indica la URL base."
        );
      }
    } catch (e) {
      setError(e?.message || String(e));
    } finally {
      setPreparing(false);
    }
  }

  async function handleRunSelected() {
    if (!endpoints.length) {
      setError("Primero pulsa «Armar endpoints».");
      return;
    }
    const indices = [...selected].sort((a, b) => a - b);
    if (!indices.length) {
      setError("Selecciona al menos un endpoint.");
      return;
    }
    setError(null);
    setRunning(true);
    setRunProgress({ done: 0, total: indices.length });
    const batches = chunkIndices(indices, PROBE_BATCH_SIZE);
    const mergedChunks = [];
    let doneCount = 0;
    try {
      for (let b = 0; b < batches.length; b++) {
        const batch = batches[b];
        const res = await fetch(`${API_BASE}/api-probe/run`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            endpoints,
            timeout_sec: timeoutSec,
            indices: batch,
          }),
        });
        if (!res.ok) {
          const detail = await errorMessage(res);
          if (res.status === 500 || detail === "Internal Server Error") {
            throw new Error(
              `El lote ${b + 1}/${batches.length} falló (timeout del servidor). ` +
                `Prueba con menos endpoints seleccionados o baja el timeout (ahora ${timeoutSec}s).`
            );
          }
          throw new Error(detail);
        }
        mergedChunks.push(await res.json());
        doneCount += batch.length;
        setRunProgress({ done: doneCount, total: indices.length });
      }
      const payload = mergeProbeReports(mergedChunks);
      setReport(payload);
      const rowCount = (payload?.results || payload?.table || []).length;
      if (!rowCount) {
        setError(
          "No se obtuvo ninguna fila de análisis (¿índices fuera de rango o lista vacía?). Revisa endpoints y selección."
        );
      }
    } catch (e) {
      const msg = e?.message || String(e);
      if (mergedChunks.length > 0) {
        setReport(mergeProbeReports(mergedChunks));
        setError(
          `${msg} Se muestran los ${mergedChunks.flatMap((c) => c.results || []).length} endpoints analizados antes del fallo.`
        );
      } else {
        setError(
          msg === "Failed to fetch" || msg.includes("NetworkError")
            ? "No hay conexión con el API o la petición tardó demasiado. El análisis de muchos endpoints se hace por lotes; comprueba que el backend (:8000) siga en marcha."
            : msg
        );
      }
    } finally {
      setRunning(false);
      setRunProgress({ done: 0, total: 0 });
    }
  }

  async function handleZapBaseline() {
    if (!endpoints.length) {
      setError("Primero pulsa «Armar endpoints».");
      return;
    }
    const indices = [...selected].sort((a, b) => a - b);
    if (!indices.length) {
      setError("Selecciona al menos un endpoint para ZAP.");
      return;
    }
    if (indices.length > 20) {
      setError("ZAP permite como máximo 20 endpoints por lote (reduce la selección).");
      return;
    }
    setError(null);
    setZapLoading(true);
    setZapResult(null);
    try {
      const res = await fetch(`${API_BASE}/api-probe/zap-baseline`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          endpoints,
          indices,
          spider_minutes: zapSpiderMinutes,
          ignore_info: true,
        }),
      });
      if (!res.ok) throw new Error(await errorMessage(res));
      setZapResult(await res.json());
    } catch (e) {
      setError(e?.message || String(e));
    } finally {
      setZapLoading(false);
    }
  }

  function downloadReportJson() {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `api-probe-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  return (
    <main className="app-shell">
      <section className="topbar">
        <div>
          <p className="eyebrow">Security reports</p>
          <h1>Probe de endpoints HTTP</h1>
          <p className="subtitle">
            Define endpoints con JSON o con una URL base y rutas; normaliza, selecciona y ejecuta
            peticiones con métricas y reporte consolidado.
          </p>
        </div>
        <div className="topbar-actions">
          <Link className="button secondary" href="/historial">
            Historial
          </Link>
          <Link className="button secondary" href="/">
            Volver al inicio
          </Link>
        </div>
      </section>

      <details className="panel probe-help">
        <summary>Cómo analizar y ver el informe (backend + front)</summary>
        <ol className="probe-help-list">
          <li>
            Backend en <strong>8000</strong>: <code>python server.py</code> o{" "}
            <code>python -m uvicorn server:app --host 127.0.0.1 --port 8000</code>
          </li>
          <li>
            Front (esta UI): en <code>client/</code> ejecuta <code>npm run dev</code> y abre la URL que muestre
            la terminal (p. ej. <code>http://localhost:3000</code>), luego entra en <strong>/probe</strong>.
          </li>
          <li>
            Pulsa <strong>Armar endpoints</strong> y después <strong>Analizar seleccionados</strong>.
            El informe aparece <strong>más abajo</strong> en «Resultados»; usa <strong>Descargar JSON</strong> para
            guardarlo.
          </li>
          <li>
            Informes ZAP y estáticos: el backend expone{" "}
            <code>http://127.0.0.1:8000/reports/&lt;carpeta&gt;/&lt;archivo&gt;</code>. Desde esta página los
            enlaces usan la misma ruta; si fallan, cópiala en el navegador apuntando al puerto 8000.
          </li>
        </ol>
      </details>

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

      <div className="probe-layout">
        <section className="panel control-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Entrada</p>
              <h2>Origen de endpoints</h2>
            </div>
          </div>

          <div className="json-base-url-block" id="probe-url-base-api">
            <p className="json-base-url-title">URL base — une todas las rutas del JSON</p>
            <p className="hint" style={{ marginTop: 0, marginBottom: 10 }}>
              Con Postman (<code>{"{{base_url}}"}</code>) o ítems con <code>path</code> relativo, este campo es{" "}
              <strong>obligatorio</strong> antes de pulsar «Armar endpoints».
            </p>
            <label className="field">
              <span>
                <strong>https://…</strong> (ej. <code>https://api.taxislibres.com.co</code>)
              </span>
              <input
                id="probe-base-url-input"
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder="https://api.ejemplo.com"
                autoComplete="off"
              />
            </label>
          </div>

          <div className="field-row probe-mode-row">
            <label className="radio-inline">
              <input
                type="radio"
                name="probe_in"
                checked={inputMode === "json"}
                onChange={() => setInputMode("json")}
              />
              JSON de endpoints
            </label>
            <label className="radio-inline">
              <input
                type="radio"
                name="probe_in"
                checked={inputMode === "base_url"}
                onChange={() => setInputMode("base_url")}
              />
              URL base + rutas
            </label>
          </div>

          {inputMode === "json" ? (
            <>
              <label className="file-drop file-drop-collection">
                <span>Cargar JSON desde archivo</span>
                <input
                  type="file"
                  accept=".json,application/json"
                  onChange={handleJsonFilePick}
                />
                <small>
                  {jsonFileHint
                    ? `Cargado: ${jsonFileHint} (también puedes editar el texto abajo)`
                    : "Elige un .json con un array de endpoints o { \"endpoints\": [...] }"}
                </small>
              </label>
              <label className="field">
                <span>JSON (array o objeto con &quot;endpoints&quot;)</span>
                <textarea
                  className="code-area"
                  rows={12}
                  value={jsonText}
                  onChange={(e) => {
                    setJsonText(e.target.value);
                    setJsonFileHint(null);
                  }}
                  spellCheck={false}
                />
              </label>
            </>
          ) : (
            <label className="field">
              <span>Rutas (una por línea: <code>GET /api/x</code> o <code>/api/x</code> → GET)</span>
              <textarea
                className="code-area"
                rows={10}
                value={pathsText}
                onChange={(e) => setPathsText(e.target.value)}
                spellCheck={false}
              />
            </label>
          )}

          <label className="field">
            <span>Timeout por petición (segundos)</span>
            <input
              type="number"
              min={1}
              max={120}
              value={timeoutSec}
              onChange={(e) => setTimeoutSec(Number(e.target.value) || 15)}
            />
          </label>

          <div className="endpoint-toolbar arm-endpoints">
            <button
              type="button"
              className="button primary full"
              disabled={preparing}
              onClick={handlePrepare}
            >
              {preparing ? "Armando endpoints…" : "Armar endpoints"}
            </button>
            <span>
              Usa la URL base (https://…) arriba y el JSON o las rutas; este botón construye la lista para probar o ZAP.
            </span>
          </div>

          {prepareErrors.length > 0 && (
            <div className="hint probe-warnings">
              <strong>Avisos:</strong>
              <ul>
                {prepareErrors.map((msg, i) => (
                  <li key={i}>{msg}</li>
                ))}
              </ul>
            </div>
          )}
        </section>

        <section className="panel control-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Selección</p>
              <h2>Endpoints ({endpoints.length})</h2>
            </div>
            <div className="endpoint-toolbar compact">
              <button type="button" className="button secondary" onClick={selectAll} disabled={!endpoints.length}>
                Todos
              </button>
              <button type="button" className="button secondary" onClick={selectNone} disabled={!endpoints.length}>
                Ninguno
              </button>
              <label className="checkbox-inline">
                <input
                  type="checkbox"
                  checked={allSelected}
                  disabled={!endpoints.length}
                  onChange={() => (allSelected ? selectNone() : selectAll())}
                />
                Alternar todos
              </label>
            </div>
          </div>

          <div className="probe-endpoint-list">
            {endpoints.length === 0 ? (
              <p className="hint">Los endpoints aparecerán aquí tras «Armar endpoints».</p>
            ) : (
              <ul>
                {endpoints.map((ep, idx) => (
                  <li key={`${ep.url}-${idx}`} className="probe-endpoint-item">
                    <label className="checkbox-row">
                      <input
                        type="checkbox"
                        checked={selected.has(idx)}
                        onChange={() => toggleOne(idx)}
                      />
                      <span className="method-tag">{ep.method}</span>
                      <span className="url-text">{ep.url}</span>
                      {ep.params && Object.keys(ep.params).length > 0 && (
                        <span className="params-hint" title={JSON.stringify(ep.params)}>
                          params
                        </span>
                      )}
                    </label>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {selected.size > PROBE_BATCH_SIZE && !running && (
            <p className="hint" role="note">
              {selected.size} seleccionados: se analizarán en lotes de {PROBE_BATCH_SIZE} para evitar timeout.
            </p>
          )}
          {running && runProgress.total > 0 && (
            <p className="hint probe-seq-progress" role="status">
              Progreso: {runProgress.done} / {runProgress.total} endpoints…
            </p>
          )}
          <button
            type="button"
            className="button primary probe-run-btn"
            disabled={running || !endpoints.length || selected.size === 0}
            onClick={handleRunSelected}
          >
            {running
              ? runProgress.total > 0
                ? `Analizando ${runProgress.done}/${runProgress.total}…`
                : "Analizando…"
              : "Analizar seleccionados"}
          </button>

          <div className="probe-zap-block">
            <p className="eyebrow" style={{ marginTop: 18 }}>
              OWASP ZAP (Docker)
            </p>
            <p className="hint" style={{ margin: "6px 0 10px" }}>
              Un <strong>baseline</strong> por cada endpoint <strong>seleccionado</strong> (orden secuencial).
              Requiere Docker con la imagen <code>owasp/zap2docker-stable</code>. Puede tardar varios minutos por URL.
            </p>
            <label className="field">
              <span>Minutos de spider por URL (-m de zap-baseline)</span>
              <input
                type="number"
                min={1}
                max={15}
                value={zapSpiderMinutes}
                onChange={(e) => setZapSpiderMinutes(Number(e.target.value) || 2)}
              />
            </label>
            <button
              type="button"
              className="button secondary probe-run-btn"
              disabled={zapLoading || !endpoints.length || selected.size === 0}
              onClick={handleZapBaseline}
            >
              {zapLoading ? "Ejecutando ZAP…" : "Generar informes ZAP (seleccionados)"}
            </button>
          </div>
        </section>
      </div>

      {zapResult && (
        <section id="probe-zap-report" className="panel findings-panel probe-results">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">ZAP baseline</p>
              <h2>Informes por endpoint (job {zapResult.job_id})</h2>
            </div>
          </div>
          {zapResult.hint && <p className="hint">{zapResult.hint}</p>}
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Método</th>
                  <th>URL</th>
                  <th>Código</th>
                  <th>JSON</th>
                  <th>HTML</th>
                  <th>Nota</th>
                </tr>
              </thead>
              <tbody>
                {(zapResult.results || []).map((row) => (
                  <tr key={row.index}>
                    <td>{row.index}</td>
                    <td>{row.method ?? "—"}</td>
                    <td className="cell-url">{row.url ?? "—"}</td>
                    <td>{row.exit_code ?? "—"}</td>
                    <td>
                      {row.json_url ? (
                        <a href={publicApiUrl(row.json_url)} target="_blank" rel="noreferrer">
                          Descargar
                        </a>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>
                      {row.html_url ? (
                        <a href={publicApiUrl(row.html_url)} target="_blank" rel="noreferrer">
                          Abrir
                        </a>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="cell-error">{row.error || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {report && (
        <section id="probe-http-report" className="panel findings-panel probe-results">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Reporte</p>
              <h2>Resultados del análisis HTTP</h2>
            </div>
            <button type="button" className="button secondary" onClick={downloadReportJson}>
              Descargar JSON
            </button>
          </div>

          {report.summary && (
            <div className="probe-summary">
              <span>Probadas: <strong>{report.summary.total_probed}</strong></span>
              <span>Errores red/timeout: <strong>{report.summary.with_error}</strong></span>
              <span>2xx/3xx: <strong>{report.summary.http_2xx_or_3xx}</strong></span>
              <span>
                Latencia media:{" "}
                <strong>
                  {report.summary.avg_elapsed_ms != null ? `${report.summary.avg_elapsed_ms} ms` : "—"}
                </strong>
              </span>
            </div>
          )}

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Método</th>
                  <th>URL</th>
                  <th>Status</th>
                  <th>ms</th>
                  <th>Error</th>
                </tr>
              </thead>
              <tbody>
                {(report.table || []).map((row) => (
                  <tr key={row.index}>
                    <td>{row.index}</td>
                    <td>{row.method}</td>
                    <td className="cell-url">{row.url}</td>
                    <td>{row.status_code ?? "—"}</td>
                    <td>{row.elapsed_ms ?? "—"}</td>
                    <td className="cell-error">{row.error || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <h3 className="probe-detail-title">Detalle por endpoint</h3>
          <div className="probe-detail-grid">
            {(report.results || []).map((row) => {
              const r = row.result || {};
              return (
                <article key={row.index} className="panel probe-detail-card">
                  <header>
                    <span className="method-tag">{row.endpoint?.method}</span>
                    <code>{row.endpoint?.url}</code>
                  </header>
                  {r.error ? (
                    <p className="cell-error">{r.error}</p>
                  ) : (
                    <>
                      <p>
                        <strong>Status:</strong> {r.status_code} · <strong>Tiempo:</strong>{" "}
                        {r.elapsed_ms} ms
                        {r.body_truncated ? " · cuerpo truncado" : ""}
                      </p>
                      <details>
                        <summary>Vista previa del cuerpo</summary>
                        <pre className="body-preview">{r.body_preview || "(vacío)"}</pre>
                      </details>
                      {Array.isArray(r.validations) && r.validations.length > 0 && (
                        <details open>
                          <summary>Validaciones</summary>
                          <ul>
                            {r.validations.map((v, i) => (
                              <li key={i}>
                                {v.name}: {v.ok ? "✓" : "✗"} {v.detail || ""}
                              </li>
                            ))}
                          </ul>
                        </details>
                      )}
                      {Array.isArray(r.hints) && r.hints.length > 0 && (
                        <details>
                          <summary>Pistas (heurísticas)</summary>
                          <ul>
                            {r.hints.map((h, i) => (
                              <li key={i}>
                                <strong>{h.severity}</strong> — {h.title}: {h.detail}
                              </li>
                            ))}
                          </ul>
                        </details>
                      )}
                    </>
                  )}
                </article>
              );
            })}
          </div>
        </section>
      )}
    </main>
  );
}
