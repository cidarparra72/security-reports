import { useEffect, useRef, useState } from "react";
import {
  API_BASE,
  errorMessage,
  publicApiUrl,
  SEVERITIES,
  totalFromSummary,
} from "../hooks/useScan";

function statusLabel(st) {
  if (st === "completed") return "OK";
  if (st === "skipped") return "Omitido";
  if (st === "failed") return "Falló";
  if (st === "timeout") return "Timeout";
  if (st === "manual_required") return "Manual";
  return st || "—";
}

export function ResultsPanel({
  lastScanId,
  loading,
  summary,
  dynamicInfo,
  externalImport,
  zapBaselineInfo,
  selectedEndpoints,
  scanInsight,
  codeOnly = false,
}) {
  const [reportLoading, setReportLoading] = useState(false);
  const [reportUrl, setReportUrl] = useState("");
  const [reportPdfUrl, setReportPdfUrl] = useState("");
  const [pdfWarning, setPdfWarning] = useState(null);
  const [error, setError] = useState(null);
  const prevLoadingRef = useRef(loading);

  useEffect(() => {
    if (prevLoadingRef.current && !loading && lastScanId) {
      document.getElementById("scan-results-panel")?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }
    prevLoadingRef.current = loading;
  }, [loading, lastScanId]);

  const total = totalFromSummary(summary);
  const canReport = Boolean(lastScanId) && !loading && !reportLoading;

  async function requestReport() {
    if (!lastScanId) return null;
    const res = await fetch(`${API_BASE}/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_id: lastScanId }),
    });
    if (!res.ok) throw new Error(await errorMessage(res));
    const data = await res.json();
    setPdfWarning(data.pdf_error || null);
    const url = publicApiUrl(data.report_url);
    const pdfUrl = data.report_pdf_url ? publicApiUrl(data.report_pdf_url) : "";
    setReportUrl(url);
    setReportPdfUrl(pdfUrl);
    return { url, pdfUrl, pdfError: data.pdf_error };
  }

  async function handleOpenReport() {
    setError(null); setReportLoading(true);
    try {
      const report = await requestReport();
      if (!report?.url) {
        setError("El servidor no devolvió URL de informe.");
        return;
      }
      const w = window.open(report.url, "_blank", "noopener,noreferrer");
      if (!w) {
        const a = document.createElement("a");
        a.href = report.url;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        document.body.appendChild(a);
        a.click();
        a.remove();
        setError(
          "El navegador bloqueó la ventana emergente. Usa el enlace «Abrir reporte HTML» debajo o «Descargar HTML»."
        );
      }
    } catch (err) { setError(err?.message || String(err)); }
    finally { setReportLoading(false); }
  }

  async function handleDownloadReport() {
    setError(null); setReportLoading(true);
    try {
      const report = await requestReport();
      if (!report?.url) return;
      const htmlRes = await fetch(report.url);
      if (!htmlRes.ok) throw new Error("No se pudo descargar el informe HTML");
      const blob = await htmlRes.blob();
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = blobUrl; a.download = `retest-report-${lastScanId}.html`;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(blobUrl);
    } catch (err) { setError(err?.message || String(err)); }
    finally { setReportLoading(false); }
  }

  async function handleDownloadPdf() {
    setError(null); setReportLoading(true);
    try {
      const report = reportPdfUrl ? { pdfUrl: reportPdfUrl } : await requestReport();
      if (!report?.pdfUrl) {
        throw new Error(
          report?.pdfError ||
            pdfWarning ||
            "El PDF no se generó (revisa dependencias reportlab y la consola del backend). El HTML sí debería estar disponible."
        );
      }
      const a = document.createElement("a");
      a.href = report.pdfUrl; a.download = `retest-report-${lastScanId}.pdf`;
      document.body.appendChild(a); a.click(); a.remove();
    } catch (err) { setError(err?.message || String(err)); }
    finally { setReportLoading(false); }
  }

  const zapHtmlHref =
    lastScanId && zapBaselineInfo?.html_report
      ? publicApiUrl(
          `/scan/${lastScanId}/artifact/${encodeURIComponent(zapBaselineInfo.html_report)}`
        )
      : "";
  const zapJsonHref =
    lastScanId && zapBaselineInfo?.json_report
      ? publicApiUrl(
          `/scan/${lastScanId}/artifact/${encodeURIComponent(zapBaselineInfo.json_report)}`
        )
      : "";

  const jsMeta = scanInsight?.js_code_analysis_meta ?? null;
  const jsMetaActive = jsMeta && jsMeta.enabled !== false;

  return (
    <section id="scan-results-panel" className="panel results-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Resultado</p>
          <h2>Resumen</h2>
        </div>
        <span className="total-pill">{total} hallazgos</span>
      </div>

      <p className="hint" style={{ marginTop: 0 }}>
        {codeOnly ? (
          <>
            Resumen del análisis de <strong>código</strong> (patrones SAST, análisis JS por función y herramientas externas).
            La tabla inferior lista cada hallazgo con archivo, línea y función. Usa <strong>Ver HTML</strong> /{" "}
            <strong>Descargar PDF</strong> para el informe completo.
          </>
        ) : (
          <>
            Aquí está el resumen del último análisis. Usa <strong>Ver HTML</strong> / <strong>Descargar PDF</strong> para el
            informe ejecutivo (incluye SAST, endpoints y hallazgos).
            {zapBaselineInfo?.enabled
              ? " Si activaste ZAP baseline, abajo tienes el informe nativo de ZAP."
              : ""}
          </>
        )}
      </p>

      {(zapBaselineInfo?.html_report || zapBaselineInfo?.json_report) && lastScanId && (
        <div className="analysis-box" style={{ marginTop: 12 }}>
          <span>Informe OWASP ZAP (esta corrida)</span>
          <p className="hint" style={{ margin: "8px 0 0" }}>
            Archivos generados en el proyecto escaneado; se sirven por el backend:
          </p>
          <p className="link-row" style={{ marginTop: 8 }}>
            {zapHtmlHref && (
              <a href={zapHtmlHref} target="_blank" rel="noreferrer">
                Abrir informe ZAP (HTML)
              </a>
            )}
            {zapJsonHref && (
              <a href={zapJsonHref} target="_blank" rel="noreferrer">
                Abrir JSON ZAP
              </a>
            )}
          </p>
        </div>
      )}

      <div className="summary-grid">
        {SEVERITIES.map((sev) => (
          <div key={sev} className={`severity-card ${sev.toLowerCase()}`}>
            <span>{sev}</span>
            <strong>{summary?.[sev] ?? 0}</strong>
          </div>
        ))}
      </div>

      <div className="meta-list">
        {!codeOnly && (
          <>
            <div>
              <span>API dinámica</span>
              <strong>
                {dynamicInfo ? `${dynamicInfo.url}${dynamicInfo.inferred ? " (inferida)" : ""}` : "Sin ejecutar"}
              </strong>
            </div>
            <div>
              <span>Importaciones</span>
              <strong>
                ZAP {externalImport?.zap ?? 0} / Burp {externalImport?.burp ?? 0} / Manual{" "}
                {externalImport?.manual ?? 0}
              </strong>
            </div>
            <div>
              <span>ZAP baseline</span>
              <strong>{zapBaselineInfo?.enabled ? "Ejecutado" : "No ejecutado"}</strong>
            </div>
          </>
        )}
        {scanInsight?.project_tests != null && (
          <div>
            <span>Tests del repo</span>
            <strong>
              {(() => {
                const pt = scanInsight.project_tests;
                if (!pt || typeof pt !== "object") return "—";
                const st = String(pt.status || "");
                const lab = statusLabel(st);
                if (pt.junit && typeof pt.junit === "object") {
                  const j = pt.junit;
                  return `${lab} — ${j.tests ?? 0} tests (${j.failures ?? 0} fallos, ${j.errors ?? 0} err.)`;
                }
                if (pt.parsed_passed != null) return `${lab} — ~${pt.parsed_passed} passed`;
                return lab;
              })()}
            </strong>
          </div>
        )}
        {!codeOnly && (
          <div>
            <span>Endpoints</span>
            <strong>{selectedEndpoints.length} seleccionados para el análisis</strong>
          </div>
        )}
        {scanInsight?.endpoint_report_meta?.report_lists_full_collection &&
          scanInsight.endpoint_report_meta.inventory_total != null && (
          <div>
            <span>Colección vs informe</span>
            <strong>
              {scanInsight.endpoint_report_meta.inventory_total} rutas en la colección
              {scanInsight.endpoint_report_meta.dynamic_scope_total != null
                ? ` — informe y dinámicas: ${scanInsight.endpoint_report_meta.dynamic_scope_total} seleccionadas`
                : ""}
            </strong>
          </div>
        )}
        {scanInsight?.scan_scope && (
          <div>
            <span>Archivos analizados (SAST)</span>
            <strong>{scanInsight.scan_scope.files_scanned ?? 0}</strong>
            {Array.isArray(scanInsight.scan_scope.extensions) && scanInsight.scan_scope.extensions.length > 0 && (
              <span className="hint" style={{ display: "block", marginTop: 4 }}>
                Extensiones: {scanInsight.scan_scope.extensions.join(", ")}
              </span>
            )}
          </div>
        )}
        {codeOnly && jsMeta && (
          <div>
            <span>Análisis JS por función</span>
            <strong>
              {jsMeta.enabled === false
                ? "No ejecutado"
                : `${jsMeta.functions_analyzed ?? 0} funciones en ${jsMeta.files_scanned ?? 0} archivos`}
            </strong>
            {jsMetaActive && (
              <span className="hint" style={{ display: "block", marginTop: 4 }}>
                {jsMeta.findings_count ?? 0} hallazgos del motor JS
                {Array.isArray(jsMeta.function_names_sample) && jsMeta.function_names_sample.length > 0
                  ? ` — ej.: ${jsMeta.function_names_sample.slice(0, 5).join(", ")}`
                  : ""}
              </span>
            )}
          </div>
        )}
      </div>

      {scanInsight?.project_tests && typeof scanInsight.project_tests === "object" && (
        <div className="analysis-box" style={{ marginTop: 14 }}>
          <span>Tests del repositorio</span>
          <p className="hint" style={{ margin: "8px 0 0" }}>
            {scanInsight.project_tests.runner
              ? `Motor: ${scanInsight.project_tests.runner} — comando: ${Array.isArray(scanInsight.project_tests.command) ? scanInsight.project_tests.command.join(" ") : "—"}`
              : "No se ejecutó motor de tests (sin detección o desactivado)."}
            {scanInsight.project_tests.duration_sec != null
              ? ` — duración ${scanInsight.project_tests.duration_sec} s`
              : ""}
            {scanInsight.project_tests.exit_code != null
              ? ` — código salida ${scanInsight.project_tests.exit_code}`
              : ""}
          </p>
          {scanInsight.project_tests.junit && typeof scanInsight.project_tests.junit === "object" ? (
            <p className="hint" style={{ margin: "8px 0 0" }}>
              <strong>JUnit:</strong> {scanInsight.project_tests.junit.tests ?? 0} tests —{" "}
              {scanInsight.project_tests.junit.failures ?? 0} fallos,{" "}
              {scanInsight.project_tests.junit.errors ?? 0} errores
              {scanInsight.project_tests.junit.skipped != null
                ? `, ${scanInsight.project_tests.junit.skipped} omitidos`
                : ""}
            </p>
          ) : null}
          {scanInsight.project_tests.reason ? (
            <p className="hint" style={{ margin: "6px 0 0" }}>{String(scanInsight.project_tests.reason)}</p>
          ) : null}
          {(() => {
            const pt = scanInsight.project_tests;
            const tail = String(pt.stdout_tail || "").trim();
            const ju = pt.junit;
            const fallback =
              ju && typeof ju === "object"
                ? [
                    "=== Resumen JUnit ===",
                    ju.path ? `Archivo: ${ju.path}` : "",
                    `Tests: ${ju.tests ?? 0}`,
                    `Failures: ${ju.failures ?? 0}`,
                    `Errors: ${ju.errors ?? 0}`,
                    ju.skipped != null ? `Skipped: ${ju.skipped}` : "",
                    "",
                    "(Sin salida de consola capturada; resumen desde junit.xml.)",
                  ]
                    .filter(Boolean)
                    .join("\n")
                : "";
            const exitOk = pt.exit_code === 0 && String(pt.status || "") === "completed";
            const minimal =
              !tail && !fallback && exitOk
                ? `Tests completados correctamente (código salida 0).\nDuración: ${pt.duration_sec ?? "—"} s.\n\nNo se capturó salida de consola (común con npm/jest en Windows).`
                : "";
            const text = tail || fallback || minimal;
            if (!text) return null;
            return (
              <details open style={{ marginTop: 10 }}>
                <summary style={{ cursor: "pointer", fontSize: "0.88rem" }}>Ver salida de tests</summary>
                <pre className="test-output-pre">{text}</pre>
              </details>
            );
          })()}
        </div>
      )}

      {codeOnly && jsMetaActive && (
        <div className="analysis-box" style={{ marginTop: 14 }}>
          <span>Análisis por función (JavaScript / TypeScript)</span>
          <p className="hint" style={{ margin: "8px 0 0" }}>
            Se extrajeron y revisaron{" "}
            <strong>{jsMeta.functions_analyzed ?? 0}</strong> funciones en{" "}
            <strong>{jsMeta.files_scanned ?? 0}</strong> archivos JS/TS.
            {(jsMeta.api_functions_reviewed ?? 0) > 0 ? (
              <>
                {" "}
                <strong>{jsMeta.api_functions_reviewed}</strong> funciones consumen API (
                <strong>{jsMeta.api_functions_ok ?? 0}</strong> con auth detectada
                {(jsMeta.api_functions_review ?? 0) > 0
                  ? `, ${jsMeta.api_functions_review} a revisar`
                  : ""}
                ).
              </>
            ) : null}
            {(jsMeta.findings_count ?? 0) === 0 ? (
              <>
                {" "}
                Sin hallazgos de seguridad JS en esta corrida (código limpio o sin patrones de riesgo).
              </>
            ) : (
              <>
                {" "}
                <strong>{jsMeta.findings_count}</strong> hallazgos del motor JS.
              </>
            )}
          </p>
          {Array.isArray(jsMeta.function_http_audit) && jsMeta.function_http_audit.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <p className="eyebrow" style={{ marginBottom: 8 }}>Consumo de servicios (API)</p>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Función</th>
                      <th>Archivo</th>
                      <th>API</th>
                      <th>Auth</th>
                      <th>try/catch</th>
                      <th>Validación</th>
                      <th>Estado</th>
                    </tr>
                  </thead>
                  <tbody>
                    {jsMeta.function_http_audit.map((row, i) => (
                      <tr key={`${row.file}-${row.function}-${i}`}>
                        <td className="mono-cell">{row.function || "—"}</td>
                        <td className="mono-cell">{row.file || "—"}</td>
                        <td className="mono-cell" style={{ fontSize: "0.78rem" }}>
                          {Array.isArray(row.api_calls) ? row.api_calls.join(", ") : "—"}
                        </td>
                        <td>{row.auth_in_function ? "Sí" : "No"}</td>
                        <td>{row.has_try_catch || row.has_promise_catch ? "Sí" : "No"}</td>
                        <td>{row.has_validation ? "Sí" : "No"}</td>
                        <td style={{ fontSize: "0.82rem" }}>
                          {row.status === "ok"
                            ? "OK"
                            : row.status === "partial"
                              ? "Parcial"
                              : row.status === "review"
                                ? "Revisar"
                                : row.status === "wrapper_impl"
                                  ? "Wrapper"
                                  : row.status || "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
          {Array.isArray(jsMeta.function_names_sample) && jsMeta.function_names_sample.length > 0 && (
            <details style={{ marginTop: 10 }}>
              <summary style={{ cursor: "pointer", fontSize: "0.88rem" }}>
                Otras funciones analizadas (muestra)
              </summary>
              <p className="mono-cell" style={{ fontSize: "0.78rem", marginTop: 8 }}>
                {jsMeta.function_names_sample.join(", ")}
              </p>
            </details>
          )}
        </div>
      )}
      {codeOnly && scanInsight?.secrets_audit?.enabled && (
        <div className="analysis-box" style={{ marginTop: 14, borderColor: scanInsight.secrets_audit.findings_count ? "#e8b4af" : "#cbe7d9" }}>
          <span>Secretos y tokens en código</span>
          <p className="hint" style={{ margin: "8px 0 0" }}>
            {scanInsight.secrets_audit.status_message || "Auditoría de secretos completada."}
          </p>
          {(scanInsight.secrets_audit.findings_count ?? 0) > 0 && (
            <p className="hint" style={{ margin: "6px 0 0", color: "#9a3b32" }}>
              <strong>{scanInsight.secrets_audit.findings_count}</strong> posible(s) secreto(s) — ver sección en el informe HTML/PDF.
            </p>
          )}
        </div>
      )}

      {codeOnly && lastScanId && !jsMeta && !loading && (
        <p className="hint" style={{ marginTop: 12 }}>
          Este escaneo no incluye metadatos de análisis JS (corrida anterior al motor por función). Vuelve a
          analizar el repositorio.
        </p>
      )}

      {scanInsight?.executive_summary?.recommended_actions?.length > 0 && (
        <div className="analysis-box" style={{ marginTop: 12 }}>
          <span>Priorización</span>
          <ul style={{ margin: "8px 0 0", paddingLeft: 18, fontSize: "0.88rem" }}>
            {scanInsight.executive_summary.recommended_actions.map((a, i) => (
              <li key={i}>{a}</li>
            ))}
          </ul>
        </div>
      )}

      {scanInsight?.analysis_run_summary?.length > 0 && (
        <div style={{ marginTop: 14 }}>
          <p className="eyebrow" style={{ marginBottom: 8 }}>Resumen de análisis (OK / falló / omitido)</p>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Análisis</th>
                  <th>Resultado</th>
                  <th>Estado</th>
                  <th>Detalle</th>
                </tr>
              </thead>
              <tbody>
                {scanInsight.analysis_run_summary.map((row) => (
                  <tr key={row.id}>
                    <td>{row.label || row.id}</td>
                    <td>
                      <span
                        className={`severity-badge ${
                          row.outcome === "ok"
                            ? "low"
                            : row.outcome === "skipped"
                              ? "medium"
                              : row.outcome === "warning"
                                ? "medium"
                                : "high"
                        }`}
                      >
                        {row.outcome_label || row.outcome || "—"}
                      </span>
                    </td>
                    <td>{statusLabel(row.status)}</td>
                    <td style={{ fontSize: "0.82rem" }}>{row.detail || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {scanInsight?.openapi_specs?.length > 0 && (
        <p className="hint" style={{ marginTop: 12 }}>
          OpenAPI/Swagger en repo: {scanInsight.openapi_specs.slice(0, 5).join(", ")}
          {scanInsight.openapi_specs.length > 5 ? "…" : ""}
        </p>
      )}

      {scanInsight?.external_tool_findings_merged &&
        Object.keys(scanInsight.external_tool_findings_merged).length > 0 && (
        <p className="hint" style={{ marginTop: 10 }}>
          Hallazgos integrados en la tabla:{" "}
          {Object.entries(scanInsight.external_tool_findings_merged)
            .map(([k, n]) => `${k} (${n})`)
            .join(", ")}
        </p>
      )}

      {error && <div className="alert" role="alert">{error}</div>}
      {pdfWarning && !error && (
        <div className="hint" role="status" style={{ marginTop: 10 }}>
          <strong>PDF no generado:</strong> {pdfWarning}. Puedes usar el informe HTML.
        </div>
      )}

      <div className="report-actions">
        <button className="button secondary" type="button" onClick={handleOpenReport} disabled={!canReport}>
          {reportLoading ? "Generando..." : "Ver HTML"}
        </button>
        <button className="button secondary" type="button" onClick={handleDownloadReport} disabled={!canReport}>
          Descargar HTML
        </button>
        <button className="button secondary" type="button" onClick={handleDownloadPdf} disabled={!canReport}>
          Descargar PDF
        </button>
      </div>

      {reportUrl && (
        <p className="link-row">
          <a href={reportUrl} target="_blank" rel="noreferrer">Abrir reporte HTML</a>
          {reportPdfUrl && <a href={reportPdfUrl} target="_blank" rel="noreferrer">Abrir PDF</a>}
        </p>
      )}
    </section>
  );
}
