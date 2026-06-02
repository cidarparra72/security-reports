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
        setError(
          "El navegador bloqueó la ventana emergente. Usa «Descargar HTML» o abre manualmente: " + report.url
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
          `/scan/${lastScanId}/project-artifact/${encodeURIComponent(zapBaselineInfo.html_report)}`
        )
      : "";
  const zapJsonHref =
    lastScanId && zapBaselineInfo?.json_report
      ? publicApiUrl(
          `/scan/${lastScanId}/project-artifact/${encodeURIComponent(zapBaselineInfo.json_report)}`
        )
      : "";

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
        Aquí está el resumen del último análisis. Usa <strong>Ver HTML</strong> / <strong>Descargar PDF</strong> para el informe ejecutivo (incluye SAST, endpoints y hallazgos).
        {zapBaselineInfo?.enabled
          ? " Si activaste ZAP baseline, abajo tienes el informe nativo de ZAP."
          : ""}
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
        <div>
          <span>API dinámica</span>
          <strong>
            {dynamicInfo ? `${dynamicInfo.url}${dynamicInfo.inferred ? " (inferida)" : ""}` : "Sin ejecutar"}
          </strong>
        </div>
        <div>
          <span>Importaciones</span>
          <strong>ZAP {externalImport?.zap ?? 0} / Burp {externalImport?.burp ?? 0} / Manual {externalImport?.manual ?? 0}</strong>
        </div>
        <div>
          <span>ZAP baseline</span>
          <strong>{zapBaselineInfo?.enabled ? "Ejecutado" : "No ejecutado"}</strong>
        </div>
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
        <div>
          <span>Endpoints</span>
          <strong>{selectedEndpoints.length} seleccionados para el análisis</strong>
        </div>
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
          {scanInsight.project_tests.reason ? (
            <p className="hint" style={{ margin: "6px 0 0" }}>{String(scanInsight.project_tests.reason)}</p>
          ) : null}
          {scanInsight.project_tests.stdout_tail ? (
            <details style={{ marginTop: 10 }}>
              <summary style={{ cursor: "pointer", fontSize: "0.88rem" }}>Ver salida (cola)</summary>
              <pre
                style={{
                  marginTop: 8,
                  maxHeight: 280,
                  overflow: "auto",
                  fontSize: "0.75rem",
                  padding: "10px",
                  background: "var(--panel-muted, #1a1d24)",
                  borderRadius: 6,
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                }}
              >
                {scanInsight.project_tests.stdout_tail}
              </pre>
            </details>
          ) : null}
        </div>
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

      {scanInsight?.external_checks_summary?.length > 0 && (
        <div style={{ marginTop: 14 }}>
          <p className="eyebrow" style={{ marginBottom: 8 }}>Herramientas externas</p>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Herramienta</th>
                  <th>Estado</th>
                  <th>Detalle</th>
                </tr>
              </thead>
              <tbody>
                {scanInsight.external_checks_summary.map((row) => (
                  <tr key={row.id}>
                    <td className="mono-cell">{row.id}</td>
                    <td><span className={`severity-badge ${row.status === "completed" ? "low" : row.status === "skipped" ? "medium" : "high"}`}>{statusLabel(row.status)}</span></td>
                    <td style={{ fontSize: "0.82rem" }}>{row.reason || "—"}</td>
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
