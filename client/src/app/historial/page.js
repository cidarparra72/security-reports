"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import {
  API_BASE,
  errorMessage,
  publicApiUrl,
} from "../../hooks/useScan";

function formatDate(iso) {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return String(iso);
    return d.toLocaleString("es-ES", {
      dateStyle: "short",
      timeStyle: "short",
    });
  } catch {
    return String(iso);
  }
}

function shortPath(p, max = 48) {
  if (!p) return "—";
  const s = String(p);
  if (s.length <= max) return s;
  return "…" + s.slice(-(max - 1));
}

export default function HistorialPage() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [busyId, setBusyId] = useState(null);
  const [toast, setToast] = useState(null);

  const load = useCallback(async () => {
    setError(null);
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/scans?limit=200`);
      if (!res.ok) throw new Error(await errorMessage(res));
      const data = await res.json();
      setScans(Array.isArray(data.scans) ? data.scans : []);
    } catch (e) {
      setError(e?.message || String(e));
      setScans([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function ensureReport(scanId) {
    const res = await fetch(`${API_BASE}/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_id: scanId }),
    });
    if (!res.ok) throw new Error(await errorMessage(res));
    return res.json();
  }

  async function openExecutiveHtml(row) {
    if (String(row.status).toLowerCase() !== "completed") {
      setToast("Este análisis no terminó bien; no hay informe ejecutivo.");
      return;
    }
    setBusyId(row.id);
    setToast(null);
    try {
      let url = row.report_html_cached
        ? publicApiUrl(`/reports/report_${row.id}.html`)
        : null;
      if (!url) {
        const data = await ensureReport(row.id);
        url = publicApiUrl(data.report_url);
      }
      const w = window.open(url, "_blank", "noopener,noreferrer");
      if (!w) {
        setToast(
          "Ventana bloqueada. Usa «Descargar HTML» o abre: " + url
        );
      }
    } catch (e) {
      setToast(e?.message || String(e));
    } finally {
      setBusyId(null);
    }
  }

  async function downloadExecutiveHtml(row) {
    if (String(row.status).toLowerCase() !== "completed") return;
    setBusyId(row.id);
    setToast(null);
    try {
      let url = row.report_html_cached
        ? publicApiUrl(`/reports/report_${row.id}.html`)
        : null;
      if (!url) {
        const data = await ensureReport(row.id);
        url = publicApiUrl(data.report_url);
      }
      const htmlRes = await fetch(url);
      if (!htmlRes.ok) throw new Error("No se pudo descargar el HTML");
      const blob = await htmlRes.blob();
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = blobUrl;
      a.download = `retest-report-${row.id}.html`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(blobUrl);
    } catch (e) {
      setToast(e?.message || String(e));
    } finally {
      setBusyId(null);
    }
  }

  async function downloadPdf(row) {
    if (String(row.status).toLowerCase() !== "completed") return;
    setBusyId(row.id);
    setToast(null);
    try {
      let pdfUrl = row.report_pdf_cached
        ? publicApiUrl(`/reports/report_${row.id}.pdf`)
        : null;
      if (!pdfUrl) {
        const data = await ensureReport(row.id);
        if (!data.report_pdf_url) {
          throw new Error(
            data.pdf_error ||
              "El PDF no está disponible (revisa reportlab en el servidor)."
          );
        }
        pdfUrl = publicApiUrl(data.report_pdf_url);
      }
      const a = document.createElement("a");
      a.href = pdfUrl;
      a.download = `retest-report-${row.id}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (e) {
      setToast(e?.message || String(e));
    } finally {
      setBusyId(null);
    }
  }

  const completed = (row) => String(row.status).toLowerCase() === "completed";

  return (
    <main className="app-shell">
      <section className="topbar">
        <div>
          <p className="eyebrow">Security reports</p>
          <h1>Historial de análisis</h1>
          <p className="subtitle">
            Todas las corridas guardadas en el servidor: abre o descarga el informe ejecutivo (HTML/PDF) y el informe ZAP si existió.
          </p>
        </div>
        <div className="topbar-actions">
          <Link className="button secondary" href="/">
            Volver al inicio
          </Link>
          <button
            className="button secondary"
            type="button"
            onClick={load}
            disabled={loading}
          >
            {loading ? "Cargando…" : "Actualizar"}
          </button>
        </div>
      </section>

      {error && (
        <div className="alert" role="alert">
          {error}
        </div>
      )}
      {toast && (
        <div className="alert" role="status">
          {toast}
          <button
            type="button"
            onClick={() => setToast(null)}
            style={{
              float: "right",
              border: "none",
              background: "transparent",
              cursor: "pointer",
              fontWeight: 700,
            }}
          >
            ✕
          </button>
        </div>
      )}

      <section className="panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Lista</p>
            <h2>Análisis recientes</h2>
          </div>
          <span className="total-pill">{scans.length} registros</span>
        </div>

        {loading && scans.length === 0 ? (
          <p className="hint">Cargando historial…</p>
        ) : scans.length === 0 ? (
          <p className="empty-state">
            No hay análisis en la base de datos. Ejecuta un scan desde el inicio.
          </p>
        ) : (
          <div className="table-wrap historial-table-wrap">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Fecha</th>
                  <th>Estado</th>
                  <th>Hallazgos</th>
                  <th>API</th>
                  <th>Proyecto</th>
                  <th>Informe ejecutivo</th>
                  <th>ZAP</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((row) => (
                  <tr key={row.id}>
                    <td className="mono-cell">{row.id}</td>
                    <td>{formatDate(row.created_at)}</td>
                    <td>
                      <span
                        className={
                          completed(row)
                            ? "severity-badge low"
                            : String(row.status).toLowerCase() === "failed"
                              ? "severity-badge high"
                              : "severity-badge medium"
                        }
                      >
                        {row.status || "—"}
                      </span>
                    </td>
                    <td>
                      {row.total_vulnerabilities != null
                        ? row.total_vulnerabilities
                        : "—"}
                    </td>
                    <td className="mono-cell" style={{ maxWidth: 180 }}>
                      {row.dynamic_api_url
                        ? shortPath(row.dynamic_api_url, 36)
                        : "—"}
                    </td>
                    <td className="mono-cell" title={row.path || ""}>
                      {shortPath(row.path, 40)}
                    </td>
                    <td>
                      <div className="historial-actions">
                        <button
                          type="button"
                          className="text-button"
                          disabled={!completed(row) || busyId === row.id}
                          onClick={() => openExecutiveHtml(row)}
                        >
                          Ver HTML
                        </button>
                        <button
                          type="button"
                          className="text-button"
                          disabled={!completed(row) || busyId === row.id}
                          onClick={() => downloadExecutiveHtml(row)}
                        >
                          Descargar HTML
                        </button>
                        <button
                          type="button"
                          className="text-button"
                          disabled={!completed(row) || busyId === row.id}
                          onClick={() => downloadPdf(row)}
                        >
                          PDF
                        </button>
                        {row.report_html_cached && (
                          <span className="hint" style={{ fontSize: "0.75rem" }}>
                            HTML en caché
                          </span>
                        )}
                      </div>
                    </td>
                    <td>
                      {completed(row) && row.zap_baseline_html ? (
                        <a
                          href={publicApiUrl(
                            `/scan/${row.id}/artifact/${encodeURIComponent(row.zap_baseline_html)}`
                          )}
                          target="_blank"
                          rel="noreferrer"
                        >
                          HTML ZAP
                        </a>
                      ) : row.zap_baseline_enabled ? (
                        <span className="hint">Sin ruta</span>
                      ) : (
                        <span className="hint">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </main>
  );
}
