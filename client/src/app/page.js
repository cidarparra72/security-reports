"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useScan } from "../hooks/useScan";
import { useArtifacts } from "../hooks/useArtifacts";
import { ScanForm } from "../components/ScanForm";
import { ResultsPanel } from "../components/ResultsPanel";
import { FindingsTable } from "../components/FindingsTable";
import { ArtifactsPanel } from "../components/ArtifactsPanel";
import { EndpointCollectionWorkbench } from "../components/EndpointCollectionWorkbench";

export default function HomePage() {
  const [view, setView] = useState("home");
  const scan = useScan();
  const { loadChecksCatalog, prepareCodeOnlyScanMode } = scan;
  const artifacts = useArtifacts(scan.lastScanId);

  useEffect(() => {
    loadChecksCatalog();
  }, [loadChecksCatalog]);

  const statusLabel = scan.loading
    ? `Escaneando${scan.scanStatus && scan.scanStatus !== "scanning" ? ` (${scan.scanStatus})` : "..."}`
    : scan.lastScanId
      ? `Scan #${scan.lastScanId}`
      : "Listo";

  if (view === "home") {
    return (
      <main className="app-shell">
        <section className="topbar hero-panel">
          <div className="hero-copy">
            <p className="eyebrow">Security reports</p>
            <h1>Centro de análisis de seguridad</h1>
            <p className="subtitle">
              Ejecuta revisiones de código, endpoints y evidencias desde un panel claro, rápido y listo para informes ejecutivos.
            </p>
            <div className="hero-metrics" aria-label="Capacidades principales">
              <span><strong>SAST</strong> Código</span>
              <span><strong>DAST</strong> API</span>
              <span><strong>PDF</strong> Reportes</span>
            </div>
          </div>
          <div className="status-strip status-strip--hero" aria-label="Estado del scanner">
            <span className={scan.loading ? "pulse-dot active" : "pulse-dot"} />
            <span>{statusLabel}</span>
          </div>
        </section>

        <section className="home-grid home-grid--featured">
          <article className="panel home-card home-card--primary">
            <p className="eyebrow">Flujo recomendado</p>
            <h2>Escanear código del repositorio</h2>
            <p>
              Revisión enfocada en el árbol de fuentes con checks configurables, lenguajes y herramientas externas cuando estén disponibles.
            </p>
            <button
              className="button primary"
              type="button"
              onClick={() => {
                prepareCodeOnlyScanMode();
                setView("code");
              }}
            >
              Abrir análisis de código
            </button>
          </article>

          <article className="panel home-card home-card--secondary">
            <p className="eyebrow">Herramientas</p>
            <h2>Otros modos de análisis</h2>
            <div className="tool-grid">
              <button
                className="tool-card"
                type="button"
                onClick={() => {
                  scan.clearForJsonMode();
                  setView("json");
                }}
              >
                <span className="tool-card-kicker">API completa</span>
                <strong>Endpoints por colección o proyecto</strong>
                <small>Importa Postman/OpenAPI o infiere rutas desde el código.</small>
              </button>
              <Link className="tool-card" href="/probe">
                <span className="tool-card-kicker">Probe</span>
                <strong>HTTP de endpoints</strong>
                <small>Prueba respuestas, estados y errores sin armar un scan completo.</small>
              </Link>
              <button
                className="tool-card"
                type="button"
                onClick={() => {
                  scan.preparePostmanOneByOneMode();
                  setView("endpoints");
                }}
              >
                <span className="tool-card-kicker">Precisión</span>
                <strong>Colección uno a uno</strong>
                <small>Postman armado al estilo Probe: lista, selección y scan por endpoint.</small>
              </button>
              <Link className="tool-card" href="/scan-api">
                <span className="tool-card-kicker">scanApi</span>
                <strong>Auditor Postman 360</strong>
                <small>Estático + live sobre colección y PDF (reglas scanApi).</small>
              </Link>
              <Link className="tool-card" href="/historial">
                <span className="tool-card-kicker">Reportes</span>
                <strong>Historial de corridas</strong>
                <small>Revisa resultados anteriores y descarga HTML o PDF.</small>
              </Link>
            </div>
          </article>
        </section>
      </main>
    );
  }

  if (view === "endpoints") {
    return (
      <main className="app-shell">
        <section className="topbar">
          <div>
            <p className="eyebrow">Security reports</p>
            <h1>Colección Postman — uno a uno</h1>
            <p className="subtitle">
              Solo colección Postman/OpenAPI y URL base: lista al estilo Probe, scan por ruta (activo o cola) con tokens A/B e informe ejecutivo. Sin ruta de proyecto.
            </p>
          </div>
        <div className="topbar-actions">
          <Link className="button secondary" href="/historial">
            Historial
          </Link>
          <button className="button secondary" type="button" onClick={() => setView("home")}>
            Volver al inicio
          </button>
          <div className="status-strip" aria-label="Estado del scanner">
            <span className={scan.loading ? "pulse-dot active" : "pulse-dot"} />
            <span>
              {scan.loading
                ? `Escaneando${scan.scanStatus && scan.scanStatus !== "scanning" ? ` (${scan.scanStatus})` : "..."}`
                : scan.lastScanId
                  ? `Scan #${scan.lastScanId}`
                  : "Listo"}
            </span>
          </div>
        </div>
      </section>

      {scan.error && (
        <div className="alert" role="alert">
          {scan.error}
          <button
            type="button"
            onClick={() => scan.setError(null)}
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
      {artifacts.error && <div className="alert" role="alert">{artifacts.error}</div>}

      <EndpointCollectionWorkbench scan={scan} />

        <section className="results-layout">
          <ResultsPanel
            lastScanId={scan.lastScanId}
            loading={scan.loading}
            summary={scan.summary}
            dynamicInfo={scan.dynamicInfo}
            externalImport={scan.externalImport}
            zapBaselineInfo={scan.zapBaselineInfo}
            selectedEndpoints={scan.selectedEndpoints}
            scanInsight={scan.scanInsight}
          />
          <ArtifactsPanel artifacts={artifacts} lastScanId={scan.lastScanId} loading={scan.loading} />
        </section>

        <FindingsTable rows={scan.rows} />
      </main>
    );
  }

  const isJsonView = view === "json";

  return (
    <main className={isJsonView ? "app-shell app-shell--scanner" : "app-shell"}>
      <section className={isJsonView ? "topbar scan-mode-header" : "topbar"}>
        <div className="scan-mode-copy">
          <p className="eyebrow">Security reports</p>
          <h1>{isJsonView ? "Análisis de endpoints" : "Análisis de código"}</h1>
          <p className="subtitle">
            {isJsonView
              ? "Arma el alcance desde un proyecto, una colección Postman/OpenAPI o evidencias JSON. Selecciona endpoints, ejecuta checks dinámicos y genera reportes HTML/PDF sin perder trazabilidad."
              : "SAST y herramientas sobre el repositorio local del servidor: sin URL de API ni lista de endpoints."}
          </p>
          {isJsonView && (
            <div className="mode-highlights" aria-label="Flujo de análisis de endpoints">
              <span><strong>1</strong> Proyecto o colección</span>
              <span><strong>2</strong> URL base y endpoints</span>
              <span><strong>3</strong> Checks y reporte</span>
            </div>
          )}
        </div>
        <div className="topbar-actions">
          <Link className="button secondary" href="/historial">
            Historial
          </Link>
          <button className="button secondary" type="button" onClick={() => setView("home")}>
            Volver al inicio
          </button>
          <div className="status-strip" aria-label="Estado del scanner">
            <span className={scan.loading ? "pulse-dot active" : "pulse-dot"} />
            <span>{statusLabel}</span>
          </div>
        </div>
      </section>

      {scan.error && (
        <div className="alert" role="alert">
          {scan.error}
          <button
            type="button"
            onClick={() => scan.setError(null)}
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
      {artifacts.error && <div className="alert" role="alert">{artifacts.error}</div>}

      <ScanForm
        scan={scan}
        onSubmit={scan.handleScan}
        mode={isJsonView ? "json" : "code"}
        codeOnly={!isJsonView}
      />

      <section
        className={
          isJsonView ? "results-layout" : "results-layout results-layout--code-only"
        }
      >
        <ResultsPanel
          lastScanId={scan.lastScanId}
          loading={scan.loading}
          summary={scan.summary}
          dynamicInfo={scan.dynamicInfo}
          externalImport={scan.externalImport}
          zapBaselineInfo={scan.zapBaselineInfo}
          selectedEndpoints={scan.selectedEndpoints}
          scanInsight={scan.scanInsight}
        />
        {isJsonView ? (
          <ArtifactsPanel artifacts={artifacts} lastScanId={scan.lastScanId} loading={scan.loading} />
        ) : null}
      </section>

      <FindingsTable rows={scan.rows} />
    </main>
  );
}
