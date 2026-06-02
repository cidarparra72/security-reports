export function ArtifactsPanel({ artifacts, lastScanId, loading }) {
  const {
    jsonArtifacts, selectedArtifactUrl, artifactAnalysis, artifactLoading,
    error, handleLoadJsonArtifacts, handleAnalyzeSelectedArtifact,
    openArtifactByKind, selectArtifact, artifactHref,
  } = artifacts;

  return (
    <section className="panel artifacts-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Evidencia</p>
          <h2>Artefactos</h2>
        </div>
        <button className="button secondary" type="button"
          onClick={handleLoadJsonArtifacts} disabled={!lastScanId || loading}>
          Cargar artefactos
        </button>
      </div>

      <div className="quick-actions">
        <button type="button" className="button secondary"
          onClick={() => openArtifactByKind("zap")} disabled={!jsonArtifacts.length}>
          ZAP JSON
        </button>
        <button type="button" className="button secondary"
          onClick={() => openArtifactByKind("uploaded_burp_json")} disabled={!jsonArtifacts.length}>
          Burp JSON
        </button>
        <button type="button" className="button secondary"
          onClick={() => openArtifactByKind("swagger")} disabled={!jsonArtifacts.length}>
          Swagger
        </button>
      </div>

      {error && <div className="alert" role="alert" style={{ marginTop: 10 }}>{error}</div>}

      {jsonArtifacts.length > 0 ? (
        <>
          <label className="field" style={{ marginTop: 12 }}>
            <span>JSON seleccionado</span>
            <select value={selectedArtifactUrl}
              onChange={(e) => selectArtifact(e.target.value)}>
              {jsonArtifacts.map((a, i) => (
                <option key={`${a.url}-${i}`} value={a.url}>
                  {a.kind} — {a.name}
                </option>
              ))}
            </select>
          </label>
          <button type="button" className="button secondary full"
            onClick={handleAnalyzeSelectedArtifact}
            disabled={!selectedArtifactUrl || artifactLoading}>
            {artifactLoading ? "Analizando..." : "Analizar JSON"}
          </button>
          <div className="artifact-list">
            {jsonArtifacts.map((a, i) => (
              <a key={`${a.url}-${i}`} href={artifactHref(a.url)} target="_blank" rel="noreferrer">
                <span>{a.kind}</span>
                <strong>{a.name}</strong>
              </a>
            ))}
          </div>
        </>
      ) : (
        <p className="empty-state" style={{ marginTop: 12 }}>
          Genera o carga artefactos después del scan.
        </p>
      )}

      {artifactAnalysis?.notes?.length > 0 && (
        <div className="analysis-box">
          <span>Análisis</span>
          {artifactAnalysis.notes.map((n, i) => (
            <p key={`${n}-${i}`}>{n}</p>
          ))}
        </div>
      )}
    </section>
  );
}
