import { useRef } from "react";
import { DEFAULT_CHECKS, LANGUAGE_OPTIONS, anyEndpointNeedsApiBase, CODE_ONLY_DEFAULT_CHECKS } from "../hooks/useScan";
import { API_COLLECTION_ACCEPT, API_COLLECTION_HINT } from "../lib/collectionFileAccept";

export function ScanForm({ scan, onSubmit, mode = "code", codeOnly = false }) {
  const {
    path, setPath, apiUrl, setApiUrl, loading, folderHint,
    runZapBaseline, setRunZapBaseline, apiCandidates,
    apiEndpoints, selectedEndpoints, inferringApi, loadingEndpoints,
    zapFile, setZapFile, burpFile, setBurpFile,
    apiCollectionFile, setApiCollectionFile,
    previewCollectionLoading, previewApiCollection,
    selectedChecks, setSelectedChecks, selectedLanguages, setSelectedLanguages,
    checksCatalog, folderInputRef, handleFolderChange,
    toggleListValue, handleListApis, handleListEndpoints,
    toggleEndpoint, selectAllEndpoints, clearEndpoints, loadChecksCatalog,
    runAdvancedChecks, setRunAdvancedChecks,
    runProjectTests, setRunProjectTests,
    authToken, setAuthToken, secondToken, setSecondToken,
    authHeadersJson, setAuthHeadersJson,
    authHintMessage, loadingAuthHints, fetchAuthHintsFromRepo,
  } = scan;

  function endKey(ep) { return `${ep.method || "GET"} ${ep.url || ""}`.trim(); }
  const isJsonMode = mode === "json";
  const hasJsonFiles = Boolean(zapFile || burpFile || apiCollectionFile);
  /** JSON + ruta sin adjuntos ni lista de endpoints: solo SAST opcional sobre la carpeta. */
  const pathTrim = (path || "").trim();
  const apiUrlTrim = (apiUrl || "").trim();
  const authTokenTrim = (authToken || "").trim();
  const jsonCodeOnlyPath =
    isJsonMode && pathTrim && !hasJsonFiles && apiEndpoints.length === 0;
  const selectedDetailsForHint = isJsonMode
    ? apiEndpoints.filter((ep) => selectedEndpoints.includes(endKey(ep)))
    : [];
  const jsonNeedsApiBase =
    isJsonMode &&
    Boolean(apiCollectionFile) &&
    selectedDetailsForHint.length > 0 &&
    !apiUrlTrim &&
    anyEndpointNeedsApiBase(selectedDetailsForHint);
  const jsonNeedsTokenA =
    isJsonMode &&
    Boolean(apiCollectionFile) &&
    apiEndpoints.length > 0 &&
    runAdvancedChecks &&
    !authTokenTrim;
  const canSubmit = isJsonMode
    ? Boolean(hasJsonFiles || pathTrim)
    : Boolean(pathTrim);

  return (
    <form className={isJsonMode ? "workspace workspace--json" : "workspace"} onSubmit={onSubmit}>
      <input
        ref={folderInputRef}
        type="file"
        className="hidden-input"
        onChange={handleFolderChange}
        {...{ webkitdirectory: "", directory: "" }}
      />

      {/* ── Panel izquierdo: Proyecto y API ── */}
      <section className={isJsonMode ? "panel control-panel json-control-panel" : "panel control-panel"}>
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Entrada</p>
            <h2>
              {isJsonMode ? "Endpoints, API y archivos opcionales" : codeOnly ? "Repositorio" : "Proyecto y API"}
            </h2>
          </div>
          <button className="button secondary" type="button" disabled={loading}
            onClick={() => folderInputRef.current?.click()}>
            Elegir carpeta
          </button>
        </div>

        {isJsonMode && (
          <div className="json-flow-banner" aria-label="Resumen del flujo">
            <div>
              <span>Fuente</span>
              <strong>Proyecto o JSON</strong>
            </div>
            <div>
              <span>Alcance</span>
              <strong>Endpoints seleccionados</strong>
            </div>
            <div>
              <span>Salida</span>
              <strong>Reporte ejecutivo</strong>
            </div>
          </div>
        )}

        {/* Siempre primero: ruta en el servidor (igual que antes para JSON → luego URL y Armar endpoints) */}
        <p className="eyebrow" style={{ marginTop: "0.25rem", marginBottom: "0.35rem" }}>
          {isJsonMode ? "1. Ruta del proyecto (servidor del escáner)" : "Ruta del proyecto"}
        </p>
        {isJsonMode ? (
          <div className="field">
            <span>
              Carpeta del código en el servidor: ahí el escáner busca rutas, llamadas y APIs en el árbol de archivos para enlazarlas con la URL base del API (paso 2) y listar endpoints
            </span>
            <div className="api-discovery-row">
              <label className="field grow" style={{ marginBottom: 0 }}>
                <input
                  id="scan-project-path-input"
                  value={path}
                  onChange={(e) => { setPath(e.target.value); }}
                  disabled={loading}
                  placeholder="Ej. E:\\repo\\mi-app o /opt/scans/mi-app"
                  autoComplete="off"
                />
              </label>
              <button
                type="button"
                className="button secondary"
                disabled={loading || inferringApi || !pathTrim}
                onClick={handleListApis}
              >
                {inferringApi ? "Buscando..." : "Listar APIs"}
              </button>
            </div>
            <p className="helper-note">
              Recorre todo el código, acepta bases <strong>https://...</strong> y agrega candidatos por prefijo cuando detecta un único host. Muestra hasta 80 opciones en el desplegable.
            </p>
          </div>
        ) : (
          <label className="field">
            <span>Ruta del proyecto</span>
            <input
              id="scan-project-path-input"
              value={path}
              onChange={(e) => { setPath(e.target.value); }}
              disabled={loading}
              placeholder="E:\\miniprograms\\mi-proyecto"
              autoComplete="off"
            />
          </label>
        )}
        {folderHint && <p className="hint">{folderHint}</p>}

        {isJsonMode && pathTrim && !hasJsonFiles && apiEndpoints.length === 0 && (
          <p className="hint">
            Sin endpoints cargados todavía: podés <strong>Listar APIs / endpoints</strong> abajo y analizar el API en vivo sobre la lista (checks dinámicos y, si querés, ZAP).
            Si solo necesitás <strong>SAST</strong> sobre la carpeta, pulsá el botón final con los checks de código a la derecha.
          </p>
        )}

        {isJsonMode && (
          <>
            <p className="eyebrow" style={{ marginTop: "1rem", marginBottom: "0.35rem" }}>
              2. URL base del API (host seleccionado)
            </p>
            <div className="json-base-url-block" id="campo-url-base-api">
              <p className="json-base-url-title">URL base del API — arma las URLs de los endpoints</p>
              <p className="hint" style={{ marginTop: 0, marginBottom: 10 }}>
                Esta vista sirve para <strong>probar los endpoints que elijas</strong> (todos vienen marcados por defecto): dinámico contra el API, opcional <strong>ZAP baseline</strong> con Docker, y opcional colección Postman/OpenAPI.
                La <strong>ruta del paso 1</strong> solo se usa para <strong>inferir la lista</strong> desde el código; el análisis va sobre esas URLs, no sobre un barrido SAST del repo salvo que no tengas lista y uses solo SAST.
                Tras <strong>Listar APIs</strong>, elegí base; en <strong>2b</strong> se completan las URLs de cada endpoint.
              </p>
              {apiCandidates.length > 0 && (
                <label className="field api-candidates-field">
                  <span>APIs detectadas (solo entornos públicos; LAN/local no se listan)</span>
                  <select
                    className="api-candidates-select"
                    title="Elegí la base del API para listar endpoints"
                    value={apiUrl}
                    onChange={(e) => {
                      const v = e.target.value;
                      setApiUrl(v);
                      handleListEndpoints(v);
                    }}
                    disabled={loading || loadingEndpoints}
                  >
                    {apiUrlTrim && !apiCandidates.includes(apiUrl) ? (
                      <option value={apiUrl}>{apiUrl} (editada a mano)</option>
                    ) : null}
                    {apiCandidates.map((u) => (
                      <option key={u} value={u} title={u}>{u}</option>
                    ))}
                  </select>
                </label>
              )}
              <label className="field">
                <span>
                  <strong>https://…</strong> (URL base; editable; debe coincidir con la API elegida arriba si usaste «Listar APIs»)
                </span>
                <input
                  id="json-api-base-url-input"
                  value={apiUrl}
                  onChange={(e) => { setApiUrl(e.target.value); }}
                  disabled={loading}
                  placeholder="https://api.tu-dominio.com"
                  autoComplete="off"
                />
              </label>
            </div>

            <p className="eyebrow" style={{ marginTop: "1rem", marginBottom: "0.35rem" }}>
              2b. Endpoints desde el código del proyecto
            </p>
            <p className="hint" style={{ marginTop: 0, marginBottom: "0.35rem" }}>
              Usá la URL con <strong>prefijo de servicio</strong> (p. ej. …/miniprogram/api/v2) en el paso 2 o en el desplegable de APIs detectadas:
              solo se listan rutas de ese API (no se mezclan /card/, /ClientAPI/, etc.). Con solo <strong>https://host</strong> se incluyen todos los servicios del host salvo que el código indique un único prefijo.
            </p>
            <div className="endpoint-toolbar arm-endpoints">
              <button
                type="button"
                className="button primary full"
                disabled={loading || loadingEndpoints || !pathTrim || !apiUrlTrim}
                onClick={() => handleListEndpoints()}
              >
                {loadingEndpoints ? "Buscando en el proyecto…" : "Listar endpoints completos (URL base + rutas)"}
              </button>
              <span>
                {apiEndpoints.length > 0 && !apiCollectionFile
                  ? `${selectedEndpoints.length} de ${apiEndpoints.length} hallados en el código — «Todos» / «Ninguno» en la lista de abajo`
                  : apiEndpoints.length > 0 && apiCollectionFile
                    ? `${selectedEndpoints.length} de ${apiEndpoints.length} en lista (última acción: colección o código; vuelve a pulsar el botón que quieras usar)`
                    : "Pulsá después de elegir la API en el paso 2 (o escribí la URL base): se arman las URLs completas de cada endpoint para ese host."}
              </span>
            </div>
          </>
        )}

        {jsonNeedsApiBase && (
          <div className="alert" role="status">
            Completa la <strong>URL base del API</strong> antes de analizar: los endpoints seleccionados no tienen URL absoluta o usan variables Postman.
          </div>
        )}
        {isJsonMode && (
          <>
            <p className="eyebrow" style={{ marginTop: "1rem", marginBottom: "0.35rem" }}>
              3. Colección Postman / OpenAPI (opcional)
            </p>
            <p className="hint" style={{ marginTop: 0, marginBottom: "0.5rem" }}>
              Alternativa o complemento al paso 2b: importás un JSON y los endpoints salen del spec, <strong>filtrados por la URL base del paso 2</strong>.
              Si ya listaste desde el código, volver a armar desde la colección sustituye la lista.
            </p>
            <label className="file-drop file-drop-collection">
              <span>Colección de APIs (Postman v2.1, OpenAPI 3, Swagger 2)</span>
              <input type="file" accept={API_COLLECTION_ACCEPT} disabled={loading}
                onChange={(e) => setApiCollectionFile(e.target.files?.[0] ?? null)} />
              <small>{apiCollectionFile?.name || `Elige ${API_COLLECTION_HINT}`}</small>
            </label>
            <div className="endpoint-toolbar arm-endpoints">
              <button
                type="button"
                className="button secondary full"
                disabled={loading || previewCollectionLoading || !apiCollectionFile}
                onClick={() => previewApiCollection(apiCollectionFile)}
              >
                {previewCollectionLoading ? "Armando desde colección…" : "Armar endpoints desde la colección"}
              </button>
              <span>
                {apiEndpoints.length > 0
                  ? `${selectedEndpoints.length} de ${apiEndpoints.length} en lista — «Todos» abajo para el mismo alcance que antes`
                  : "Con archivo: rellená la URL base (2) si hace falta y pulsá para resolver variables y rutas del spec."}
              </span>
            </div>
          </>
        )}

        {!isJsonMode && !codeOnly && (
          <div className="json-base-url-block" id="code-mode-url-base">
            <p className="json-base-url-title">URL base del API (https://…)</p>
            <p className="hint" style={{ marginTop: 0, marginBottom: 10 }}>
              Pon aquí el host que quieres probar (ej. <code>https://api.ejemplo.com</code>). Luego pulsa{" "}
              <strong>Armar endpoints</strong> para cargar rutas desde el código del proyecto.
            </p>
            <div className="field-row">
              <label className="field grow">
                <span>
                  <strong>https://…</strong> o vacío para inferir tras «Detectar APIs»
                </span>
                <input
                  value={apiUrl}
                  onChange={(e) => { setApiUrl(e.target.value); }}
                  disabled={loading}
                  placeholder="https://api.ejemplo.com"
                  autoComplete="off"
                />
              </label>
              <button
                type="button"
                className="button secondary inline-action"
                disabled={loading || inferringApi || !pathTrim}
                onClick={handleListApis}
              >
                {inferringApi ? "Buscando..." : "Detectar APIs"}
              </button>
            </div>
          </div>
        )}

        {!isJsonMode && codeOnly && (
          <p className="hint">
            Análisis <strong>JavaScript/TypeScript</strong>: patrones por línea, funciones, llamadas HTTP/API sin auth
            evidente, sinks peligrosos (eval, innerHTML, JWT decode…) y Semgrep (reglas OWASP/XSS/JWT si está instalado).
            Marca <strong>javascript</strong> y <strong>typescript</strong> a la derecha. La ruta debe existir en el equipo del backend.
          </p>
        )}

        {!isJsonMode && !codeOnly && (
          <p className="hint">
            Revisa los lenguajes marcados (extensiones del SAST). Los checks externos (Semgrep, Trivy…)
            deben estar instalados en el servidor si los seleccionas en el panel derecho.
          </p>
        )}

        {!isJsonMode && !codeOnly && apiCandidates.length > 0 && (
          <label className="field api-candidates-field">
            <span>APIs detectadas (públicas)</span>
            <select
              className="api-candidates-select"
              title="Elegí la base del API"
              value={apiUrl}
              onChange={(e) => { setApiUrl(e.target.value); handleListEndpoints(e.target.value); }}
              disabled={loading}
            >
              {apiCandidates.map((u) => (
                <option key={u} value={u} title={u}>{u}</option>
              ))}
            </select>
          </label>
        )}

        {!isJsonMode && !codeOnly && (
          <div className="endpoint-toolbar arm-endpoints">
            <button
              type="button"
              className="button primary full"
              disabled={loading || loadingEndpoints || !apiUrlTrim || !pathTrim}
              onClick={() => handleListEndpoints()}
            >
              {loadingEndpoints ? "Armando endpoints…" : "Armar endpoints"}
            </button>
            <span>
              {apiEndpoints.length > 0
                ? `${selectedEndpoints.length} de ${apiEndpoints.length} seleccionados para el análisis`
                : "Necesitas ruta de proyecto + URL base; opcional: «Detectar APIs» y elige una en el desplegable."}
            </span>
          </div>
        )}

        {!codeOnly && apiEndpoints.length > 0 && (
          <div className="endpoint-panel">
            <div className="endpoint-panel-head">
              <strong>Endpoints que se van a analizar</strong>
              <div>
                <button type="button" className="text-button" onClick={selectAllEndpoints}>Todos</button>
                <button type="button" className="text-button" onClick={clearEndpoints}>Ninguno</button>
              </div>
            </div>
            <div className="endpoint-list">
              {apiEndpoints.map((endpoint) => {
                const key = endKey(endpoint);
                return (
                  <label key={key} className="endpoint-item">
                    <input type="checkbox" checked={selectedEndpoints.includes(key)}
                      onChange={() => toggleEndpoint(key)} disabled={loading} />
                    <span className="method-pill">{endpoint.method}</span>
                    <span className="endpoint-path">{endpoint.path}</span>
                    <small>
                      {endpoint.files?.[0]
                        ? `${endpoint.files[0].file}:${endpoint.files[0].line}`
                        : (endpoint.source
                          ? String(endpoint.source)
                          : (endpoint.count != null ? `${endpoint.count} ref.` : ""))}
                    </small>
                  </label>
                );
              })}
            </div>
          </div>
        )}

        {!codeOnly && !jsonCodeOnlyPath && (
          <div className="switch-line">
            <input id="run-advanced" type="checkbox" checked={runAdvancedChecks}
              onChange={(e) => setRunAdvancedChecks(e.target.checked)} disabled={loading} />
            <label htmlFor="run-advanced">Checks dinámicos avanzados (métodos HTTP, mass assignment, JWT en servidor, BOLA si hay 2 tokens…)</label>
          </div>
        )}

        {!codeOnly && !jsonCodeOnlyPath && (
          <>
            {isJsonMode && (
              <p className="eyebrow" style={{ marginTop: "0.35rem", marginBottom: "0.25rem" }}>
                ZAP y JSON externos (opcional)
              </p>
            )}
            {isJsonMode ? (
              <p className="hint" style={{ margin: "0 0 8px" }}>
                Marcá ZAP solo si querés informe OWASP baseline en Docker sobre los endpoints seleccionados; desmarcado = mismo análisis sin ZAP.
              </p>
            ) : null}
            <div className="switch-line">
              <input id="zap-baseline" type="checkbox" checked={runZapBaseline}
                onChange={(e) => setRunZapBaseline(e.target.checked)} disabled={loading} />
              <label htmlFor="zap-baseline">
                {isJsonMode
                  ? "Incluir OWASP ZAP baseline (Docker) además de las pruebas del escáner"
                  : "Ejecutar OWASP ZAP baseline con Docker"}
              </label>
            </div>
            {runZapBaseline && (
              <p className="hint" style={{ margin: "-6px 0 8px" }}>
                Al terminar, la página baja al panel <strong>Resultado</strong>: ahí verás enlaces al informe ZAP (HTML/JSON) y los botones <strong>Ver HTML</strong> / PDF del informe ejecutivo.
              </p>
            )}

            <div className="upload-grid">
              <label className="file-drop">
                <span>ZAP JSON</span>
                <input type="file" accept=".json,application/json" disabled={loading}
                  onChange={(e) => setZapFile(e.target.files?.[0] ?? null)} />
                <small>{zapFile?.name || "Opcional"}</small>
              </label>
              <label className="file-drop">
                <span>Burp JSON</span>
                <input type="file" accept=".json,application/json" disabled={loading}
                  onChange={(e) => setBurpFile(e.target.files?.[0] ?? null)} />
                <small>{burpFile?.name || "Opcional"}</small>
              </label>
            </div>
          </>
        )}

        {(!isJsonMode || jsonCodeOnlyPath) && (!isJsonMode || pathTrim) && (
          <div className="switch-line">
            <input id="run-repo-tests" type="checkbox" checked={runProjectTests}
              onChange={(e) => setRunProjectTests(e.target.checked)} disabled={loading} />
            <label htmlFor="run-repo-tests">
              Ejecutar <strong>tests del repositorio</strong> en el servidor (<code>npm test</code> o <code>pytest</code>).
              Requiere dependencias ya instaladas en esa ruta; tope de tiempo <code>REPO_TESTS_TIMEOUT_SEC</code> (p. ej. 600).
            </label>
          </div>
        )}

        <button className="button primary full" type="submit" disabled={loading || !canSubmit}>
          {loading
            ? "Escaneando..."
            : isJsonMode
              ? jsonCodeOnlyPath
                ? "Iniciar solo SAST en la ruta"
                : hasJsonFiles && pathTrim
                  ? "Analizar endpoints (JSON + proyecto)"
                  : hasJsonFiles
                    ? "Analizar desde JSON adjunto"
                    : "Analizar endpoints seleccionados"
              : codeOnly
                ? "Iniciar análisis de código"
                : "Iniciar scan"}
        </button>
        {isJsonMode && jsonCodeOnlyPath && (
          <p className="hint">
            Modo <strong>solo carpeta</strong>: SAST sobre la ruta con los checks a la derecha. Cuando cargues endpoints (paso 2b o colección paso 3), el mismo botón pasa a analizar <strong>esas URLs</strong> y podés activar o no <strong>ZAP</strong> arriba.
          </p>
        )}
        {isJsonMode && !jsonCodeOnlyPath && (
          <p className="hint">
            Se analizan los endpoints <strong>marcados</strong> (por defecto todos). <strong>ZAP baseline</strong> es opcional: desmarcado = pruebas del escáner sin Docker; marcado = además informes ZAP en Resultado.
            Listá desde el proyecto (2b) o importá colección (3); la última acción reemplaza la lista hasta que vuelvas a pulsar.
          </p>
        )}
      </section>

      {/* ── Panel derecho: Checks y contexto ── */}
      <section className="panel options-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Configuración</p>
            <h2>{codeOnly || jsonCodeOnlyPath ? "Checks y lenguajes" : "Checks y contexto"}</h2>
          </div>
        </div>

        <div className="option-block">
          <div className="option-title">
            <span>Checks</span>
            <button className="text-button" type="button" onClick={loadChecksCatalog} disabled={loading}>
              Recargar
            </button>
          </div>
          <div className="chip-grid">
            {(checksCatalog.length > 0
              ? checksCatalog
              : (codeOnly || jsonCodeOnlyPath ? CODE_ONLY_DEFAULT_CHECKS : DEFAULT_CHECKS).map((id) => ({ id, name: id.replaceAll("_", " ") }))
            ).map((c) => (
              <label key={c.id} className={selectedChecks.includes(c.id) ? "check-chip selected" : "check-chip"}>
                <input type="checkbox" checked={selectedChecks.includes(c.id)}
                  onChange={() => toggleListValue(setSelectedChecks, c.id)} disabled={loading} />
                <span>{c.name}</span>
              </label>
            ))}
          </div>
        </div>

        <div className="option-block">
          <div className="option-title"><span>Lenguajes</span></div>
          <div className="chip-grid compact">
            {LANGUAGE_OPTIONS.map((lang) => (
              <label key={lang} className={selectedLanguages.includes(lang) ? "check-chip selected" : "check-chip"}>
                <input type="checkbox" checked={selectedLanguages.includes(lang)}
                  onChange={() => toggleListValue(setSelectedLanguages, lang)} disabled={loading} />
                <span>{lang}</span>
              </label>
            ))}
          </div>
        </div>

        {!codeOnly && !jsonCodeOnlyPath && (
          <div className="option-block">
            <div className="option-title"><span>Sesión API (opcional)</span></div>
            <p className="hint" style={{ marginBottom: "0.75rem" }}>
              Podés lanzar el análisis <strong>sin tokens</strong>: TLS, cabeceras, runtime sobre endpoints, etc. siguen.
              Con <strong>checks avanzados</strong>, el token A habilita inspección JWT y pruebas con <code>alg=none</code>; con A+B también BOLA/IDOR si el API responde 2xx por usuario.
            </p>
            {jsonNeedsTokenA && (
              <p className="hint" style={{ marginBottom: "0.75rem" }}>
                Sin token A no habrá hallazgos específicos de <strong>JWT</strong> ni <strong>BOLA</strong> (usuario B); el resto de checks avanzados puede ejecutarse igual.
              </p>
            )}
            <div className="endpoint-toolbar" style={{ marginBottom: "0.65rem" }}>
              <button
                type="button"
                className="button secondary"
                disabled={loading || loadingAuthHints || !pathTrim}
                onClick={() => fetchAuthHintsFromRepo()}
              >
                {loadingAuthHints ? "Buscando en el repo…" : "Rellenar token A desde el repo"}
              </button>
              <span className="hint" style={{ margin: 0 }}>
                Busca literales JWT en <code>.env*</code> y en JS/TS bajo la ruta del paso 1 (heurística).
              </span>
            </div>
            {authHintMessage ? <p className="hint" style={{ marginBottom: "0.75rem" }}>{authHintMessage}</p> : null}
            <p className="hint" style={{ marginBottom: "0.75rem" }}>
              También podés pegar el JWT a mano (Postman, login) o dejar vacío.
            </p>
            <label className="field">
              <span>Token usuario A (opcional)</span>
              <input type="password" autoComplete="off"
                value={authToken} onChange={(e) => setAuthToken(e.target.value)}
                disabled={loading} placeholder="eyJhbG… — vacío = sin sesión" />
            </label>
            <label className="field">
              <span>Token usuario B (opcional, IDOR / BOLA)</span>
              <input type="password" autoComplete="off"
                value={secondToken} onChange={(e) => setSecondToken(e.target.value)}
                disabled={loading} placeholder="Segunda cuenta — solo para BOLA/IDOR" />
            </label>
            <label className="field">
              <span>Cabeceras extra (JSON)</span>
              <textarea rows={3} value={authHeadersJson}
                onChange={(e) => setAuthHeadersJson(e.target.value)}
                disabled={loading}
                placeholder='{"X-Api-Key":"…"} — opcional; Authorization suele bastar con token A' />
            </label>
          </div>
        )}
      </section>
    </form>
  );
}
