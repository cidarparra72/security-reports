"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  DEFAULT_CHECKS,
  LANGUAGE_OPTIONS,
  endpointKey,
  endpointDedupeKey,
  endpointLikelyNeedsApiBase,
  dedupeApiEndpoints,
} from "../hooks/useScan";

function endpointDisplayLine(ep) {
  const path = String(ep?.path || "").trim();
  const url = String(ep?.url || "").trim();
  const name = String(ep?.name || ep?.request_name || "").trim();
  if (url.startsWith("http://") || url.startsWith("https://")) {
    try {
      const u = new URL(url.split("?")[0]);
      const normPath = u.pathname || "/";
      const p = path.startsWith("/") ? path : path ? `/${path}` : "";
      if (!name && p && normPath === p) return url;
      if (name && p && normPath === p) return name;
    } catch {
      /* ignore */
    }
    return name ? `${name} — ${url}` : url;
  }
  if (name && path && name !== path) return `${name} — ${path}`;
  return name || url || path || "";
}

const STATUS_LABEL = {
  pending: "Pendiente",
  scanning: "Analizando…",
  done: "Listo",
  error: "Error",
};

/**
 * Colección Postman/OpenAPI: lista estilo Probe + un scan de seguridad por endpoint (activo o cola secuencial).
 */
export function EndpointCollectionWorkbench({ scan }) {
  const {
    apiUrl,
    setApiUrl,
    loading,
    apiCollectionFile,
    setApiCollectionFile,
    previewCollectionLoading,
    previewApiCollection,
    apiEndpoints,
    selectedEndpoints,
    selectedChecks,
    setSelectedChecks,
    selectedLanguages,
    setSelectedLanguages,
    checksCatalog,
    loadChecksCatalog,
    runAdvancedChecks,
    setRunAdvancedChecks,
    runZapBaseline,
    setRunZapBaseline,
    zapFile,
    setZapFile,
    burpFile,
    setBurpFile,
    authToken,
    setAuthToken,
    secondToken,
    setSecondToken,
    authHeadersJson,
    setAuthHeadersJson,
    toggleListValue,
    toggleEndpoint,
    selectAllEndpoints,
    clearEndpoints,
    handleScan,
    handleScanSequential,
    sequentialScan,
    lastScanId,
  } = scan;

  const [activeKey, setActiveKey] = useState("");
  const [itemStatus, setItemStatus] = useState(() => ({}));

  const endpointRows = useMemo(() => {
    const unique = dedupeApiEndpoints(apiEndpoints || []);
    return unique.map((ep, idx) => ({
      key: endpointKey(ep),
      rowId: `${endpointDedupeKey(ep)}-${idx}`,
      ep,
      label: endpointDisplayLine(ep),
    }));
  }, [apiEndpoints]);

  const allSelected = useMemo(
    () =>
      endpointRows.length > 0 &&
      endpointRows.every((r) => selectedEndpoints.includes(r.key)),
    [endpointRows, selectedEndpoints]
  );

  useEffect(() => {
    loadChecksCatalog();
  }, [loadChecksCatalog]);

  useEffect(() => {
    if (!endpointRows.length) {
      setActiveKey("");
      return;
    }
    const keys = new Set(endpointRows.map((r) => r.key));
    if (!activeKey || !keys.has(activeKey)) {
      setActiveKey(endpointRows[0].key);
    }
  }, [endpointRows, activeKey]);

  useEffect(() => {
    if (!apiCollectionFile) {
      setItemStatus({});
    }
  }, [apiCollectionFile]);

  const setStatusForKeys = useCallback((keys, status) => {
    setItemStatus((prev) => {
      const next = { ...prev };
      for (const k of keys) {
        if (k) next[k] = status;
      }
      return next;
    });
  }, []);

  useEffect(() => {
    if (sequentialScan.running && sequentialScan.currentKey) {
      setStatusForKeys([sequentialScan.currentKey], "scanning");
    }
  }, [
    sequentialScan.running,
    sequentialScan.currentKey,
    setStatusForKeys,
  ]);

  const activeRow = useMemo(
    () => endpointRows.find((r) => r.key === activeKey),
    [endpointRows, activeKey]
  );

  const selectedKeysOrdered = useMemo(
    () =>
      endpointRows
        .filter((r) => selectedEndpoints.includes(r.key))
        .map((r) => r.key),
    [endpointRows, selectedEndpoints]
  );

  const showNeedApiBase = Boolean(
    activeRow?.ep &&
      !(apiUrl || "").trim() &&
      endpointLikelyNeedsApiBase(activeRow.ep)
  );
  const showNeedTokenA = Boolean(
    apiEndpoints.length > 0 && runAdvancedChecks && !(authToken || "").trim()
  );

  const busy = loading || sequentialScan.running;
  const canAnalyzeOne =
    Boolean(apiCollectionFile || zapFile || burpFile) &&
    Boolean(activeKey) &&
    endpointRows.some((r) => r.key === activeKey);

  async function onAnalyzeActive(e) {
    if (e?.preventDefault) e.preventDefault();
    if (!activeKey) return;
    setStatusForKeys([activeKey], "scanning");
    const out = await handleScan(null, {
      endpointKeys: [activeKey],
      postmanOnly: true,
    });
    setStatusForKeys([activeKey], out?.ok ? "done" : "error");
  }

  async function onAnalyzeSequential(e) {
    if (e?.preventDefault) e.preventDefault();
    const keys = selectedKeysOrdered;
    if (!keys.length) return;
    setStatusForKeys(keys, "pending");
    setStatusForKeys([keys[0]], "scanning");
    const out = await handleScanSequential(keys, { postmanOnly: true });
    const results = Array.isArray(out?.results) ? out.results : [];
    setItemStatus((prev) => {
      const next = { ...prev };
      for (const r of results) {
        if (r?.key) next[r.key] = r.ok ? "done" : "error";
      }
      return next;
    });
  }

  function statusBadge(key) {
    const st = itemStatus[key];
    if (!st || st === "pending") return null;
    return (
      <span className={`endpoint-scan-badge endpoint-scan-badge--${st}`}>
        {STATUS_LABEL[st] || st}
      </span>
    );
  }

  return (
    <form
      className="workspace endpoint-collection-workbench"
      onSubmit={onAnalyzeActive}
    >
      <section className="panel control-panel endpoint-collection-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Colección Postman</p>
            <h2>Armar y analizar uno a uno</h2>
          </div>
        </div>

        <p className="hint">
          Solo necesitas la <strong>colección Postman/OpenAPI</strong> y la URL base si aplica. No hace
          falta ruta de código en el servidor: el análisis usa la colección y pruebas dinámicas contra
          el API (misma lista que en Probe HTTP).
        </p>

        <div className="json-base-url-block" id="endpoint-collection-url-base">
          <p className="json-base-url-title">URL base del API</p>
          <p className="hint" style={{ marginTop: 0, marginBottom: 10 }}>
            Sustituye <code>{"{{base_url}}"}</code> y rutas relativas de Postman antes de armar la
            lista.
          </p>
          <label className="field">
            <span>
              <strong>https://…</strong>
            </span>
            <input
              value={apiUrl}
              onChange={(e) => setApiUrl(e.target.value)}
              disabled={busy}
              placeholder="https://api.ejemplo.com"
              autoComplete="off"
            />
          </label>
        </div>

        {showNeedApiBase && (
          <div className="alert" role="status">
            Indica la <strong>URL base</strong> para el endpoint activo.
          </div>
        )}
        {showNeedTokenA && (
          <p className="hint" role="note">
            Sin token A no habrá JWT ni BOLA; el resto de checks avanzados puede ejecutarse.
          </p>
        )}

        <label className="file-drop file-drop-collection">
          <span>Colección Postman v2.1 u OpenAPI (JSON)</span>
          <input
            type="file"
            accept=".json,application/json"
            disabled={busy}
            onChange={(e) => setApiCollectionFile(e.target.files?.[0] ?? null)}
          />
          <small>{apiCollectionFile?.name || "Exporta desde Postman → Collection v2.1"}</small>
        </label>

        <div className="endpoint-toolbar arm-endpoints">
          <button
            type="button"
            className="button primary full"
            disabled={busy || previewCollectionLoading || !apiCollectionFile}
            onClick={() => previewApiCollection(apiCollectionFile)}
          >
            {previewCollectionLoading ? "Armando endpoints…" : "Armar endpoints"}
          </button>
          <span>
            {apiEndpoints.length > 0
              ? `${apiEndpoints.length} en lista · ${selectedEndpoints.length} seleccionados`
              : "Carga el JSON, URL base si aplica, y pulsa «Armar endpoints»."}
          </span>
        </div>

        <div className="panel-heading endpoint-list-heading">
          <div>
            <p className="eyebrow">Selección</p>
            <h3>Endpoints ({endpointRows.length})</h3>
          </div>
          <div className="endpoint-toolbar compact">
            <button
              type="button"
              className="button secondary"
              disabled={!endpointRows.length || busy}
              onClick={selectAllEndpoints}
            >
              Todos
            </button>
            <button
              type="button"
              className="button secondary"
              disabled={!endpointRows.length || busy}
              onClick={clearEndpoints}
            >
              Ninguno
            </button>
            <label className="checkbox-inline">
              <input
                type="checkbox"
                checked={allSelected}
                disabled={!endpointRows.length || busy}
                onChange={() => (allSelected ? clearEndpoints() : selectAllEndpoints())}
              />
              Alternar todos
            </label>
          </div>
        </div>

        <div className="probe-endpoint-list endpoint-collection-list">
          {endpointRows.length === 0 ? (
            <p className="hint">Los endpoints aparecerán aquí tras «Armar endpoints».</p>
          ) : (
            <ul>
              {endpointRows.map((row) => {
                const isActive = row.key === activeKey;
                const checked = selectedEndpoints.includes(row.key);
                return (
                  <li
                    key={row.rowId}
                    className={
                      isActive
                        ? "probe-endpoint-item is-active"
                        : "probe-endpoint-item"
                    }
                  >
                    <div className="probe-endpoint-row">
                      <label className="checkbox-row">
                        <input
                          type="checkbox"
                          checked={checked}
                          disabled={busy}
                          onChange={() => toggleEndpoint(row.key)}
                        />
                        <span className="method-tag">
                          {(row.ep.method || "GET").toUpperCase()}
                        </span>
                        <span className="url-text" title={row.label}>
                          {row.label}
                        </span>
                        {statusBadge(row.key)}
                      </label>
                      <button
                        type="button"
                        className="text-button endpoint-set-active"
                        disabled={busy || isActive}
                        onClick={() => setActiveKey(row.key)}
                      >
                        {isActive ? "Activo" : "Usar"}
                      </button>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </div>

        {sequentialScan.running && (
          <p className="hint endpoint-seq-progress" role="status">
            Cola: {sequentialScan.index} / {sequentialScan.total}
            {sequentialScan.currentKey ? ` — ${sequentialScan.currentKey}` : ""}
          </p>
        )}

        <div className="endpoint-seq-actions">
          <button
            className="button primary"
            type="submit"
            disabled={busy || !canAnalyzeOne}
          >
            {loading && !sequentialScan.running
              ? "Escaneando…"
              : "Analizar endpoint activo"}
          </button>
          <button
            type="button"
            className="button secondary"
            disabled={busy || !selectedKeysOrdered.length || !apiCollectionFile}
            onClick={onAnalyzeSequential}
          >
            {sequentialScan.running
              ? `Cola ${sequentialScan.index}/${sequentialScan.total}…`
              : `Analizar selección uno por uno (${selectedKeysOrdered.length})`}
          </button>
        </div>
        {lastScanId && !busy ? (
          <p className="hint" style={{ marginTop: 8 }}>
            Último scan: <strong>#{lastScanId}</strong> — abre informes en el panel inferior o en
            historial.
          </p>
        ) : null}

        <div className="switch-line">
          <input
            id="ec-advanced"
            type="checkbox"
            checked={runAdvancedChecks}
            onChange={(e) => setRunAdvancedChecks(e.target.checked)}
            disabled={busy}
          />
          <label htmlFor="ec-advanced">
            Checks dinámicos avanzados (JWT, métodos HTTP, mass assignment, BOLA…)
          </label>
        </div>

        <div className="switch-line">
          <input
            id="ec-zap"
            type="checkbox"
            checked={runZapBaseline}
            onChange={(e) => setRunZapBaseline(e.target.checked)}
            disabled={busy}
          />
          <label htmlFor="ec-zap">OWASP ZAP baseline (Docker)</label>
        </div>

        <div className="upload-grid">
          <label className="file-drop">
            <span>ZAP JSON (opcional)</span>
            <input
              type="file"
              accept=".json,application/json"
              disabled={busy}
              onChange={(e) => setZapFile(e.target.files?.[0] ?? null)}
            />
            <small>{zapFile?.name || "Opcional"}</small>
          </label>
          <label className="file-drop">
            <span>Burp JSON (opcional)</span>
            <input
              type="file"
              accept=".json,application/json"
              disabled={busy}
              onChange={(e) => setBurpFile(e.target.files?.[0] ?? null)}
            />
            <small>{burpFile?.name || "Opcional"}</small>
          </label>
        </div>
      </section>

      <section className="panel options-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Sesión y controles</p>
            <h2>Tokens y checks</h2>
          </div>
        </div>

        <div className="option-block">
          <div className="option-title">
            <span>Checks</span>
            <button
              type="button"
              className="text-button"
              onClick={loadChecksCatalog}
              disabled={busy}
            >
              Recargar
            </button>
          </div>
          <div className="chip-grid">
            {(checksCatalog.length > 0
              ? checksCatalog
              : DEFAULT_CHECKS.map((id) => ({ id, name: id.replaceAll("_", " ") }))
            ).map((c) => (
              <label
                key={c.id}
                className={
                  selectedChecks.includes(c.id) ? "check-chip selected" : "check-chip"
                }
              >
                <input
                  type="checkbox"
                  checked={selectedChecks.includes(c.id)}
                  onChange={() => toggleListValue(setSelectedChecks, c.id)}
                  disabled={busy}
                />
                <span>{c.name}</span>
              </label>
            ))}
          </div>
        </div>

        <div className="option-block">
          <div className="option-title">
            <span>Lenguajes</span>
          </div>
          <div className="chip-grid compact">
            {LANGUAGE_OPTIONS.map((lang) => (
              <label
                key={lang}
                className={
                  selectedLanguages.includes(lang) ? "check-chip selected" : "check-chip"
                }
              >
                <input
                  type="checkbox"
                  checked={selectedLanguages.includes(lang)}
                  onChange={() => toggleListValue(setSelectedLanguages, lang)}
                  disabled={busy}
                />
                <span>{lang}</span>
              </label>
            ))}
          </div>
        </div>

        <div className="option-block">
          <div className="option-title">
            <span>Usuario A y usuario B</span>
          </div>
          <p className="hint" style={{ marginBottom: "0.75rem" }}>
            <strong>A:</strong> JWT o sesión del API. <strong>B:</strong> segundo usuario para BOLA/IDOR
            (pega los tokens a mano; no se lee el repositorio en este modo).
          </p>
          <label className="field">
            <span>Token usuario A</span>
            <input
              type="password"
              autoComplete="off"
              value={authToken}
              onChange={(e) => setAuthToken(e.target.value)}
              disabled={busy}
              placeholder="eyJhbG…"
            />
          </label>
          <label className="field">
            <span>Token usuario B (opcional, IDOR/BOLA)</span>
            <input
              type="password"
              autoComplete="off"
              value={secondToken}
              onChange={(e) => setSecondToken(e.target.value)}
              disabled={busy}
              placeholder="Segunda cuenta"
            />
          </label>
          <label className="field">
            <span>Cabeceras extra (JSON opcional)</span>
            <textarea
              rows={3}
              value={authHeadersJson}
              onChange={(e) => setAuthHeadersJson(e.target.value)}
              disabled={busy}
              placeholder='{"X-Api-Key":"…"}'
            />
          </label>
        </div>
      </section>
    </form>
  );
}
