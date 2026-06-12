import { useCallback, useMemo, useRef, useState } from "react";

const _apiRaw = process.env.NEXT_PUBLIC_API_BASE;

/**
 * Base del API para fetch.
 * - Con NEXT_PUBLIC_API_BASE: esa URL (p. ej. backend en otro host).
 * - En el navegador sin env: cadena vacía → rutas relativas (/infer-api, …) y el mismo origen;
 *   con «npm run dev» en client/, Next reenvía a NEXT_PROXY_API / 127.0.0.1:8000 (sin pelear CORS).
 * - En SSR (sin window): http://127.0.0.1:8000 por si algún código lo evalúa fuera del cliente.
 */
function _defaultApiBase() {
  return typeof window !== "undefined" ? "" : "http://127.0.0.1:8000";
}
const API_BASE =
  _apiRaw != null && String(_apiRaw).trim() !== ""
    ? String(_apiRaw).replace(/\/$/, "")
    : _defaultApiBase();

/** Errores típicos de fetch cuando no hay respuesta HTTP (backend caído, CORS, red). */
export function isNetworkFetchError(err) {
  const raw = err?.message || String(err);
  return (
    raw === "Failed to fetch" ||
    raw.includes("NetworkError") ||
    (err?.name === "TypeError" && raw.toLowerCase().includes("fetch"))
  );
}

export function networkErrorUserMessage() {
  return (
    "No se pudo conectar con el backend (puerto 8000). Arrancalo desde la raíz del repo " +
    "(p. ej. npm run dev:backend o run-backend.ps1). Si el front corre con «npm run dev» en client/, " +
    "Next reenvía /infer-api al API; sin backend el navegador puede mostrar «Internal Server Error» (fallo del proxy). " +
    "Si el API está en otra máquina o puerto, definí NEXT_PUBLIC_API_BASE o NEXT_PROXY_API en client/."
  );
}

export const DEFAULT_CHECKS = [
  "static_patterns",
  "dynamic_http_tls",
  "api_runtime_core",
  "docs_exposure_probe",
];

/** Checks que corren solo sobre el árbol del repo (sin URL de API). SAST + dependencias/IaC. */
export const CODE_ONLY_DEFAULT_CHECKS = [
  "static_patterns",
  "js_code_analysis",
  "eslint",
  "semgrep",
  "trivy",
  "grype",
];
export const DEFAULT_LANGUAGES = ["javascript", "typescript", "json"];
export const LANGUAGE_OPTIONS = ["javascript", "typescript", "python", "java", "go", "php", "json"];
export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
/** Máx. espera del scan (SSE + polling). Alineado con SCAN_EVENTS_MAX_WAIT_SEC en server.py (default 1800 s). */
const SCAN_WAIT_MAX_MS =
  Number(process.env.NEXT_PUBLIC_SCAN_MAX_WAIT_MS) || 30 * 60 * 1000;
export { API_BASE };

/**
 * URL para abrir informes o APIs: si NEXT_PUBLIC_API_BASE apunta al backend, úsala;
 * si no, en el navegador fuerza el origin actual (Next en dev) para que /report y /reports pasen por el proxy.
 */
export function publicApiUrl(path) {
  const p = path.startsWith("/") ? path : `/${path}`;
  const b = String(API_BASE || "").replace(/\/$/, "");
  if (b) return `${b}${p}`;
  if (typeof window !== "undefined" && window.location?.origin) {
    return `${window.location.origin}${p}`;
  }
  return p;
}

/** LAN, loopback, link-local IPv4, *.local — no listar en «APIs detectadas» (sí podés pegar la URL a mano). */
export function isNonPublicApiBaseUrl(url) {
  const s = String(url || "").trim();
  if (!s) return true;
  try {
    const u = new URL(s);
    const host = u.hostname.toLowerCase();
    if (host === "localhost" || host.endsWith(".local")) return true;
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
    if (m) {
      const a = Number(m[1]);
      const b = Number(m[2]);
      const c = Number(m[3]);
      const d = Number(m[4]);
      if ([a, b, c, d].some((x) => x > 255)) return false;
      if (a === 10) return true;
      if (a === 127) return true;
      if (a === 0) return true;
      if (a === 169 && b === 254) return true;
      if (a === 172 && b >= 16 && b <= 31) return true;
      if (a === 192 && b === 168) return true;
    }
    return false;
  } catch {
    return false;
  }
}

export function endpointKey(ep) {
  return `${ep.method || "GET"} ${ep.url || ""}`.trim();
}

/** Clave estable para deduplicar (método + path normalizado). */
export function endpointDedupeKey(ep) {
  const m = (ep?.method || "GET").toUpperCase();
  let path = String(ep?.path || "/").trim();
  if (!path.startsWith("/")) path = `/${path}`;
  const rawUrl = String(ep?.url || "").trim().split("?")[0];
  if (rawUrl.startsWith("http://") || rawUrl.startsWith("https://")) {
    try {
      const u = new URL(rawUrl);
      if (u.pathname) path = u.pathname.startsWith("/") ? u.pathname : `/${u.pathname}`;
    } catch {
      /* keep path */
    }
  }
  return `${m}\0${path}`;
}

/** Fusiona GET /ruta y GET https://host/ruta; prioriza entrada con URL absoluta. */
export function dedupeApiEndpoints(eps) {
  const order = [];
  const seen = new Map();
  for (const ep of eps || []) {
    if (!ep || typeof ep !== "object") continue;
    const dk = endpointDedupeKey(ep);
    if (!seen.has(dk)) {
      seen.set(dk, ep);
      order.push(dk);
      continue;
    }
    const prev = seen.get(dk);
    const prevUrl = String(prev?.url || "");
    const newUrl = String(ep?.url || "");
    if (
      !prevUrl.startsWith("http://") &&
      !prevUrl.startsWith("https://") &&
      (newUrl.startsWith("http://") || newUrl.startsWith("https://"))
    ) {
      seen.set(dk, ep);
    }
  }
  return order.map((k) => seen.get(k));
}

/** URL relativa, vacía o con variables Postman/OpenAPI tipo {{baseUrl}} → hace falta URL base. */
export function endpointLikelyNeedsApiBase(ep) {
  const u = String(ep?.url || "").trim();
  if (!u) return true;
  if (u.includes("{{")) return true;
  if (u.startsWith("http://") || u.startsWith("https://")) return false;
  return true;
}

export function anyEndpointNeedsApiBase(endpoints) {
  return Array.isArray(endpoints) && endpoints.some(endpointLikelyNeedsApiBase);
}

export async function errorMessage(res) {
  try {
    const data = await res.json();
    const d = data.detail;
    if (typeof d === "string") return d;
    if (Array.isArray(d)) {
      return d
        .map((x) => (typeof x === "object" && x != null ? x.msg || JSON.stringify(x) : String(x)))
        .join("; ");
    }
    if (d && typeof d === "object") {
      const msg = d.message ? String(d.message) : "";
      const err = d.error ? String(d.error) : "";
      if (msg && err) return `${msg}: ${err}`;
      if (msg) return msg;
      if (err) return err;
    }
    if (d != null) return JSON.stringify(d);
    return res.statusText;
  } catch {
    return res.statusText;
  }
}

export function totalFromSummary(summary) {
  if (!summary) return 0;
  return SEVERITIES.reduce((acc, sev) => acc + (summary[sev] ?? 0), 0);
}

export function summarizeBySeverity(items) {
  const base = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const item of items || []) {
    const sev = String(item?.severity || "").toUpperCase();
    if (base[sev] != null) base[sev] += 1;
  }
  return base;
}

const SEVERITY_SORT = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

function isSyntheticSourceFile(file) {
  const f = String(file || "");
  return f.startsWith("<dynamic") || f === "<external:tool>";
}

function sourceLabelForVuln(v) {
  const file = String(v?.file || "");
  const cat = String(v?.category || "");
  if (/Secretos|Tokens en código/i.test(cat)) return "Secretos";
  if (/JavaScript/i.test(cat)) return "Análisis JS";
  if (/Semgrep/i.test(cat)) return "Semgrep";
  if (/Trivy/i.test(cat)) return "Trivy";
  if (/Grype/i.test(cat)) return "Grype";
  if (/Nuclei/i.test(cat)) return "Nuclei";
  if (file.startsWith("<dynamic:advanced>")) return "Dinámico avanzado";
  if (file.startsWith("<dynamic:bola>")) return "BOLA";
  if (file === "<dynamic:api>") return "API dinámico";
  if (file === "<external:tool>") return "Herramienta externa";
  return "Patrones SAST";
}

/** Hallazgos de análisis de código: todas las vulnerabilidades del resultado del scan. */
export function buildCodeFindings(result) {
  const raw = Array.isArray(result?.vulnerabilities) ? result.vulnerabilities : [];
  const seen = new Set();
  const out = [];
  for (const v of raw) {
    if (!v || typeof v !== "object") continue;
    const sev = String(v.severity || "MEDIUM").toUpperCase();
    const title = String(v.title || "Hallazgo");
    const file = String(v.file || "");
    const line = v.line ?? 0;
    const snippet = String(v.code_snippet || "").slice(0, 240);
    const dedupe = `${file}|${line}|${sev}|${title}|${snippet.slice(0, 80)}`;
    if (seen.has(dedupe)) continue;
    seen.add(dedupe);
    const synthetic = isSyntheticSourceFile(file);
    const funcName = String(v.function_name || "").trim();
    out.push({
      severity: sev,
      title,
      category: String(v.category || ""),
      recommendation: String(v.recommendation || ""),
      confidence: String(v.confidence || "medium"),
      file: synthetic ? "" : file,
      line: synthetic || line === 0 || line === "" ? "" : String(line),
      function_name: funcName,
      code_snippet: snippet,
      source: sourceLabelForVuln(v),
      endpoint: synthetic ? file.replace(/^<|>$/g, "") : "",
      api_url: "",
      cwe_id: String(v.cwe_id || ""),
      false_positive_note: String(v.false_positive_note || ""),
    });
  }
  out.sort(
    (a, b) =>
      (SEVERITY_SORT[a.severity] ?? 9) - (SEVERITY_SORT[b.severity] ?? 9) ||
      String(a.file).localeCompare(String(b.file)) ||
      Number(a.line || 0) - Number(b.line || 0)
  );
  return out;
}

export function normalizeSummaryFromResult(result) {
  const summary = result?.summary;
  if (summary && typeof summary === "object") {
    return {
      CRITICAL: Number(summary.CRITICAL) || 0,
      HIGH: Number(summary.HIGH) || 0,
      MEDIUM: Number(summary.MEDIUM) || 0,
      LOW: Number(summary.LOW) || 0,
    };
  }
  return summarizeBySeverity(result?.vulnerabilities);
}

export function buildApiFindings(result) {
  const endpointReport = Array.isArray(result?.api_endpoint_report)
    ? result.api_endpoint_report
    : [];
  const out = [];
  const seen = new Set();
  for (const endpoint of endpointReport) {
    const method = String(endpoint?.method || "GET").toUpperCase();
    const path = String(endpoint?.path || "");
    const url = String(endpoint?.url || "");
    const findings = Array.isArray(endpoint?.findings) ? endpoint.findings : [];
    for (const finding of findings) {
      const sev = String(finding?.severity || "MEDIUM").toUpperCase();
      const title = String(finding?.title || "Hallazgo");
      const key = `${method} ${url} ${sev} ${title}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        severity: sev, title,
        category: String(finding?.category || "API"),
        recommendation: String(finding?.recommendation || ""),
        confidence: String(finding?.confidence || "medium"),
        endpoint: `${method} ${path}`.trim(),
        api_url: url,
        cwe_id: String(finding?.cwe_id || ""),
        false_positive_note: String(finding?.false_positive_note || ""),
      });
    }
  }
  const fallback = [];
  const raw = Array.isArray(result?.vulnerabilities) ? result.vulnerabilities : [];
  for (const v of raw) {
    if (String(v?.file || "") !== "<dynamic:api>") continue;
    const sev = String(v?.severity || "MEDIUM").toUpperCase();
    const title = String(v?.title || "Hallazgo API");
    const dupKey = `${String(result?.dynamic_api_url || "")} ${sev} ${title}`;
    if (seen.has(dupKey)) continue;
    seen.add(dupKey);
    fallback.push({
      severity: sev, title,
      category: String(v?.category || "API"),
      recommendation: String(v?.recommendation || ""),
      confidence: String(v?.confidence || "medium"),
      endpoint: String(v?.code_snippet || result?.dynamic_api_url || ""),
      api_url: String(result?.dynamic_api_url || ""),
      cwe_id: String(v?.cwe_id || ""),
      false_positive_note: String(v?.false_positive_note || ""),
    });
  }

  const toolRows = [];
  for (const v of raw) {
    const cat = String(v?.category || "");
    if (!/Semgrep|Trivy|Grype|Nuclei/.test(cat)) continue;
    const sev = String(v?.severity || "MEDIUM").toUpperCase();
    const title = String(v?.title || "Hallazgo");
    const file = String(v?.file || "");
    const line = v?.line ?? "";
    const dedupe = `ext:${file}:${line}:${sev}:${title}`;
    if (seen.has(dedupe)) continue;
    seen.add(dedupe);
    toolRows.push({
      severity: sev,
      title,
      category: cat,
      recommendation: String(v?.recommendation || ""),
      confidence: String(v?.confidence || "medium"),
      endpoint: file && file !== "<dynamic:api>" && file !== "<external:tool>"
        ? `${file}${line !== "" && line !== 0 ? `:${line}` : ""}`
        : String(v?.code_snippet || "").slice(0, 120) || file,
      api_url: "",
      cwe_id: String(v?.cwe_id || ""),
      false_positive_note: String(v?.false_positive_note || ""),
    });
  }

  return [...out, ...fallback, ...toolRows];
}

/** Wait for scan completion via SSE, falling back to polling if SSE fails. */
async function waitForScan(scanId, onStatus) {
  return new Promise((resolve, reject) => {
    const url = `${API_BASE}/scan/${scanId}/events`;
    let es;
    let usedFallback = false;

    const startPolling = () => {
      if (usedFallback) return;
      usedFallback = true;
      const maxWaitMs = SCAN_WAIT_MAX_MS;
      const start = Date.now();
      const poll = async () => {
        if (Date.now() - start > maxWaitMs) {
          reject(new Error("El scan tardó demasiado y fue cancelado por la UI."));
          return;
        }
        try {
          const res = await fetch(`${API_BASE}/scan/${scanId}`);
          if (!res.ok) { reject(new Error(await errorMessage(res))); return; }
          const data = await res.json();
          onStatus?.(data.status);
          if (data.status === "completed") { resolve(data); return; }
          if (data.status === "failed") { reject(new Error(data.result?.error ?? "Scan failed")); return; }
        } catch (e) { reject(e); return; }
        setTimeout(poll, 1500);
      };
      poll();
    };

    try {
      es = new EventSource(url);
      const timeout = setTimeout(() => { es?.close(); startPolling(); }, 3000);

      es.addEventListener("status", (e) => {
        clearTimeout(timeout);
        try {
          const payload = JSON.parse(e.data);
          onStatus?.(payload.status);
          if (payload.status === "completed" || payload.status === "failed") {
            es.close();
            fetch(`${API_BASE}/scan/${scanId}`)
              .then((r) => r.json())
              .then((data) => {
                if (data.status === "completed") resolve(data);
                else reject(new Error(data.result?.error ?? "Scan failed"));
              })
              .catch(reject);
          }
        } catch { /* ignore parse errors */ }
      });

      es.addEventListener("error", () => { es?.close(); startPolling(); });
      es.addEventListener("timeout", () => { es?.close(); reject(new Error("Scan timeout")); });
      es.onerror = () => { clearTimeout(timeout); es?.close(); startPolling(); };
    } catch {
      startPolling();
    }
  });
}

export function useScan() {
  const [path, setPath] = useState("./project");
  const [apiUrl, setApiUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [rows, setRows] = useState([]);
  const [lastScanId, setLastScanId] = useState(null);
  const [summary, setSummary] = useState(null);
  const [folderHint, setFolderHint] = useState(null);
  const [dynamicInfo, setDynamicInfo] = useState(null);
  const [externalImport, setExternalImport] = useState(null);
  const [runZapBaseline, setRunZapBaseline] = useState(false);
  const [runProjectTests, setRunProjectTests] = useState(false);
  const [zapBaselineInfo, setZapBaselineInfo] = useState(null);
  const [apiCandidates, setApiCandidates] = useState([]);
  const [apiEndpoints, setApiEndpoints] = useState([]);
  const [selectedEndpoints, setSelectedEndpoints] = useState([]);
  const [inferringApi, setInferringApi] = useState(false);
  const [loadingEndpoints, setLoadingEndpoints] = useState(false);
  const [zapFile, setZapFile] = useState(null);
  const [burpFile, setBurpFile] = useState(null);
  const [apiCollectionFile, setApiCollectionFile] = useState(null);
  const [previewCollectionLoading, setPreviewCollectionLoading] = useState(false);
  const [selectedChecks, setSelectedChecks] = useState(DEFAULT_CHECKS);
  const [selectedLanguages, setSelectedLanguages] = useState(DEFAULT_LANGUAGES);
  const [checksCatalog, setChecksCatalog] = useState([]);
  const [scanStatus, setScanStatus] = useState("idle"); // idle | scanning | done
  const [runAdvancedChecks, setRunAdvancedChecks] = useState(true);
  /** Post-scan diagnostics (scope, executive summary, external tools). */
  const [scanInsight, setScanInsight] = useState(null);
  /** JWT / sesión usuario principal y segundo usuario (BOLA/IDOR); el backend añade Bearer si hace falta en algunos checks. */
  const [authToken, setAuthToken] = useState("");
  const [secondToken, setSecondToken] = useState("");
  /** JSON opcional de cabeceras HTTP extra, p.ej. {"Authorization":"Bearer …","X-Custom":"…"} */
  const [authHeadersJson, setAuthHeadersJson] = useState("");
  const [authHintMessage, setAuthHintMessage] = useState(null);
  const [loadingAuthHints, setLoadingAuthHints] = useState(false);
  const folderInputRef = useRef(null);

  const selectedEndpointDetails = useMemo(
    () => apiEndpoints.filter((ep) => selectedEndpoints.includes(endpointKey(ep))),
    [apiEndpoints, selectedEndpoints]
  );

  const resetResults = useCallback(() => {
    setRows([]); setSummary(null); setDynamicInfo(null);
    setExternalImport(null); setZapBaselineInfo(null);
    setScanInsight(null);
  }, []);

  const clearForJsonMode = useCallback(() => {
    setPath("");
    setApiEndpoints([]);
    setSelectedEndpoints([]);
    setApiCollectionFile(null);
    setZapFile(null);
    setBurpFile(null);
    setApiCandidates([]);
    setAuthHintMessage(null);
  }, []);

  /** Modo colección Postman uno a uno: sin carpeta de proyecto en el servidor. */
  const preparePostmanOneByOneMode = useCallback(() => {
    setPath("");
    setApiEndpoints([]);
    setSelectedEndpoints([]);
    setApiCollectionFile(null);
    setZapFile(null);
    setBurpFile(null);
    setApiCandidates([]);
    setAuthHintMessage(null);
    setAuthToken("");
    setSecondToken("");
    setAuthHeadersJson("");
  }, []);

  /** Entrada principal: solo ruta del proyecto + checks de código (sin API, endpoints ni sesión). */
  const prepareCodeOnlyScanMode = useCallback(() => {
    setApiUrl("");
    setApiCandidates([]);
    setApiEndpoints([]);
    setSelectedEndpoints([]);
    setRunAdvancedChecks(false);
    setRunZapBaseline(false);
    setAuthToken("");
    setSecondToken("");
    setAuthHeadersJson("");
    setAuthHintMessage(null);
    setZapFile(null);
    setBurpFile(null);
    setApiCollectionFile(null);
    setSelectedChecks([...CODE_ONLY_DEFAULT_CHECKS]);
    setRunProjectTests(true);
    setError(null);
  }, []);

  const loadChecksCatalog = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/checks/catalog`);
      if (!res.ok) return;
      const data = await res.json();
      setChecksCatalog(Array.isArray(data.checks) ? data.checks : []);
    } catch { /* optional */ }
  }, []);

  function folderRootFromWebkitFile(file) {
    const rel = file.webkitRelativePath;
    const fp = file.path;
    if (!rel || typeof fp !== "string" || !fp) return null;
    const nrel = rel.replace(/\\/g, "/");
    const nfp = fp.replace(/\\/g, "/");
    const i = nfp.toLowerCase().lastIndexOf(nrel.toLowerCase());
    if (i < 0) return null;
    const root = nfp.slice(0, i).replace(/\/$/, "");
    if (!root) return null;
    return nfp.startsWith("C:") || nfp.startsWith("c:") || nfp.includes("\\")
      ? root.replace(/\//g, "\\")
      : root;
  }

  function handleFolderChange(e) {
    const files = e.target.files;
    if (!files?.length) return;
    const f = files[0];
    const abs = folderRootFromWebkitFile(f);
    if (abs) { setPath(abs); setFolderHint(null); }
    else {
      const rootName = f.webkitRelativePath?.split("/")[0] ?? "";
      const parts = path.replace(/\\/g, "/").split("/").filter(Boolean);
      const match = (parts[parts.length - 1] ?? "").toLowerCase() === rootName.toLowerCase();
      setFolderHint(
        match ? null : rootName
          ? `Carpeta "${rootName}": el navegador no puede rellenar la ruta absoluta. Copiala desde el Explorador.`
          : "No se pudo leer la carpeta seleccionada."
      );
    }
    e.target.value = "";
  }

  function toggleListValue(setter, value) {
    setter((prev) =>
      prev.includes(value) ? prev.filter((x) => x !== value) : [...new Set([...prev, value])]
    );
  }

  /**
   * @param {React.FormEvent} [e]
   * @param {{ endpointKeys?: string[] }} [options] Si endpointKeys está definido, el scan usa solo esas claves (evita race con setState).
   */
  const [sequentialScan, setSequentialScan] = useState({
    running: false,
    index: 0,
    total: 0,
    currentKey: "",
  });

  async function handleScan(e, options = {}) {
    if (e && typeof e.preventDefault === "function") {
      e.preventDefault();
    }
    const sequentialPart = Boolean(options.sequentialPart);
    const skipResetResults = Boolean(options.skipResetResults);
    const postmanOnly = Boolean(options.postmanOnly);
    const codeOnly = Boolean(options.codeOnly);
    const keysOverride = Array.isArray(options.endpointKeys)
      ? options.endpointKeys.filter((k) => typeof k === "string" && k.trim())
      : null;
    const keysPayload = keysOverride ?? selectedEndpoints;
    const detailsPayload =
      keysOverride != null
        ? apiEndpoints.filter((ep) => keysOverride.includes(endpointKey(ep)))
        : selectedEndpointDetails;

    const trimmedApi = (apiUrl || "").trim();
    const useUpload = zapFile != null || burpFile != null || apiCollectionFile != null;

    if (apiCollectionFile != null) {
      if (apiEndpoints.length === 0) {
        setError(
          "Antes del primer análisis con la colección: pulsa «Armar endpoints» para cargar las rutas. " +
            "Así podemos comprobar URL base y sesión."
        );
        return { ok: false };
      }
      if (
        detailsPayload.length > 0 &&
        !trimmedApi &&
        anyEndpointNeedsApiBase(detailsPayload)
      ) {
        setError(
          "Falta la URL base del API: en tu colección hay rutas relativas o variables (p. ej. {{base_url}}). " +
            "Complétala en el campo «URL base del API» y vuelve a analizar."
        );
        return { ok: false };
      }
    }

    setError(null);
    if (!skipResetResults) resetResults();
    if (!sequentialPart) {
      setLoading(true);
      setScanStatus("scanning");
    }
    try {
      let authHeadersDict = null;
      const ahTrim = (authHeadersJson || "").trim();
      if (ahTrim) {
        try {
          const parsed = JSON.parse(ahTrim);
          if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
            throw new Error("auth_headers debe ser un objeto JSON (clave → valor).");
          }
          authHeadersDict = parsed;
        } catch (parseErr) {
          throw new Error(
            parseErr?.message === "auth_headers debe ser un objeto JSON (clave → valor)."
              ? parseErr.message
              : `Cabeceras extra: JSON inválido (${parseErr?.message || parseErr}).`
          );
        }
      }

      let res;
      if (useUpload) {
        const fd = new FormData();
        fd.append("path", postmanOnly ? "" : path);
        if (trimmedApi) fd.append("api_url", trimmedApi);
        fd.append("run_zap_baseline", String(runZapBaseline));
        fd.append("selected_checks", JSON.stringify(selectedChecks));
        fd.append("selected_endpoints", JSON.stringify(keysPayload));
        fd.append("selected_endpoint_details", JSON.stringify(detailsPayload));
        fd.append("languages", JSON.stringify(selectedLanguages));
        fd.append("auth_token", (authToken || "").trim());
        fd.append("second_token", (secondToken || "").trim());
        if (ahTrim) fd.append("auth_headers", ahTrim);
        fd.append("run_advanced_checks", String(runAdvancedChecks));
        fd.append("run_project_tests", String(runProjectTests));
        fd.append("dynamic_http_max_per_endpoint", "0");
        fd.append("code_only", String(codeOnly));
        if (zapFile) fd.append("zap_file", zapFile);
        if (burpFile) fd.append("burp_file", burpFile);
        if (apiCollectionFile) fd.append("api_collection_file", apiCollectionFile);
        res = await fetch(`${API_BASE}/scan/upload`, { method: "POST", body: fd });
      } else {
        const payload = {
          path, run_zap_baseline: runZapBaseline,
          selected_checks: selectedChecks, selected_endpoints: keysPayload,
          selected_endpoint_details: detailsPayload, languages: selectedLanguages,
          auth_token: (authToken || "").trim(),
          second_token: (secondToken || "").trim(),
          run_advanced_checks: runAdvancedChecks,
          run_project_tests: runProjectTests,
          dynamic_http_max_per_endpoint: 0,
          code_only: codeOnly,
        };
        if (authHeadersDict) payload.auth_headers = authHeadersDict;
        if (trimmedApi) payload.api_url = trimmedApi;
        res = await fetch(`${API_BASE}/scan`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
      }
      if (!res.ok) throw new Error(await errorMessage(res));

      const { scan_id } = await res.json();
      setLastScanId(scan_id);

      // SSE with polling fallback
      const data = await waitForScan(scan_id, (st) => setScanStatus(st));
      if (!data || data.status !== "completed") throw new Error("El scan tardó demasiado.");

      const result = data.result ?? {};
      const isCodeScan = codeOnly || Boolean(result.code_only);
      const findings = isCodeScan ? buildCodeFindings(result) : buildApiFindings(result);
      setSummary(normalizeSummaryFromResult(result));
      setRows(findings);
      setDynamicInfo(
        !isCodeScan && result.dynamic_api_url
          ? { url: result.dynamic_api_url, inferred: Boolean(result.dynamic_api_inferred) }
          : null
      );
      setExternalImport(result.external_import ?? null);
      setZapBaselineInfo(result.zap_baseline ?? null);
      setScanInsight({
        scan_scope: result.scan_scope ?? null,
        js_code_analysis_meta: result.js_code_analysis_meta ?? null,
        secrets_audit: result.secrets_audit ?? null,
        analysis_run_summary: Array.isArray(result.analysis_run_summary)
          ? result.analysis_run_summary
          : [],
        executive_summary: result.executive_summary ?? null,
        external_checks_summary: Array.isArray(result.external_checks_summary)
          ? result.external_checks_summary
          : [],
        openapi_specs: Array.isArray(result.openapi_specs) ? result.openapi_specs : [],
        external_tool_findings_merged: result.external_tool_findings_merged ?? null,
        endpoint_report_meta: result.endpoint_report_meta ?? null,
        project_tests: result.project_tests ?? null,
      });
      if (keysOverride != null) {
        setSelectedEndpoints(keysPayload);
      }
      setScanStatus("done");
      return { ok: true, scanId: scan_id };
    } catch (err) {
      const msg = isNetworkFetchError(err) ? networkErrorUserMessage() : err?.message || String(err);
      if (!sequentialPart) setError(msg);
      setScanStatus("idle");
      return { ok: false, error: msg };
    } finally {
      if (!sequentialPart) setLoading(false);
    }
  }

  /**
   * Ejecuta un scan completo por cada clave, en orden (misma validación que handleScan).
   * @param {string[]} [keys] Si se omite, usa selectedEndpoints.
   */
  async function handleScanSequential(keys, options = {}) {
    const postmanOnly = Boolean(options.postmanOnly);
    const list = (Array.isArray(keys) ? keys : selectedEndpoints).filter(
      (k) => typeof k === "string" && k.trim()
    );
    if (!list.length) {
      setError("Selecciona al menos un endpoint en la lista.");
      return { ok: false, results: [] };
    }

    const trimmedApi = (apiUrl || "").trim();
    if (apiCollectionFile != null) {
      if (apiEndpoints.length === 0) {
        setError(
          "Antes del análisis secuencial: pulsa «Armar endpoints» para cargar la colección."
        );
        return { ok: false, results: [] };
      }
      const details = apiEndpoints.filter((ep) => list.includes(endpointKey(ep)));
      if (details.length > 0 && !trimmedApi && anyEndpointNeedsApiBase(details)) {
        setError(
          "Falta la URL base del API para rutas relativas o variables (p. ej. {{base_url}})."
        );
        return { ok: false, results: [] };
      }
    }

    setError(null);
    resetResults();
    setLoading(true);
    setSequentialScan({ running: true, index: 0, total: list.length, currentKey: list[0] || "" });

    const results = [];
    const onItemComplete = typeof options.onItemComplete === "function" ? options.onItemComplete : null;

    for (let i = 0; i < list.length; i++) {
      const key = list[i];
      setSequentialScan({
        running: true,
        index: i + 1,
        total: list.length,
        currentKey: key,
      });
      let out;
      try {
        out = await handleScan(null, {
          endpointKeys: [key],
          sequentialPart: true,
          skipResetResults: i > 0,
          postmanOnly,
        });
      } catch (err) {
        out = { ok: false, error: err?.message || String(err) };
      }
      if (!out || typeof out !== "object") {
        out = { ok: false, error: "Respuesta de scan inválida" };
      }
      results.push({ key, ...out });
      onItemComplete?.(key, out);
    }

    setLoading(false);
    setSequentialScan({ running: false, index: 0, total: 0, currentKey: "" });

    const failed = results.filter((r) => !r.ok);
    const ok = results.some((r) => r.ok);
    if (failed.length === results.length) {
      setError(
        failed.length === 1
          ? failed[0].error || "El análisis falló."
          : `Los ${failed.length} análisis fallaron. Último: ${failed[failed.length - 1].error || "error"}.`
      );
    } else if (failed.length > 0) {
      setError(
        `${failed.length} de ${results.length} análisis fallaron; el resto terminó correctamente.`
      );
    } else {
      setError(null);
    }

    return { ok, results };
  }

  async function handleListApis() {
    setError(null); setInferringApi(true);
    try {
      const res = await fetch(`${API_BASE}/infer-api`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          path,
          limit: 80,
          languages: selectedLanguages.length ? selectedLanguages : undefined,
        }),
      });
      if (!res.ok) {
        const msg = await errorMessage(res);
        if (res.status === 404) {
          throw new Error(
            `${msg} La ruta debe existir en el equipo donde corre el backend (puerto 8000). ` +
              "Si elegiste carpeta y el campo sigue en ./project o vacío, pega la ruta absoluta desde el Explorador."
          );
        }
        throw new Error(msg);
      }
      const data = await res.json();
      const raw = Array.isArray(data.candidates) ? data.candidates : [];
      const seen = new Set();
      const list = [];
      for (const u of raw) {
        const s = typeof u === "string" ? u.trim() : "";
        if (!s || seen.has(s) || isNonPublicApiBaseUrl(s)) continue;
        seen.add(s);
        list.push(s);
      }
      setApiCandidates(list);
      if (list.length === 0) {
        setError(
          "No se encontraron URLs de API públicas en el código (las locales/LAN no se listan). Probá: marcar más **lenguajes** a la derecha " +
            "(p. ej. TypeScript, JavaScript, Python), comprobar que la **ruta** sea la carpeta raíz del repo en el servidor, " +
            "o ingresá la URL base a mano en el paso 2."
        );
        return;
      }
      const trimmed = (apiUrl || "").trim();
      if (!trimmed || isNonPublicApiBaseUrl(trimmed)) {
        setApiUrl(list[0]);
        await handleListEndpoints(list[0]);
      }
    } catch (err) {
      setError(isNetworkFetchError(err) ? networkErrorUserMessage() : err?.message || String(err));
    } finally { setInferringApi(false); }
  }

  async function handleListEndpoints(apiOverride = null) {
    const selectedApi = (apiOverride || apiUrl || "").trim();
    if (!selectedApi) { setError("Selecciona o ingresa una API base para listar endpoints."); return; }
    setError(null); setLoadingEndpoints(true);
    try {
      const res = await fetch(`${API_BASE}/infer-endpoints`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          path,
          api_url: selectedApi,
          limit: 1000,
          languages: selectedLanguages.length ? selectedLanguages : undefined,
        }),
      });
      if (!res.ok) {
        const msg = await errorMessage(res);
        if (res.status === 404) {
          throw new Error(
            `${msg} La ruta del proyecto debe ser válida en el servidor del scan (misma que para Detectar APIs).`
          );
        }
        throw new Error(msg);
      }
      const data = await res.json();
      const list = Array.isArray(data.endpoints) ? data.endpoints : [];
      setApiEndpoints(list);
      setSelectedEndpoints(list.map(endpointKey).filter(Boolean));
      if (list.length === 0) setError("No encontré endpoints asociados a esa API en el código.");
    } catch (err) {
      setError(isNetworkFetchError(err) ? networkErrorUserMessage() : err?.message || String(err));
    } finally { setLoadingEndpoints(false); }
  }

  async function previewApiCollection(file) {
    if (!file) {
      setError("Selecciona un archivo de colección (JSON).");
      return;
    }
    if (previewCollectionLoading) return;
    setError(null);
    setPreviewCollectionLoading(true);
    try {
      const fd = new FormData();
      if ((apiUrl || "").trim()) fd.append("api_url", (apiUrl || "").trim());
      fd.append("collection_file", file);
      const res = await fetch(`${API_BASE}/parse-api-collection`, { method: "POST", body: fd });
      if (!res.ok) throw new Error(await errorMessage(res));
      const data = await res.json();
      const raw = Array.isArray(data.endpoints) ? data.endpoints : [];
      const eps = dedupeApiEndpoints(raw);
      setApiEndpoints(eps);
      const keys = [...new Set(eps.map(endpointKey).filter(Boolean))];
      setSelectedEndpoints(keys);
      if (!(apiUrl || "").trim() && data.suggested_api_url) {
        setApiUrl(String(data.suggested_api_url));
      }
    } catch (err) {
      setError(isNetworkFetchError(err) ? networkErrorUserMessage() : err?.message || String(err));
    } finally {
      setPreviewCollectionLoading(false);
    }
  }

  async function fetchAuthHintsFromRepo() {
    const p = (path || "").trim();
    if (!p) {
      setAuthHintMessage("Indicá la ruta del proyecto (paso 1) en el servidor del escáner.");
      return;
    }
    setAuthHintMessage(null);
    setLoadingAuthHints(true);
    try {
      const res = await fetch(`${API_BASE}/infer-auth-hints`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          path: p,
          languages: selectedLanguages.length ? selectedLanguages : undefined,
          limit: 20,
        }),
      });
      if (!res.ok) throw new Error(await errorMessage(res));
      const data = await res.json();
      const hints = Array.isArray(data.hints) ? data.hints : [];
      if (hints.length === 0) {
        setAuthHintMessage(
          "No encontré JWT literales en el repo (.env, JS/TS). Podés dejar vacío: el scan corre igual; solo faltan chequeos JWT/BOLA. Si el token está en runtime, pegalo a mano.",
        );
        return;
      }
      const first = hints[0];
      const token = String(first?.token ?? first?.value ?? "").trim();
      if (token) setAuthToken(token);
      const loc = `${first?.file ?? "?"}:${first?.line ?? "?"}`;
      const src = first?.source ?? first?.kind ?? "repo";
      if (hints.length === 1) {
        setAuthHintMessage(
          token
            ? `Token copiado desde ${loc} (${src}).`
            : `Candidato en ${loc} sin token legible; pegalo a mano.`,
        );
      } else {
        setAuthHintMessage(
          token
            ? `Hay ${hints.length} candidatos; se usó el primero (${loc}, ${src}). Revisá o pegá otro.`
            : `Hay ${hints.length} candidatos en el repo; el primero (${loc}) no trajo token — pegalo a mano.`,
        );
      }
      if (hints.length > 1 && token && hints[1]) {
        const second = String(hints[1]?.token ?? hints[1]?.value ?? "").trim();
        if (second && !(secondToken || "").trim()) setSecondToken(second);
      }
    } catch (e) {
      setAuthHintMessage(isNetworkFetchError(e) ? networkErrorUserMessage() : e?.message || String(e));
    } finally {
      setLoadingAuthHints(false);
    }
  }

  function toggleEndpoint(url) {
    setSelectedEndpoints((prev) =>
      prev.includes(url) ? prev.filter((x) => x !== url) : [...prev, url]
    );
  }

  return {
    path, setPath, apiUrl, setApiUrl, loading, error, setError,
    rows, lastScanId, summary, folderHint, dynamicInfo, externalImport,
    runZapBaseline, setRunZapBaseline, runProjectTests, setRunProjectTests, zapBaselineInfo, apiCandidates, apiEndpoints,
    selectedEndpoints, inferringApi, loadingEndpoints, zapFile, setZapFile,
    burpFile, setBurpFile, apiCollectionFile, setApiCollectionFile,
    previewCollectionLoading, previewApiCollection, clearForJsonMode,
    preparePostmanOneByOneMode,
    prepareCodeOnlyScanMode,
    selectedChecks, setSelectedChecks, selectedLanguages,
    setSelectedLanguages, checksCatalog, scanStatus, selectedEndpointDetails,
    folderInputRef, handleFolderChange, toggleListValue, handleScan,
    handleScanSequential, sequentialScan,
    handleListApis, handleListEndpoints, toggleEndpoint,
    selectAllEndpoints: () => setSelectedEndpoints(apiEndpoints.map(endpointKey).filter(Boolean)),
    clearEndpoints: () => setSelectedEndpoints([]),
    /** Alcance de exactamente un endpoint (modo análisis uno a uno). */
    selectSingleEndpoint: (key) =>
      setSelectedEndpoints(typeof key === "string" && key.trim() ? [key.trim()] : []),
    loadChecksCatalog,
    runAdvancedChecks, setRunAdvancedChecks,
    scanInsight,
    authToken, setAuthToken, secondToken, setSecondToken,
    authHeadersJson, setAuthHeadersJson,
    authHintMessage, loadingAuthHints, fetchAuthHintsFromRepo,
  };
}
