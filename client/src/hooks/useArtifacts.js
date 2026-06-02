import { useState } from "react";
import { API_BASE, errorMessage } from "./useScan";

export function useArtifacts(lastScanId) {
  const [jsonArtifacts, setJsonArtifacts] = useState([]);
  const [selectedArtifactUrl, setSelectedArtifactUrl] = useState("");
  const [selectedArtifactName, setSelectedArtifactName] = useState("");
  const [artifactAnalysis, setArtifactAnalysis] = useState(null);
  const [artifactLoading, setArtifactLoading] = useState(false);
  const [error, setError] = useState(null);

  function artifactHref(url) {
    return String(url || "").startsWith("http") ? url : `${API_BASE}${url}`;
  }

  function summarizeJsonArtifact(name, payload) {
    if (payload == null || typeof payload !== "object")
      return { kind: "generic", notes: ["El archivo no es un objeto JSON válido."] };
    const keys = Object.keys(payload);
    if (payload.openapi || payload.swagger) {
      const pathCount =
        payload.paths && typeof payload.paths === "object" ? Object.keys(payload.paths).length : 0;
      return {
        kind: "swagger_openapi",
        notes: [`Spec detectada: ${payload.openapi ? "OpenAPI" : "Swagger"}`, `Endpoints en paths: ${pathCount}`],
      };
    }
    if (Array.isArray(payload.site)) {
      const alerts = payload.site.reduce((acc, s) => acc + (Array.isArray(s.alerts) ? s.alerts.length : 0), 0);
      return { kind: "zap", notes: [`Sitios analizados: ${payload.site.length}`, `Alertas: ${alerts}`] };
    }
    if (Array.isArray(payload.issues)) return { kind: "burp", notes: [`Issues: ${payload.issues.length}`] };
    if (Array.isArray(payload.results)) return { kind: "semgrep", notes: [`Resultados: ${payload.results.length}`] };
    if (Array.isArray(payload.Results)) {
      const vulns = payload.Results.reduce(
        (acc, r) => acc + (Array.isArray(r.Vulnerabilities) ? r.Vulnerabilities.length : 0), 0
      );
      return { kind: "trivy", notes: [`Targets: ${payload.Results.length}`, `Vulnerabilidades: ${vulns}`] };
    }
    if (Array.isArray(payload.matches)) return { kind: "grype", notes: [`Matches: ${payload.matches.length}`] };
    if (Array.isArray(payload)) return { kind: "array", notes: [`Arreglo JSON con ${payload.length} elementos.`] };
    return { kind: "generic", notes: [`Archivo: ${name}`, `Claves: ${keys.slice(0, 12).join(", ") || "(sin claves)"}`] };
  }

  async function handleLoadJsonArtifacts() {
    if (!lastScanId) return;
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/scan/${lastScanId}/artifacts`);
      if (!res.ok) throw new Error(await errorMessage(res));
      const data = await res.json();
      const list = Array.isArray(data.artifacts) ? data.artifacts : [];
      setJsonArtifacts(list);
      if (list.length > 0) {
        setSelectedArtifactUrl(list[0].url || "");
        setSelectedArtifactName(list[0].name || "");
      } else {
        setError("No hay artefactos JSON disponibles para este scan.");
      }
    } catch (err) { setError(err?.message || String(err)); }
  }

  async function handleAnalyzeSelectedArtifact() {
    if (!selectedArtifactUrl) return;
    setError(null); setArtifactAnalysis(null); setArtifactLoading(true);
    try {
      const res = await fetch(artifactHref(selectedArtifactUrl));
      if (!res.ok) throw new Error(await errorMessage(res));
      const data = await res.json();
      setArtifactAnalysis(summarizeJsonArtifact(selectedArtifactName || selectedArtifactUrl, data));
    } catch (err) { setError(err?.message || String(err)); }
    finally { setArtifactLoading(false); }
  }

  function openArtifactByKind(kindPrefix) {
    const item = jsonArtifacts.find((a) => String(a.kind || "").startsWith(kindPrefix));
    if (!item?.url) { setError(`No se encontró artefacto para ${kindPrefix}.`); return; }
    window.open(artifactHref(item.url), "_blank", "noopener,noreferrer");
  }

  function selectArtifact(url) {
    setSelectedArtifactUrl(url);
    const hit = jsonArtifacts.find((x) => x.url === url);
    setSelectedArtifactName(hit?.name || "");
    setArtifactAnalysis(null);
  }

  return {
    jsonArtifacts, selectedArtifactUrl, selectedArtifactName,
    artifactAnalysis, artifactLoading, error,
    handleLoadJsonArtifacts, handleAnalyzeSelectedArtifact,
    openArtifactByKind, selectArtifact, artifactHref,
  };
}
