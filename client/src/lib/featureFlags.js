/**
 * Qué modos mostrar en la UI (Vercel / live sin Docker ni ZAP).
 *
 * NEXT_PUBLIC_SCANNER_FEATURES — lista separada por comas:
 *   code      → Escanear código del repositorio (SAST)
 *   historial → Historial y descarga de reportes
 *   dast      → API en vivo, Probe, ZAP, scanApi, colección Postman
 *
 * Si no se define, se habilitan todos (desarrollo local).
 *
 * Ejemplo live: NEXT_PUBLIC_SCANNER_FEATURES=code,historial
 */

const ALL = ["code", "historial", "dast"];

function parseFeatureSet() {
  const raw = process.env.NEXT_PUBLIC_SCANNER_FEATURES;
  if (raw == null || String(raw).trim() === "") {
    return new Set(ALL);
  }
  return new Set(
    String(raw)
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean)
  );
}

const ENABLED = parseFeatureSet();

export function hasScannerFeature(id) {
  return ENABLED.has(String(id).toLowerCase());
}

/** Modos que requieren API en vivo, Docker o OWASP ZAP. */
export function isDastEnabled() {
  return hasScannerFeature("dast");
}

export function isCodeScanEnabled() {
  return hasScannerFeature("code");
}

export function isHistorialEnabled() {
  return hasScannerFeature("historial");
}
