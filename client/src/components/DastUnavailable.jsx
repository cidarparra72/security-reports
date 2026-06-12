import Link from "next/link";

/** Pantalla cuando se accede a una ruta DAST deshabilitada en live. */
export function DastUnavailable({ title = "Modo no disponible" }) {
  return (
    <main className="app-shell">
      <section className="panel" style={{ maxWidth: 560, margin: "2rem auto" }}>
        <p className="eyebrow">Security reports</p>
        <h1>{title}</h1>
        <p className="subtitle">
          Este entorno está configurado solo para <strong>análisis de código</strong> e{" "}
          <strong>historial de reportes</strong>. Las pruebas contra API en vivo, Probe HTTP y OWASP
          ZAP (Docker) no están habilitadas aquí.
        </p>
        <div style={{ display: "flex", gap: 12, marginTop: 20, flexWrap: "wrap" }}>
          <Link className="button primary" href="/">
            Ir al análisis de código
          </Link>
          <Link className="button secondary" href="/historial">
            Ver historial
          </Link>
        </div>
      </section>
    </main>
  );
}
