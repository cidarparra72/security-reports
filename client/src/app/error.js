"use client";

import "./globals.css";

export default function Error({ error, reset }) {
  return (
    <main className="app-shell" style={{ paddingTop: 48 }}>
      <div className="panel control-panel">
        <p className="eyebrow">Error</p>
        <h1>Algo salió mal</h1>
        <p className="subtitle" style={{ color: "#8c2f25" }}>
          {error?.message || "Error inesperado al cargar la página."}
        </p>
        <button type="button" className="button primary" onClick={() => reset()}>
          Reintentar
        </button>
      </div>
    </main>
  );
}
