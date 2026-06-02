"use client";

export default function GlobalError({ error, reset }) {
  return (
    <html lang="es">
      <body style={{ fontFamily: "system-ui, sans-serif", padding: 24, background: "#edf1f5" }}>
        <h1 style={{ color: "#111820" }}>Error de aplicación</h1>
        <p style={{ color: "#53616d" }}>{error?.message || "Error crítico."}</p>
        <button
          type="button"
          onClick={() => reset()}
          style={{
            marginTop: 16,
            padding: "10px 16px",
            borderRadius: 8,
            border: "none",
            background: "#126b7f",
            color: "#fff",
            cursor: "pointer",
            fontWeight: 700,
          }}
        >
          Reintentar
        </button>
      </body>
    </html>
  );
}
