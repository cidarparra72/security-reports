/**
 * Fallback Pages Router para errores internos de Next (p. ej. cuando falla el render
 * y el dev server busca /_error). El flujo principal sigue en app/.
 */
export default function ErrorPage({ statusCode }) {
  return (
    <div style={{ padding: 32, fontFamily: "system-ui, sans-serif", background: "#edf1f5", minHeight: "100vh" }}>
      <h1 style={{ color: "#111820" }}>Error</h1>
      <p style={{ color: "#53616d" }}>
        {statusCode ? `Código ${statusCode}` : "Error en el cliente"}
      </p>
      <p style={{ marginTop: 16 }}>
        <a href="/" style={{ color: "#126b7f", fontWeight: 700 }}>
          Volver al inicio
        </a>
      </p>
    </div>
  );
}

ErrorPage.getInitialProps = ({ res, err }) => {
  const statusCode = res ? res.statusCode : err ? err.statusCode : 404;
  return { statusCode };
};
