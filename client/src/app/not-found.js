import Link from "next/link";
import "./globals.css";

export default function NotFound() {
  return (
    <main className="app-shell" style={{ paddingTop: 48 }}>
      <div className="panel control-panel">
        <p className="eyebrow">404</p>
        <h1>Página no encontrada</h1>
        <p className="subtitle">La ruta solicitada no existe.</p>
        <Link href="/" className="button primary" style={{ display: "inline-flex", marginTop: 12, textDecoration: "none" }}>
          Volver al inicio
        </Link>
      </div>
    </main>
  );
}
