import Link from "next/link";
import "./globals.css";
import { isDastEnabled, isHistorialEnabled } from "../lib/featureFlags";

export const metadata = {
  title: "Security Scanner",
  description: "API Security Scanner",
};

export default function RootLayout({ children }) {
  return (
    <html lang="es">
      <body>
        <nav className="app-nav" aria-label="Navegación principal">
          <Link href="/">Inicio</Link>
          {isHistorialEnabled() && <Link href="/historial">Historial</Link>}
          {isDastEnabled() && <Link href="/probe">Probe HTTP</Link>}
        </nav>
        {children}
      </body>
    </html>
  );
}
