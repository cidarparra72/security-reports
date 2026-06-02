/** @type {import('next').NextConfig} */
const api = process.env.NEXT_PROXY_API ?? "http://127.0.0.1:8000";

const nextConfig = {
  async rewrites() {
    return [
      { source: "/scans", destination: `${api}/scans` },
      { source: "/scan/:path*", destination: `${api}/scan/:path*` },
      { source: "/infer-api", destination: `${api}/infer-api` },
      { source: "/infer-endpoints", destination: `${api}/infer-endpoints` },
      { source: "/infer-auth-hints", destination: `${api}/infer-auth-hints` },
      { source: "/parse-api-collection", destination: `${api}/parse-api-collection` },
      { source: "/checks/:path*", destination: `${api}/checks/:path*` },
      { source: "/manual-checks/:path*", destination: `${api}/manual-checks/:path*` },
      { source: "/report", destination: `${api}/report` },
      { source: "/report/:path*", destination: `${api}/report/:path*` },
      { source: "/reports/:path*", destination: `${api}/reports/:path*` },
      // Rutas explícitas: el patrón :path* a veces no reenvía bien a destinos externos en Windows.
      { source: "/api-probe/prepare", destination: `${api}/api-probe/prepare` },
      { source: "/api-probe/run", destination: `${api}/api-probe/run` },
      { source: "/api-probe/zap-baseline", destination: `${api}/api-probe/zap-baseline` },
      { source: "/api-probe/:path*", destination: `${api}/api-probe/:path*` },
      { source: "/scan-api/static", destination: `${api}/scan-api/static` },
      { source: "/scan-api/live", destination: `${api}/scan-api/live` },
      { source: "/scan-api/report-pdf", destination: `${api}/scan-api/report-pdf` },
    ];
  },
};

export default nextConfig;
