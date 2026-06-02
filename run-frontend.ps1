# Next.js en http://localhost:3000 (reenvía API a :8000 según next.config.mjs)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "client")

$apiUp = $false
$tcp = $null
try {
    $tcp = [System.Net.Sockets.TcpClient]::new()
    $iar = $tcp.BeginConnect("127.0.0.1", 8000, $null, $null)
    if ($iar.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds(2))) {
        $tcp.EndConnect($iar)
        $apiUp = $tcp.Connected
    }
} catch {
    $apiUp = $false
} finally {
    if ($null -ne $tcp) { $tcp.Close() }
}

if (-not $apiUp) {
    Write-Host ""
    Write-Host "  *** AVISO: no hay proceso escuchando en 127.0.0.1:8000 ***" -ForegroundColor Yellow
    Write-Host "  En otra terminal (raiz del repo):  npm run dev:backend" -ForegroundColor Yellow
    Write-Host "  Sin el API, Next dev responde «Internal Server Error» al proxy (/checks/catalog, /infer-api, ...)." -ForegroundColor Yellow
    Write-Host ""
}

$nextSemver = "node_modules\next\dist\compiled\semver\index.js"
if (-not (Test-Path "node_modules")) {
    npm install
} elseif (-not (Test-Path $nextSemver)) {
    Write-Host "node_modules incompleto (falta Next). Ejecutando npm run fresh-install..." -ForegroundColor Yellow
    npm run fresh-install
}

npm run dev
