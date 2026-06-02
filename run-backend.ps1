# Backend API (FastAPI). Preferimos .venv del repo; si no existe, py -3.13 (evita `python` → 3.14 roto).
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$venvPy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (Test-Path $venvPy) {
    & $venvPy -m uvicorn server:app --host 127.0.0.1 --port 8000
    exit $LASTEXITCODE
}

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    Write-Host "No hay .venv ni launcher 'py'. Ejecuta primero: .\dev-setup.ps1" -ForegroundColor Red
    exit 1
}

Write-Host 'Aviso: no existe .venv; se usa py -3.13. Para entorno fijo: .\dev-setup.ps1' -ForegroundColor Yellow
py -3.13 -m uvicorn server:app --host 127.0.0.1 --port 8000
