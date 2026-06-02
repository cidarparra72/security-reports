# Crea .venv con Python 3.13 e instala dependencias (Windows).
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    Write-Host "Instala Python 3.13 desde python.org (incluye el launcher 'py')." -ForegroundColor Red
    exit 1
}

Write-Host "Creando .venv con Python 3.13..." -ForegroundColor Cyan
py -3.13 -m venv .venv

$pip = Join-Path $PSScriptRoot ".venv\Scripts\pip.exe"
& $pip install -r requirements.txt

$extReq = Join-Path $PSScriptRoot "requirements-external.txt"
if (Test-Path $extReq) {
    Write-Host "Instalando herramientas Python externas (semgrep, schemathesis)..." -ForegroundColor Cyan
    & $pip install -r $extReq
}

Write-Host "Listo. Usa run-backend.ps1 o: .\.venv\Scripts\python.exe -m uvicorn server:app --host 127.0.0.1 --port 8000" -ForegroundColor Green
Write-Host "Opcional (trivy, grype, nuclei): .\install-external-tools.ps1" -ForegroundColor DarkGray
