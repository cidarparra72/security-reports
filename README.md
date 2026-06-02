# 🔒 Alipay Mini Program Security Scanner

Sistema de escaneo de vulnerabilidades para Mini Programs de Alipay con integración Azure DevOps.

## 📋 Características

- **Escaneo de APIs**: Detecta vulnerabilidades comunes en mini programs
- **Análisis de dependencias**: Escanea librerías con vulnerabilidades conocidas
- **Detección de secretos**: Encuentra API keys y credenciales expuestas
- **Reportes HTML**: Genera reportes visuales de vulnerabilidades
- **Integración Azure DevOps**: Pipeline listo para CI/CD

## 🚀 Inicio Rápido

**Guía paso a paso (1, 2, 3… hasta tener API + web):** [`PASOS-ARRANQUE.md`](./PASOS-ARRANQUE.md)

### Prerrequisitos

- **Python 3.9 a 3.13** (recomendado **3.13**). En Windows, si el comando `python` abre una versión **rota** (p. ej. 3.14 sin librería estándar), usa el launcher **`py -3.13`** o el intérprete de **`.venv`** tras `dev-setup.ps1`.
- **Node.js 18+** (para la UI en `client/`).

### Instalación (Windows, PowerShell)

```powershell
cd security-reports
powershell -ExecutionPolicy Bypass -File dev-setup.ps1
```

### UI + API (dos terminales)

```powershell
# Terminal 1 — backend http://127.0.0.1:8000
powershell -ExecutionPolicy Bypass -File run-backend.ps1

# Terminal 2 — frontend http://localhost:3000
powershell -ExecutionPolicy Bypass -File run-frontend.ps1
```

O con npm (misma carpeta raíz del repo):

```powershell
npm run dev:backend
npm run dev:client
```

### Instalación (Linux / macOS o sin scripts)

```bash
cd security-reports
python3.13 -m venv .venv
source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
npm install --prefix client
```

Tras crear `.venv`, en VS Code / Cursor elegí como intérprete **`.venv/Scripts/python.exe`** (Windows) o **`.venv/bin/python`** (Linux/macOS).

### Uso básico (CLI)

```bash
# Con el venv activado (o usando py -3.13 en Windows):
python -m src.security.api_scanner --path ./mi-proyecto

python -m src.security.api_scanner --path ./mi-proyecto --output reporte.json
python -m src.security.report_generator --input reporte.json --output reporte.html
```

## 📁 Estructura del Proyecto

```
security-reports/
├── azure-pipelines.yml    # Pipeline de Azure DevOps
├── package.json           # Configuración npm
├── requirements.txt       # Dependencias Python
├── src/
│   └── security/
│       ├── __init__.py
│       ├── api_scanner.py      # Escáner de vulnerabilidades
│       └── report_generator.py # Generador de reportes
└── README.md
```

## 🔧 Configuración Azure DevOps

### 1. Agregar el Pipeline

1. Ve a **Azure DevOps** → **Pipelines** → **New Pipeline**
2. Selecciona **Azure Repos Git**
3. Selecciona tu repositorio
4. Elige **Existing Azure Pipelines YAML file**
5. Selecciona `security-reports/azure-pipelines.yml`
6. Click en **Run**

### 2. Configurar Variables

En Azure DevOps, configura estas variables en el pipeline:

| Variable | Descripción | Valor por defecto |
|----------|-------------|-------------------|
| `azureServiceConnection` | Conexión a Azure | - |
| `criticalVulnerabilities` | Máximo de críticos | 0 |
| `highVulnerabilities` | Máximo de altos | 0 |
| `mediumVulnerabilities` | Máximo de medios | 5 |

### 3. Configurar Service Connection

Para publicar reportes, necesitas una Azure Service Connection:
1. Project Settings → Service connections
2. New service connection → Azure Resource Manager
3. Selecciona tu suscripción y recurso

## 📊 Vulnerabilidades Detectadas

### Categorías

| Categoría | Severidad | Descripción |
|-----------|-----------|-------------|
| Hardcoded Secrets | 🔴 CRITICAL | API keys/secretos en código |
| SQL Injection | 🔴 CRITICAL | Inyección SQL potencial |
| Insecure HTTP | 🟠 HIGH | Endpoints sin HTTPS |
| Missing Auth | 🟠 HIGH | Sin verificación de autenticación |
| XSS | 🟡 MEDIUM | Cross-site scripting |
| Weak Crypto | 🟡 MEDIUM | Algoritmos criptográficos débiles |
| Debug Mode | 🟢 LOW | Modo debug habilitado |

## 🔍 Escaneo Personalizado

### Agregar nuevos patrones

Edita `src/security/api_scanner.py` y agrega un nuevo patrón:

```python
{
    "id": "NEW_PATTERN",
    "severity": "HIGH",
    "category": "Nueva Categoría",
    "title": "Nueva Vulnerabilidad",
    "description": "Descripción",
    "pattern": r'tu regex aquí',
    "recommendation": "Recomendación",
    "cwe": "CWE-XXX"
}
```

## 📈 Integración con Pull Requests

El pipeline incluye un **Security Gate** que se ejecuta en PRs:

```yaml
- stage: SecurityGate
  condition: eq(variables['Build.Reason'], 'PullRequest')
```

Puedes configurar que el PR se bloquee si hay vulnerabilidades críticas.

## 🛠️ Comandos Útiles

```bash
# Escanear solo archivos JavaScript
python -m src.security.api_scanner --path ./src --output scan.json

# Generar reporte desde múltiples scans
python -m src.security.report_generator \
  --input audit-report.json \
  --input api-scan-report.json \
  --output security-report.html

# Ver ayuda
python -m src.security.api_scanner --help
python -m src.security.report_generator --help
```

## 📝 Licencia

MIT © 2026 Security Team