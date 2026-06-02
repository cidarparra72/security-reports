# Pasos para levantar el proyecto (API + interfaz)

Hacé los pasos **en orden**. Necesitás **dos ventanas de PowerShell** (o pestañas) para el backend y el frontend a la vez.

**Carpeta raíz del repo:** `e:\revision\security-reports` (adaptá la ruta si la moviste).

---

## 1. Abrir PowerShell en la raíz del repo

```powershell
Set-Location "e:\revision\security-reports"
```

---

## 2. Instalar dependencias Python y crear el entorno virtual (solo la primera vez o tras borrar `.venv`)

```powershell
powershell -ExecutionPolicy Bypass -File .\dev-setup.ps1
```

Esperá a que termine sin errores. Si falla, revisá que exista el launcher `py` y Python 3.13 (`py -3.13 --version`).

---

## 3. (Opcional) Instalar dependencias del cliente si aún no lo hiciste

```powershell
Set-Location "e:\revision\security-reports\client"
npm install
Set-Location "e:\revision\security-reports"
```

Si ya tenés `client\node_modules`, podés saltear este paso.

---

## 4. Levantar el **backend** (API en el puerto 8000)

Abrí **la primera** terminal, en la raíz del repo:

```powershell
Set-Location "e:\revision\security-reports"
powershell -ExecutionPolicy Bypass -File .\run-backend.ps1
```

Dejá esta ventana **abierta**. Deberías ver algo como: `Uvicorn running on http://127.0.0.1:8000`.

**Comprobación rápida (otra terminal o navegador):** abrí `http://127.0.0.1:8000/docs` o `http://127.0.0.1:8000/checks/catalog`.

---

## 5. Levantar el **frontend** (Next.js, suele ser puerto 3000)

Abrí **una segunda** terminal (dejá la del backend corriendo):

```powershell
Set-Location "e:\revision\security-reports"
powershell -ExecutionPolicy Bypass -File .\run-frontend.ps1
```

Dejá esta ventana **abierta**. En la salida te indica la URL (normalmente `http://localhost:3000`).

---

## 6. Abrir la aplicación en el navegador

Entrá a la URL que muestra Next, por ejemplo:

`http://localhost:3000`

El front reenvía las peticiones al API en `:8000` según la configuración del proyecto.

---

## Resumen rápido (si ya tenés todo instalado)

| Orden | Dónde | Comando |
|------|--------|---------|
| 1 | Raíz | `powershell -ExecutionPolicy Bypass -File .\dev-setup.ps1` (solo cuando haga falta) |
| 2 | Terminal A, raíz | `powershell -ExecutionPolicy Bypass -File .\run-backend.ps1` |
| 3 | Terminal B, raíz | `powershell -ExecutionPolicy Bypass -File .\run-frontend.ps1` |
| 4 | Navegador | `http://localhost:3000` |

Equivalente con **npm** (desde la raíz):

1. `npm run setup` — misma idea que `dev-setup.ps1` (cuando haga falta)  
2. `npm run dev:backend` — terminal A  
3. `npm run dev:client` — terminal B  

---

## Si algo no arranca

### El front no levanta (Next) — error `MODULE_NOT_FOUND` / `semver` / archivos dentro de `next`

Suele ser **`node_modules` incompleto o corrupto** (corte de luz, antivirus, copia a medias). En la carpeta `client`:

```powershell
Set-Location "e:\revision\security-reports\client"
npm run fresh-install
npm run dev
```

O manual: borrá la carpeta `client\node_modules` y el archivo `client\package-lock.json`, luego `npm install` otra vez.

### Otros

- **No uses** `python` solo si te falla con errores raros de librería estándar: usá los scripts o `py -3.13`.
- **Puerto 8000 ocupado:** cerrá el otro proceso que use ese puerto o cambiá el puerto en `run-backend.ps1` (y en `client/next.config.mjs` el proxy debe apuntar al mismo host/puerto).
- **Puerto 3000 ocupado:** Next suele proponer el 3001; seguí la URL que imprime la consola.
- **Docker / ZAP:** el backend debe ver el comando `docker` en el PATH si vas a usar ZAP baseline desde la UI.

---

## Parar todo

En cada terminal donde corre el servidor: **Ctrl+C**.
