#!/usr/bin/env python3
"""
Inferencia heurística de URL base del API y de endpoints desde el código fuente.
Usado por el servidor FastAPI (/infer-api, /infer-endpoints) y por ZAP baseline CLI.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from .scan_scope import extensions_for_languages

_SKIP_DIRS = frozenset(
    {
        "node_modules",
        "bower_components",
        ".pnpm",
        "dist",
        "build",
        ".git",
        "vendor",
        ".next",
        "__pycache__",
        ".venv",
        "venv",
        "coverage",
        "target",
    }
)
_SKIP_DIRS_LOWER = frozenset(d.lower() for d in _SKIP_DIRS)

_URL_RE = re.compile(r"https?://[^\s\"'`<\])]+", re.IGNORECASE)
# URLs en config (utils/request.js, constants.ts, etc.)
_CONFIG_URL_RES: Tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?:baseURL|baseUrl|BASE_URL|base_url|apiURL|API_URL|apiUrl|apiHost|API_HOST|serverURL|SERVER_URL|"
        r"BACKEND_URL|backendUrl|requestHost|REQUEST_HOST|gatewayUrl|GATEWAY_URL|"
        r"userInfo|ursUrl|urlMerchant|urlVepayMerchant|urlVepayServiceRegister)"
        r"\s*(?::|=)\s*['\"](https?://[^'\"`\s>]+)['\"]",
        re.I,
    ),
    re.compile(
        r"(?:host|hostname|origin|domain)\s*(?::|=)\s*['\"](https?://[^'\"`\s>]+)['\"]",
        re.I,
    ),
    re.compile(
        r"(?:baseURL|baseUrl|BASE_URL|apiURL|API_URL)\s*(?::|=)\s*`(https?://[^`$\s]+)`",
        re.I,
    ),
)
# Rutas tipo '/v1/users' o "/api/health" en comillas
_QUOTED_PATH_RE = re.compile(
    r"""['"](/[a-zA-Z0-9_\-./?=&%*+:@{}[\]]{1,240}?)['"]"""
)

# Manifest npm + lockfiles: registries / mirrors — no inferir API desde aquí.
_SKIP_INFER_FILE_NAMES_LOWER = frozenset(
    n.lower()
    for n in (
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
    )
)

_INFER_NOISE_NETLOCS = frozenset(
    {
        "registry.npmjs.org",
        "registry.npmmirror.com",
        "www.npmjs.com",
        "npm.pkg.github.com",
        "registry.yarnpkg.com",
        "registry.yarnpkg.io",
        "unpkg.com",
        "www.unpkg.com",
        "cdn.jsdelivr.net",
        "cdnjs.cloudflare.com",
    }
)


def _norm_origin(url: str) -> str:
    p = urlparse((url or "").strip())
    if p.scheme not in ("http", "https") or not p.netloc:
        return ""
    return f"{p.scheme}://{p.netloc}"


def _infer_noise_netloc(netloc: str) -> bool:
    """Registries npm, mirrors chinos, CDNs de paquetes: no son la API de la app."""
    nl = (netloc or "").strip().lower()
    if not nl:
        return False
    if nl in _INFER_NOISE_NETLOCS:
        return True
    if nl.endswith(".npmmirror.com") or nl.endswith(".npmjs.org"):
        return True
    if nl.endswith(".yarnpkg.com") or nl.endswith(".yarnpkg.io"):
        return True
    return False


def _url_is_infer_noise(raw: str) -> bool:
    p = urlparse((raw or "").strip().rstrip(".,);'\""))
    if p.scheme not in ("http", "https") or not p.netloc:
        return False
    return _infer_noise_netloc(p.netloc)


def _infer_candidate_url_is_non_public(url: str) -> bool:
    """
    Bases LAN / loopback / link-local / .local: no listar en «APIs detectadas».
    (Se puede seguir pegando a mano en el input si hace falta probar local.)
    """
    try:
        pu = urlparse((url or "").strip())
    except ValueError:
        return True
    if pu.scheme not in ("http", "https") or not pu.netloc:
        return True
    host = pu.netloc.split("@")[-1].strip()
    if host.startswith("["):
        bracket = host.find("]")
        host = host[1:bracket] if bracket > 0 else host
    else:
        if ":" in host:
            if host.count(":") == 1:
                host = host.rsplit(":", 1)[0]
    host = host.strip().lower()
    if not host:
        return True
    if host == "localhost" or host.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return bool(
            ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified
        )
    except ValueError:
        return False


def _prefer_https_candidate(url: str) -> str:
    """Para el listado de APIs: priorizar https://; conservar http en local."""
    u = (url or "").strip().rstrip("/")
    lu = u.lower()
    if lu.startswith("https://"):
        return u
    if lu.startswith("http://localhost") or lu.startswith("http://127.0.0.1"):
        return u
    if lu.startswith("http://"):
        return "https://" + u[len("http://") :].rstrip("/")
    return u


def _bases_from_api_url(raw: str) -> List[str]:
    """
    Bases de API completas desde una URL absoluta en el código: https://host[/prefijo].
    Ej.: https://claro-co.saludinclusiva.ai/api/users → https://claro-co.saludinclusiva.ai/api y https://claro-co.saludinclusiva.ai
    """
    raw = (raw or "").strip().rstrip(".,);'\"")
    if _url_is_infer_noise(raw):
        return []
    p = urlparse(raw)
    if p.scheme not in ("http", "https") or not p.netloc:
        return []
    origin = f"{p.scheme}://{p.netloc}".rstrip("/")
    parts = [x for x in (p.path or "").split("/") if x]
    ordered: List[str] = []
    if len(parts) >= 2 and re.match(r"^v\d+$", parts[1], re.I):
        ordered.append(f"{origin}/{parts[0]}/{parts[1]}".rstrip("/"))
    elif len(parts) >= 2:
        ordered.append(f"{origin}/{parts[0]}".rstrip("/"))
    elif len(parts) == 1 and _first_path_segment_is_api_root(parts[0]):
        ordered.append(f"{origin}/{parts[0]}".rstrip("/"))
    ordered.append(origin)
    out: List[str] = []
    seen: Set[str] = set()
    for c in ordered:
        c = _prefer_https_candidate(c).rstrip("/")
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _looks_like_api_url(url: str) -> bool:
    u = (url or "").lower()
    if not u.startswith(("http://", "https://")):
        return False
    if _url_is_infer_noise(url):
        return False
    if "example.com" in u or "localhost" in u or "127.0.0.1" in u:
        return True
    pu = urlparse(url)
    if pu.scheme in ("http", "https") and pu.netloc:
        pth = (pu.path or "").strip()
        if pth in ("", "/"):
            host = pu.netloc.split("@")[-1].lower()
            if "localhost" in host or host.startswith("127."):
                return True
            # https://api.proveedor.com (sin ruta en el literal) — base válida
            if "." in host:
                return True
    if any(x in u for x in ("/api", "/v1", "/v2", "/graphql", "swagger", "openapi")):
        return True
    if re.search(r"https?://[^/]+/[^/?#]{2,}", u):
        return True
    return False


_API_ROOT_SEGMENTS = frozenset(
    {"api", "graphql", "rest", "gateway", "services", "svc", "bff", "backend"}
)


def _first_path_segment_is_api_root(seg: str) -> bool:
    s = (seg or "").lower()
    if not s or len(s) > 80:
        return False
    if s in _API_ROOT_SEGMENTS:
        return True
    if re.match(r"^v\d+$", s):
        return True
    if "api" in s and len(s) <= 40:
        return True
    return False


def _is_under_utils(path: Path) -> bool:
    """True si el archivo está bajo una carpeta 'utils' (p. ej. src/utils/config.js)."""
    return any(part.lower() == "utils" for part in path.parts)


def _infer_scan_priority(path: Path) -> tuple:
    """
    Orden de lectura: primero config remota y apiPaths (Claro / MaaS),
    luego *Source.js de data, utils, resto; al final UI del mini (/main/ui/) para no llenar el cupo con basura.
    """
    s = str(path).replace("\\", "/").lower()
    if "data/config/remote" in s or path.name.lower() == "apipaths.js":
        return (0, s)
    if "/data/" in s and "/source/" in s and path.suffix.lower() == ".js":
        return (1, s)
    if _is_under_utils(path):
        return (2, s)
    if "/main/ui/" in s:
        return (9, s)
    return (5, s)


def _quoted_path_is_mini_ui_or_asset(path: str) -> bool:
    """Rutas locales del mini program (navegación, assets) — no son endpoints HTTP remotos."""
    p = (path or "").strip()
    pl = p.lower()
    if pl.startswith("/main/ui/"):
        return True
    if pl.startswith("/pages/") or pl.startswith("/package"):
        return True
    if re.search(r"\.(svg|png|jpg|jpeg|gif|webp|ico|woff2?)(\?|$)", pl):
        return True
    if "/assets/" in pl or "/images/" in pl or "/components/" in pl:
        return True
    return False


def _infer_rel_is_mini_ui_markup(rel: str) -> bool:
    """Páginas .axml / estilos bajo main/ui: suelen tener slugs de navegación, no el API remoto."""
    rl = rel.replace("\\", "/").lower()
    return "main/ui/" in rl and rl.endswith((".axml", ".acss"))


def _quoted_path_single_segment_kebab_marketing(path: str) -> bool:
    """
    Slugs tipo /activa-tu-recarga (una sola ruta kebab, típico de landings o deep links en UI).
    No coinciden con prefijos de API (/miniprogram/, /ClientAPI/, …).
    """
    p = (path or "").strip().rstrip("/")
    if not p.startswith("/"):
        return False
    segs = [x for x in p.split("/") if x]
    if len(segs) != 1:
        return False
    s = segs[0].lower()
    if len(s) < 12:
        return False
    # al menos tres trozos unidos por guion (p. ej. activa-tu-recarga)
    if not re.match(r"^[a-z0-9]+(?:-[a-z0-9]+){2,}$", s):
        return False
    return True


def _quoted_path_likely_remote_http_api(path: str) -> bool:
    """True si la ruta entre comillas parece API backend (Claro minipro, Vepay, URS, etc.)."""
    if not path or not path.startswith("/"):
        return False
    if _quoted_path_single_segment_kebab_marketing(path):
        return False
    if _quoted_path_is_mini_ui_or_asset(path):
        return False
    pl = path.lower()
    markers = (
        "/miniprogram/",
        "/clientapi/",
        "/api/",
        "/graphql",
        "/v1/",
        "/v2/",
        "/v3/",
        "/webrecharge/",
        "/cartaspago/",
        "/authorization",
        "/payments/",
        "/users/",
        "/inquiry",
    )
    if any(m in pl for m in markers):
        return True
    if pl.startswith("/card/"):
        return True
    return False


def _iter_text_files(project_path: Path, languages: Optional[List[str]]) -> List[Path]:
    project_path = project_path.resolve()
    if not project_path.is_dir():
        return []
    exts = extensions_for_languages(languages)
    out: List[Path] = []
    for p in project_path.rglob("*"):
        if not p.is_file():
            continue
        if any(part.lower() in _SKIP_DIRS_LOWER for part in p.parts):
            continue
        if p.name.lower() in _SKIP_INFER_FILE_NAMES_LOWER:
            continue
        suf = p.suffix.lower()
        if suf not in exts and not p.name.endswith((".axml", ".acss")):
            continue
        try:
            if p.stat().st_size > 2_000_000:
                continue
        except OSError:
            continue
        out.append(p)
    # Priorizar config remota / sources de datos / utils; al final UI /main/ui/
    out.sort(key=_infer_scan_priority)
    return out


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _collect_raw_urls_from_snippet(snippet: str) -> List[str]:
    """https://… explícitos + asignaciones tipo baseURL: 'https://…' (común en utils/)."""
    out: List[str] = []
    for m in _URL_RE.finditer(snippet):
        out.append(m.group(0))
    for cre in _CONFIG_URL_RES:
        for m in cre.finditer(snippet):
            g = m.group(1)
            if g:
                out.append(g)
    return out


def infer_api_candidates(
    project_path: Path,
    limit: int = 5,
    languages: Optional[List[str]] = None,
) -> List[str]:
    """
    Bases de API listables: https://host[/prefijo] (p. ej. …/api), no solo el origen,
    para coincidir con URLs reales del proyecto.

    Recorre *todo* el proyecto (no corta al primer bloque de archivos): así no se pierden
    otros https:// en carpetas tardías. Si hay un solo host conocido por URLs en código,
    añade bases sintéticas por prefijos de rutas remotas (/miniprogram/api/v2, /ClientAPI, …).
    """
    collected: List[str] = []
    seen: Set[str] = set()

    def push(u: str) -> None:
        u = _prefer_https_candidate(u).rstrip("/")
        if not u or u in seen:
            return
        if _infer_candidate_url_is_non_public(u):
            return
        seen.add(u)
        collected.append(u)

    files = _iter_text_files(project_path, languages)
    file_texts: List[Tuple[Path, str]] = [(fp, _read_text(fp)) for fp in files]
    for fp, text in file_texts:
        for raw in _collect_raw_urls_from_snippet(text):
            raw = raw.rstrip(".,);'\"")
            if not _looks_like_api_url(raw):
                continue
            for c in _bases_from_api_url(raw):
                push(c)

    origins = sorted({_norm_origin(u).rstrip("/") for u in collected if _norm_origin(u)})
    if len(origins) == 1:
        origin = origins[0]
        for fp, text in file_texts:
            rel = str(fp.relative_to(project_path.resolve()))
            if _infer_rel_is_mini_ui_markup(rel):
                continue
            for line in text.splitlines():
                for m in _QUOTED_PATH_RE.finditer(line):
                    path_only = m.group(1)
                    if "//" in path_only or " " in path_only or not path_only.startswith("/"):
                        continue
                    if not _quoted_path_likely_remote_http_api(path_only):
                        continue
                    sp = _synthetic_base_path_from_api_path(path_only)
                    if not sp:
                        continue
                    push(f"{origin.rstrip('/')}{sp}")

    # Más específicas (URL más larga) primero, luego alfabético
    ordered = sorted(dict.fromkeys(collected), key=lambda u: (-len(u), u.lower()))
    return ordered[: max(1, int(limit))]


def _synthetic_base_path_from_api_path(path: str) -> str:
    """
    Prefijo de servicio bajo un mismo host: p. ej. /miniprogram/api/v2/foo → /miniprogram/api/v2.
    """
    parts = [x for x in (path or "").split("/") if x]
    if not parts:
        return ""
    pl = path.lower()
    if pl.startswith("/miniprogram/") and len(parts) >= 3:
        return "/" + "/".join(parts[:3])
    if pl.startswith("/clientapi"):
        return "/" + parts[0]
    if pl.startswith("/card"):
        return "/" + parts[0]
    if pl.startswith("/webrecharge"):
        return "/" + parts[0]
    if pl.startswith("/cartaspago"):
        return "/" + parts[0]
    if len(parts) >= 2:
        return "/" + "/".join(parts[:2])
    return "/" + parts[0]


def infer_primary_api_url(project_path: Path) -> str:
    """Primera URL candidata o cadena vacía."""
    c = infer_api_candidates(project_path, limit=1)
    return c[0] if c else ""


def _method_from_line(line: str) -> str:
    m = re.search(r"method\s*:\s*['\"]([A-Za-z]+)['\"]", line, re.I)
    if m:
        return m.group(1).upper()
    if re.search(r"\bmy\.request\s*\(", line):
        m2 = re.search(r"method\s*:\s*['\"]([A-Za-z]+)['\"]", line, re.I)
        if m2:
            return m2.group(1).upper()
    return "GET"


def _resource_path_prefix_from_parsed(pu) -> str:
    """
    Prefijo de ruta del API elegido: p. ej. https://x.com/miniprogram/api/v2 → /miniprogram/api/v2.
    Vacío si la base es solo el origen (path / o vacío): en ese caso no se filtra por prefijo.
    """
    raw_path = (pu.path or "").strip()
    if not raw_path or raw_path == "/":
        return ""
    p = raw_path if raw_path.startswith("/") else "/" + raw_path
    return p.rstrip("/") or ""


def _path_matches_resource_prefix(prefix: str, resource_path: str) -> bool:
    """True si resource_path es exactamente prefix o un subcamino bajo prefix."""
    if not (prefix or "").strip():
        return True
    rp = (resource_path or "").strip()
    if not rp.startswith("/"):
        rp = "/" + rp
    rp_clean = rp.rstrip("/") or "/"
    pre = prefix.rstrip("/")
    if not pre.startswith("/"):
        pre = "/" + pre
    return rp_clean == pre or rp_clean.startswith(pre + "/")


def _endpoint_path_from_detail(ep: Dict[str, Any]) -> str:
    path = str(ep.get("path") or "").strip()
    if path:
        return path if path.startswith("/") else "/" + path
    url = str(ep.get("url") or "").strip()
    if url.startswith(("http://", "https://")):
        pr = urlparse(url)
        p = pr.path or "/"
        return p if p.startswith("/") else "/" + p
    return ""


def filter_endpoints_by_api_base(
    api_url: str, endpoints: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Deja solo endpoints cuya ruta cae bajo el prefijo de api_url (p. ej. …/miniprogram/api/v2).
    Si api_url es solo origen (sin path), no filtra por prefijo pero exige mismo host en URLs absolutas.
    """
    base = (api_url or "").strip().rstrip("/")
    if not base or not endpoints:
        return [x for x in (endpoints or []) if isinstance(x, dict)]
    pu = urlparse(base if "://" in base else f"https://{base}")
    if pu.scheme not in ("http", "https") or not pu.netloc:
        return [x for x in endpoints if isinstance(x, dict)]
    path_prefix = _resource_path_prefix_from_parsed(pu)
    origin = f"{pu.scheme}://{pu.netloc}".rstrip("/")
    out: List[Dict[str, Any]] = []
    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        path = _endpoint_path_from_detail(ep)
        if not path:
            continue
        if path_prefix:
            if not _path_matches_resource_prefix(path_prefix, path):
                continue
        else:
            url = str(ep.get("url") or "").strip()
            if url.startswith(("http://", "https://")):
                pr = urlparse(url)
                if f"{pr.scheme}://{pr.netloc}".rstrip("/") != origin:
                    continue
        out.append(ep)
    return out


def _infer_path_prefix_when_single_service_on_origin(
    pu,
    project_path: Path,
    languages: Optional[List[str]],
) -> str:
    """
    Si la URL base es solo https://host y en el código hay un único prefijo de servicio
    (p. ej. solo /miniprogram/api/v2), usarlo para no mezclar /card/ u otros.
    """
    origin = f"{pu.scheme}://{pu.netloc}".rstrip("/")
    if not origin:
        return ""
    cands = infer_api_candidates(project_path, limit=30, languages=languages)
    prefixes: List[str] = []
    for c in cands:
        if _norm_origin(c).rstrip("/") != origin:
            continue
        cp = _resource_path_prefix_from_parsed(urlparse(c.rstrip("/")))
        if cp:
            prefixes.append(cp)
    uniq = list(dict.fromkeys(prefixes))
    if len(uniq) == 1:
        return uniq[0]
    return ""


def _resolve_listing_path_prefix(
    api_url: str,
    project_path: Optional[Path] = None,
    languages: Optional[List[str]] = None,
) -> str:
    pu = urlparse((api_url or "").strip().rstrip("/"))
    pf = _resource_path_prefix_from_parsed(pu)
    if pf:
        return pf
    if project_path is not None and project_path.is_dir():
        return _infer_path_prefix_when_single_service_on_origin(
            pu, project_path, languages
        )
    return ""


def _detail(
    method: str,
    path: str,
    full_url: str,
    rel_file: str,
    line: int,
) -> Dict[str, Any]:
    p = (path or "").strip() or "/"
    if not p.startswith("/"):
        p = "/" + p
    return {
        "method": method.upper() if method else "GET",
        "path": p,
        "url": full_url.strip(),
        "files": [{"file": rel_file.replace("\\", "/"), "line": int(line)}],
        "count": 1,
        "source": "inferred",
        "strong_binding": False,
    }


def infer_api_endpoints(
    project_path: Path,
    api_url: str,
    limit: int = 500,
    languages: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Heurística: URLs absolutas con mismo host que api_url y rutas entre comillas
    unidas a la base api_url.

    Si api_url incluye prefijo de ruta (p. ej. …/miniprogram/api/v2), solo se listan
    endpoints cuya ruta cae bajo ese prefijo; no se mezclan otros servicios del mismo host
    (/ClientAPI/…, /card/…, etc.) salvo que la base elegida los comparta.

    Filtra rutas locales típicas de mini programs Alipay (p. ej. /main/ui/pages/…,
    assets .svg) para no mezclarlas con APIs remotas (apiPaths, /miniprogram/, /ClientAPI/, …).
    """
    base = (api_url or "").strip().rstrip("/")
    pu = urlparse(base)
    if pu.scheme not in ("http", "https") or not pu.netloc:
        return []
    origin = f"{pu.scheme}://{pu.netloc}"
    path_prefix = _resolve_listing_path_prefix(base, project_path, languages)

    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    lim = max(1, int(limit))

    def add_ep(ep: Dict[str, Any]) -> bool:
        key = f"{ep.get('method')} {ep.get('url')}".strip().upper()
        if key in seen:
            return len(out) < lim
        seen.add(key)
        out.append(ep)
        return len(out) < lim

    url_prop = re.compile(r"""url\s*:\s*['"]([^'"]+)['"]""", re.I)

    for fp in _iter_text_files(project_path, languages):
        rel = str(fp.relative_to(project_path.resolve()))
        text = _read_text(fp)
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            method = _method_from_line(line)
            for raw in _collect_raw_urls_from_snippet(line):
                raw = raw.rstrip(".,);'\"")
                if _url_is_infer_noise(raw):
                    continue
                pr = urlparse(raw)
                if pr.scheme not in ("http", "https") or not pr.netloc:
                    continue
                ro = f"{pr.scheme}://{pr.netloc}"
                if ro != origin:
                    continue
                path = pr.path or "/"
                if not path.startswith("/"):
                    path = "/" + path
                if not _path_matches_resource_prefix(path_prefix, path):
                    continue
                full = raw
                if not add_ep(_detail(method, path, full, rel, i)):
                    return out
            um = url_prop.search(line)
            if um:
                uval = um.group(1).strip()
                if uval.startswith(("http://", "https://")):
                    pr = urlparse(uval)
                    ro = f"{pr.scheme}://{pr.netloc}" if pr.scheme and pr.netloc else ""
                    if ro == origin:
                        path = pr.path or "/"
                        if not path.startswith("/"):
                            path = "/" + path
                        if not _path_matches_resource_prefix(path_prefix, path):
                            continue
                        if not add_ep(_detail(method, path, uval, rel, i)):
                            return out
                elif uval.startswith("/"):
                    if "${" in uval or "`" in uval:
                        pass
                    elif _infer_rel_is_mini_ui_markup(rel):
                        pass
                    elif _quoted_path_likely_remote_http_api(uval):
                        if not _path_matches_resource_prefix(path_prefix, uval):
                            continue
                        joined = urljoin(base + "/", uval.lstrip("/"))
                        if not add_ep(_detail(method, uval, joined, rel, i)):
                            return out
            for m in _QUOTED_PATH_RE.finditer(line):
                path_only = m.group(1)
                if "//" in path_only or " " in path_only:
                    continue
                if not path_only.startswith("/"):
                    continue
                if _infer_rel_is_mini_ui_markup(rel):
                    continue
                if not _quoted_path_likely_remote_http_api(path_only):
                    continue
                if not _path_matches_resource_prefix(path_prefix, path_only):
                    continue
                joined = urljoin(base + "/", path_only.lstrip("/"))
                if not add_ep(_detail(method, path_only, joined, rel, i)):
                    return out
    return out
