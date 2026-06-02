#!/usr/bin/env python3
"""
Heuristica: localizar literales tipo JWT / Bearer en el arbol del proyecto (.env, JS/TS…).
Solo para rellenar la sesion en la UI; no sustituye secret manager.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .infer_api_url import _iter_text_files

_JWT = re.compile(
    r"\b(eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,})\b"
)
_BEARER = re.compile(
    r"(?i)bearer\s+(eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,})"
)
_ASSIGN = re.compile(
    r"(?i)(?:access[_-]?token|auth[_-]?token|jwt[_-]?token|id[_-]?token|token|bearer)"
    r"\s*(?::|=)\s*['\"]?(eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,})['\"]?"
)

_ENV_NAMES = frozenset(
    n.lower()
    for n in (
        ".env",
        ".env.local",
        ".env.development",
        ".env.production",
        ".env.staging",
    )
)


def _push_hint(
    out: List[Dict[str, Any]],
    seen: Set[str],
    token: str,
    rel: str,
    line_no: int,
    source: str,
    limit: int,
) -> None:
    tok = (token or "").strip()
    if not tok or tok in seen or len(out) >= limit:
        return
    seen.add(tok)
    preview = tok[:24] + "…" if len(tok) > 28 else tok
    out.append(
        {
            "token_preview": preview,
            "token": tok,
            "file": rel,
            "line": line_no,
            "source": source,
        }
    )


def infer_auth_hints_from_repo(
    project_path: Path,
    languages: Optional[List[str]] = None,
    limit: int = 15,
) -> List[Dict[str, Any]]:
    """Busca JWT literales en .env y archivos de codigo del proyecto."""
    root = project_path.resolve()
    if not root.is_dir():
        return []

    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    for fp in root.rglob("*"):
        if len(out) >= limit:
            break
        if not fp.is_file() or fp.name.lower() not in _ENV_NAMES:
            continue
        try:
            if fp.stat().st_size > 500_000:
                continue
        except OSError:
            continue
        rel = str(fp.relative_to(root)).replace("\\", "/")
        try:
            lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            for m in _ASSIGN.finditer(line):
                _push_hint(out, seen, m.group(1), rel, i, "env", limit)
            for cre in (_JWT, _BEARER):
                for m2 in cre.finditer(line):
                    _push_hint(out, seen, m2.group(1), rel, i, "env", limit)

    for fp in _iter_text_files(root, languages):
        if len(out) >= limit:
            break
        rel = str(fp.relative_to(root)).replace("\\", "/")
        try:
            lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            for m in _ASSIGN.finditer(line):
                _push_hint(out, seen, m.group(1), rel, i, "code", limit)
            for cre in (_JWT, _BEARER):
                for m2 in cre.finditer(line):
                    _push_hint(out, seen, m2.group(1), rel, i, "code", limit)

    return out
