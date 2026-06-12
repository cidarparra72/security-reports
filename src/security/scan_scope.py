#!/usr/bin/env python3
"""
Language → file extensions for static scan, and optional suppressions (.api-security-ignore.yaml).
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Alipay mini-program friendly defaults + common web stacks
LANGUAGE_EXTENSIONS: Dict[str, frozenset[str]] = {
    "javascript": frozenset({".js", ".jsx", ".mjs", ".cjs", ".vue", ".axml", ".acss", ".sss"}),
    "typescript": frozenset({".ts", ".tsx", ".mts", ".cts"}),
    "json": frozenset({".json"}),
    "python": frozenset({".py"}),
    "java": frozenset({".java"}),
    "go": frozenset({".go"}),
    "php": frozenset({".php"}),
}

LEGACY_DEFAULT_EXTENSIONS: frozenset[str] = frozenset(
    {".js", ".ts", ".json", ".axml", ".acss", ".sss"}
)


def extensions_for_languages(languages: Optional[List[str]]) -> frozenset[str]:
    """Union of extensions for selected UI languages; empty / None → legacy mini-program set."""
    if not languages:
        return LEGACY_DEFAULT_EXTENSIONS
    exts: Set[str] = set()
    for raw in languages:
        key = str(raw or "").strip().lower()
        if key in LANGUAGE_EXTENSIONS:
            exts |= LANGUAGE_EXTENSIONS[key]
    return frozenset(exts) if exts else LEGACY_DEFAULT_EXTENSIONS


_IGNORE_FILENAMES = frozenset(
    {
        ".api-security-ignore.yaml",
        ".api-security-ignore.yml",
        "api-security-ignore.yaml",
    }
)

# Artefactos generados por el propio escáner (Trivy/Grype/Semgrep en la raíz del repo).
_SCAN_ARTIFACT_RE = re.compile(
    r"^scan-\d+-(trivy|grype|semgrep|nuclei|eslint|zap-baseline)(?:-upload)?\.json$",
    re.IGNORECASE,
)


def is_scan_artifact_filename(name: str) -> bool:
    base = (name or "").strip().replace("\\", "/").split("/")[-1]
    return bool(_SCAN_ARTIFACT_RE.match(base))


def load_suppressions(project_path: Path) -> List[Dict[str, Any]]:
    """Load suppress rules from project root YAML."""
    for name in _IGNORE_FILENAMES:
        p = project_path / name
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        try:
            import yaml  # type: ignore

            data = yaml.safe_load(text) or {}
        except Exception:
            return []
        rules = data.get("suppress") or data.get("suppressions") or []
        return [r for r in rules if isinstance(r, dict)]
    return []


def _norm_rel(rel: str) -> str:
    return rel.replace("\\", "/")


def is_finding_suppressed(
    pattern_id: str,
    rel_file: str,
    rules: List[Dict[str, Any]],
) -> bool:
    """True if pattern_id + path matches a suppression rule."""
    if not rules:
        return False
    rel = _norm_rel(rel_file)
    for rule in rules:
        rid = str(rule.get("pattern_id", "*") or "*").strip()
        if rid != "*" and rid.upper() != pattern_id.upper():
            continue
        if "path_glob" in rule and rule["path_glob"]:
            pat = str(rule["path_glob"]).replace("\\", "/")
            if fnmatch.fnmatch(rel, pat):
                return True
        if "path_contains" in rule and rule["path_contains"]:
            needle = str(rule["path_contains"]).replace("\\", "/")
            if needle in rel:
                return True
        if "path_suffix" in rule and rule["path_suffix"]:
            suf = str(rule["path_suffix"]).lower()
            if rel.lower().endswith(suf.lower()):
                return True
    return False


def discover_openapi_specs(project_path: Path, limit: int = 12) -> List[str]:
    """Relative paths to likely OpenAPI/Swagger specs (for Schemathesis / documentation)."""
    if not project_path.is_dir():
        return []
    found: List[str] = []
    seen: Set[str] = set()
    globs = (
        "**/openapi.json",
        "**/openapi.yaml",
        "**/openapi.yml",
        "**/swagger.json",
        "**/swagger.yaml",
        "**/swagger.yml",
    )
    skip_parts = {
        "node_modules",
        "dist",
        "build",
        ".git",
        "vendor",
        ".next",
        "__pycache__",
        ".venv",
        "venv",
        "coverage",
    }
    for pattern in globs:
        for p in project_path.glob(pattern):
            try:
                rel = str(p.relative_to(project_path)).replace("\\", "/")
            except ValueError:
                continue
            if any(part in skip_parts for part in p.parts):
                continue
            low = rel.lower()
            if low in seen:
                continue
            seen.add(low)
            found.append(rel)
            if len(found) >= limit:
                return found
    return found
