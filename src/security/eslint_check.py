#!/usr/bin/env python3
"""Ejecuta ESLint del proyecto escaneado (mejor esfuerzo) y devuelve JSON de salida."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _truncate(s: str, max_chars: int = 6000) -> str:
    s = (s or "").strip()
    if len(s) <= max_chars:
        return s
    return "…\n" + s[-max_chars:]


def _read_package_scripts(project: Path) -> Dict[str, str]:
    pkg = project / "package.json"
    if not pkg.is_file():
        return {}
    try:
        data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return {}
    scripts = data.get("scripts")
    return scripts if isinstance(scripts, dict) else {}


def _eslint_available(project: Path) -> bool:
    if (project / "node_modules" / "eslint").is_dir():
        return True
    if shutil.which("eslint"):
        return True
    deps = _read_package_scripts(project)
    if deps:
        return True
    pkg = project / "package.json"
    if not pkg.is_file():
        return False
    try:
        data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return False
    for key in ("devDependencies", "dependencies"):
        block = data.get(key)
        if isinstance(block, dict) and block.get("eslint"):
            return True
    return False


def _eslint_command(project: Path, report_path: Path) -> Optional[List[str]]:
    """Comando para generar report_path en formato JSON."""
    scripts = _read_package_scripts(project)
    report_s = str(report_path.resolve())
    npm = shutil.which("npm")
    npx = shutil.which("npx")

    if npm and "lint:global" in scripts:
        return ["npm", "run", "lint:global", "--", "-f", "json", "-o", report_s]
    if npm and "lint" in scripts:
        return ["npm", "run", "lint", "--", "-f", "json", "-o", report_s]

    eslint_args = [
        ".",
        "--ext",
        ".js,.jsx,.ts,.tsx,.mjs,.cjs",
        "-f",
        "json",
        "-o",
        report_s,
    ]
    local_bin = project / "node_modules" / ".bin"
    eslint_exe = local_bin / ("eslint.cmd" if os.name == "nt" else "eslint")
    if eslint_exe.is_file():
        return [str(eslint_exe), *eslint_args]
    if npx:
        return ["npx", "--no-install", "eslint", *eslint_args]
    if shutil.which("eslint"):
        return ["eslint", *eslint_args]
    return None


def run_eslint_check(
    project_path: str,
    scan_id: int,
    artifacts_dir: str | Path,
) -> Dict[str, Any]:
    """
    Corre ESLint si el proyecto lo declara (package.json / node_modules).
    Exit code 1 con hallazgos es normal; se considera completed si hay JSON.
    """
    project = Path(project_path).resolve()
    out_dir = Path(artifacts_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    report = out_dir / f"scan-{scan_id}-eslint.json"

    if not _eslint_available(project):
        return {
            "status": "skipped",
            "reason": "eslint_no_configurado",
            "hint": "Añade eslint en devDependencies o script npm run lint en package.json",
        }

    cmd = _eslint_command(project, report)
    if not cmd:
        return {"status": "skipped", "reason": "eslint_cmd_no_disponible"}

    env = os.environ.copy()
    env.setdefault("CI", "true")
    use_shell = os.name == "nt" and cmd and not Path(str(cmd[0])).is_file()
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(project),
            capture_output=True,
            text=True,
            check=False,
            env=env,
            timeout=int(os.environ.get("ESLINT_TIMEOUT_SEC", "300")),
            shell=use_shell,
        )
        code = int(completed.returncode)
        out = _truncate((completed.stdout or "") + "\n" + (completed.stderr or ""))
    except subprocess.TimeoutExpired:
        return {"status": "failed", "reason": "eslint_timeout", "output": "ESLint excedió el tiempo máximo."}
    except OSError as exc:
        return {"status": "failed", "reason": "eslint_os_error", "output": str(exc)}

    if not report.is_file():
        return {
            "status": "failed",
            "exit_code": code,
            "reason": "eslint_sin_salida_json",
            "output": out,
        }

    issue_count = 0
    try:
        raw = json.loads(report.read_text(encoding="utf-8", errors="replace"))
        if isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, dict):
                    msgs = entry.get("messages")
                    if isinstance(msgs, list):
                        issue_count += len(msgs)
    except (json.JSONDecodeError, OSError):
        pass

    status = "completed"
    if code not in (0, 1):
        status = "failed"

    return {
        "status": status,
        "exit_code": code,
        "output": out,
        "report_file": report.name,
        "issue_count": issue_count,
        "reason": (
            f"{issue_count} aviso(s)/error(es) ESLint"
            if issue_count
            else "ESLint sin hallazgos"
        ),
    }
