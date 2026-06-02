#!/usr/bin/env python3
"""
Ejecuta tests unitarios del proyecto escaneado (mejor esfuerzo) y resume salida / JUnit.

Solo usar con repositorios de confianza: `npm test` puede ejecutar scripts definidos en package.json.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional


def _truncate(s: str, max_chars: int = 12000) -> str:
    s = (s or "").strip()
    if len(s) <= max_chars:
        return s
    return "…\n" + s[-max_chars:]


def _parse_junit_file(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except (ET.ParseError, OSError):
        return None

    tests = failures = errors = skipped = 0
    # testsuite singular o plural (JUnit agregado)
    for el in root.iter():
        tag = el.tag.split("}")[-1] if "}" in el.tag else el.tag
        if tag == "testsuite":
            tests += int(el.attrib.get("tests", 0) or 0)
            failures += int(el.attrib.get("failures", 0) or 0)
            errors += int(el.attrib.get("errors", 0) or 0)
            skipped += int(el.attrib.get("skipped", 0) or 0)
    if tests == 0 and root.tag.split("}")[-1] == "testsuite":
        tests = int(root.attrib.get("tests", 0) or 0)
        failures = int(root.attrib.get("failures", 0) or 0)
        errors = int(root.attrib.get("errors", 0) or 0)
        skipped = int(root.attrib.get("skipped", 0) or 0)
    if tests == 0 and failures == 0 and errors == 0:
        return None
    return {
        "path": str(path),
        "tests": tests,
        "failures": failures,
        "errors": errors,
        "skipped": skipped,
    }


def _find_junit_after(root: Path, since_ts: float) -> Optional[Dict[str, Any]]:
    """Busca junit.xml típico de Jest (coverage/) o raíz, recientemente modificado."""
    candidates: List[Path] = [
        root / "coverage" / "junit.xml",
        root / "junit.xml",
        root / "test-results" / "junit.xml",
        root / "reports" / "junit.xml",
    ]
    found: List[Path] = []
    for p in candidates:
        try:
            if p.is_file() and p.stat().st_mtime >= since_ts - 2.0:
                found.append(p)
        except OSError:
            continue
    for p in sorted(found, key=lambda x: x.stat().st_mtime, reverse=True):
        parsed = _parse_junit_file(p)
        if parsed:
            return parsed
    return None


def _npm_test_available(root: Path) -> bool:
    pkg = root / "package.json"
    if not pkg.is_file():
        return False
    try:
        data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return False
    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return False
    return bool((scripts.get("test") or "").strip())


def _pytest_marker(root: Path) -> bool:
    if (root / "pytest.ini").is_file():
        return True
    if (root / "pyproject.toml").is_file():
        return True
    tests_dir = root / "tests"
    if tests_dir.is_dir():
        for p in tests_dir.iterdir():
            if p.suffix == ".py" and p.name.startswith("test_"):
                return True
    return (root / "test").is_dir()


def _pytest_cmd() -> Optional[List[str]]:
    if shutil.which("pytest") is not None:
        return ["pytest", "-q", "--tb=short"]
    if shutil.which("py") is not None:
        return ["py", "-m", "pytest", "-q", "--tb=short"]
    if shutil.which("python") is not None:
        return ["python", "-m", "pytest", "-q", "--tb=short"]
    return None


def _pytest_available(root: Path) -> bool:
    return _pytest_marker(root) and _pytest_cmd() is not None


def run_project_tests(project_path: str, timeout_sec: Optional[float] = None) -> Dict[str, Any]:
    """
    Detecta npm test o pytest y ejecuta en project_path.

    timeout_sec: por defecto REPO_TESTS_TIMEOUT_SEC o 600.
    """
    root = Path(project_path).resolve()
    default_t = float(os.environ.get("REPO_TESTS_TIMEOUT_SEC", "600"))
    timeout = float(timeout_sec) if timeout_sec is not None else default_t
    timeout = max(30.0, min(timeout, 3600.0))

    out: Dict[str, Any] = {
        "status": "skipped",
        "runner": None,
        "command": None,
        "exit_code": None,
        "duration_sec": None,
        "reason": "",
        "junit": None,
        "stdout_tail": "",
    }

    if not root.is_dir():
        out["reason"] = "La ruta del proyecto no es un directorio."
        return out

    cmd: Optional[List[str]] = None
    runner: Optional[str] = None
    if _npm_test_available(root):
        npm_bin = shutil.which("npm")
        if npm_bin is None:
            out["reason"] = "Hay package.json con script test pero `npm` no está en PATH."
            return out
        cmd = [npm_bin, "test"]
        runner = "npm"
    elif _pytest_available(root):
        cmd = _pytest_cmd()
        if cmd is None:
            out["reason"] = "pytest no disponible en PATH."
            return out
        runner = "pytest"
    else:
        out["reason"] = (
            "No se detectó `scripts.test` en package.json ni entorno pytest "
            "(pytest.ini, pyproject.toml o tests/*.py)."
        )
        return out

    out["runner"] = runner
    out["command"] = cmd
    since = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            env={**os.environ, "CI": "true", "FORCE_COLOR": "0"},
        )
        out["duration_sec"] = round(time.time() - since, 2)
        out["exit_code"] = int(proc.returncode)
        combined = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        out["stdout_tail"] = _truncate(combined, 14000)
        if proc.returncode == 0:
            out["status"] = "completed"
        else:
            out["status"] = "failed"
            out["reason"] = f"exit_code={proc.returncode}"
    except subprocess.TimeoutExpired as exc:
        out["duration_sec"] = round(time.time() - since, 2)
        out["status"] = "timeout"
        out["reason"] = f"superó {int(timeout)} s"
        combined = ""
        if exc.stdout:
            combined += exc.stdout
        if exc.stderr:
            combined += "\n" + exc.stderr
        out["stdout_tail"] = _truncate(combined, 14000)
        out["exit_code"] = None
    except OSError as exc:
        out["duration_sec"] = round(time.time() - since, 2)
        out["status"] = "failed"
        out["reason"] = str(exc)
        out["exit_code"] = None

    junit = _find_junit_after(root, since)
    if junit:
        out["junit"] = junit
        bad = int(junit.get("failures", 0)) + int(junit.get("errors", 0))
        if bad > 0 and out["status"] == "completed":
            out["status"] = "failed"
            out["reason"] = out["reason"] or f"junit: {bad} fallos/errores"

    # Línea tipo "Tests: 19 passed" desde la cola
    tail = out.get("stdout_tail") or ""
    m = re.search(r"Tests?:\s*(\d+)\s*passed", tail, re.I)
    if m:
        out["parsed_passed"] = int(m.group(1))
    m2 = re.search(r"(\d+)\s+passed", tail)
    if m2 and "parsed_passed" not in out:
        out["parsed_passed"] = int(m2.group(1))

    return out
