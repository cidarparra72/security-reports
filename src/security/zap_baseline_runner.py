#!/usr/bin/env python3
"""
Ejecuta OWASP ZAP baseline en Docker usando URL inferida del proyecto.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .infer_api_url import infer_primary_api_url


def _is_valid_api_url(url: str) -> bool:
    parsed = urlparse((url or "").strip())
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def run_zap_baseline_target(
    work_dir: Path,
    target_url: str,
    *,
    spider_minutes: int = 5,
    ignore_info: bool = True,
    html_report: str = "zap-baseline.html",
    json_report: str = "zap-baseline.json",
    image: str = "owasp/zap2docker-stable",
    allocate_tty: bool = False,
) -> int:
    """
    Ejecuta zap-baseline.py contra una URL; escribe informes en work_dir (montado como /zap/wrk).
    allocate_tty: usar -t en docker (consola interactiva); en servidor suele ir en False.
    """
    work_dir = work_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    api_url = (target_url or "").strip()
    if not _is_valid_api_url(api_url):
        print(f"ERROR: Invalid API URL: {api_url}")
        return 2

    print(f"ZAP baseline target: {api_url}")
    print(f"Work dir: {work_dir}")

    cmd: List[str] = ["docker", "run", "--rm"]
    if allocate_tty:
        cmd.append("-t")
    cmd.extend(
        [
            "-v",
            f"{work_dir}:/zap/wrk:rw",
            image,
            "zap-baseline.py",
            "-t",
            api_url,
            "-m",
            str(max(1, spider_minutes)),
            "-r",
            html_report,
            "-J",
            json_report,
        ]
    )
    if ignore_info:
        cmd.append("-I")

    print("RUN " + " ".join(cmd))
    try:
        completed = subprocess.run(cmd, check=False)
        code = int(completed.returncode)
    except FileNotFoundError:
        print("ERROR: Docker is not installed or not available in PATH.")
        return 127
    except OSError as exc:
        print(f"ERROR: Failed to launch Docker: {exc}")
        return 1

    html_path = work_dir / html_report
    json_path = work_dir / json_report
    print(f"HTML report: {html_path}")
    print(f"JSON report: {json_path}")

    if code != 0:
        print(f"WARNING: ZAP baseline finished with exit code {code}")
    else:
        print("ZAP baseline completed successfully")
    return code


def run_zap_baseline_on_indices(
    work_dir: Path,
    endpoints: List[Dict[str, Any]],
    indices: List[int],
    *,
    spider_minutes: int = 2,
    ignore_info: bool = True,
    image: str = "owasp/zap2docker-stable",
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Un baseline ZAP por cada índice (URL de arranque del spider).
    Devuelve (filas, error_global); error_global si Docker no está o carpeta inválida.
    """
    work_dir = work_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    rows: List[Dict[str, Any]] = []
    try:
        subprocess.run(["docker", "version"], check=False, capture_output=True, timeout=20)
    except (FileNotFoundError, OSError):
        return [], "Docker no está disponible en PATH (instala Docker Desktop y prueba de nuevo)."
    except subprocess.TimeoutExpired:
        return [], "Docker no respondió a tiempo."

    for idx in sorted(set(indices)):
        if idx < 0 or idx >= len(endpoints):
            rows.append(
                {
                    "index": idx,
                    "url": None,
                    "method": None,
                    "exit_code": 2,
                    "error": "Índice fuera de rango",
                    "json_file": None,
                    "html_file": None,
                }
            )
            continue
        ep = endpoints[idx]
        url = str(ep.get("url") or "").strip()
        method = str(ep.get("method") or "GET")
        if not _is_valid_api_url(url):
            rows.append(
                {
                    "index": idx,
                    "url": url,
                    "method": method,
                    "exit_code": 2,
                    "error": "URL no válida para ZAP",
                    "json_file": None,
                    "html_file": None,
                }
            )
            continue
        html_name = f"zap-{idx}.html"
        json_name = f"zap-{idx}.json"
        code = run_zap_baseline_target(
            work_dir,
            url,
            spider_minutes=spider_minutes,
            ignore_info=ignore_info,
            html_report=html_name,
            json_report=json_name,
            image=image,
            allocate_tty=False,
        )
        rows.append(
            {
                "index": idx,
                "url": url,
                "method": method,
                "exit_code": code,
                "error": None if code == 0 else f"ZAP terminó con código {code}",
                "json_file": json_name if (work_dir / json_name).is_file() else None,
                "html_file": html_name if (work_dir / html_name).is_file() else None,
            }
        )
    return rows, None


def run_zap_baseline(
    project_path: Path,
    target_url: Optional[str] = None,
    spider_minutes: int = 5,
    ignore_info: bool = True,
    html_report: str = "zap-baseline.html",
    json_report: str = "zap-baseline.json",
    image: str = "owasp/zap2docker-stable",
    work_dir: Optional[Path] = None,
) -> int:
    project_path = project_path.resolve()
    if not project_path.is_dir():
        print(f"ERROR: Invalid project path: {project_path}")
        return 2

    api_url = (target_url or "").strip() or infer_primary_api_url(project_path)
    if not api_url:
        print("ERROR: Could not infer API URL from project.")
        print("   Provide one with --target-url https://api.example.com")
        return 2
    if not _is_valid_api_url(api_url):
        print(f"ERROR: Invalid API URL: {api_url}")
        return 2

    out_dir = (work_dir or project_path).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"API URL selected: {api_url}")
    print(f"Running ZAP baseline Docker image: {image}")
    print(f"Report output dir: {out_dir}")

    return run_zap_baseline_target(
        out_dir,
        api_url,
        spider_minutes=spider_minutes,
        ignore_info=ignore_info,
        html_report=html_report,
        json_report=json_report,
        image=image,
        allocate_tty=sys.stdout.isatty(),
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run OWASP ZAP baseline in Docker using inferred API URL."
    )
    parser.add_argument(
        "--path",
        default=".",
        help="Project path to inspect and mount in Docker (default: current directory).",
    )
    parser.add_argument(
        "--target-url",
        default="",
        help="Optional API URL. If omitted, URL is inferred from the project code.",
    )
    parser.add_argument(
        "--minutes",
        type=int,
        default=5,
        help="Spider duration in minutes for zap-baseline.py (-m). Default: 5",
    )
    parser.add_argument(
        "--no-ignore-info",
        action="store_true",
        help="Do not pass -I to ZAP (informational alerts may affect exit behavior).",
    )
    parser.add_argument(
        "--html",
        default="zap-baseline.html",
        help="HTML report filename (stored in project root).",
    )
    parser.add_argument(
        "--json",
        default="zap-baseline.json",
        help="JSON report filename (stored in project root).",
    )
    parser.add_argument(
        "--image",
        default="owasp/zap2docker-stable",
        help="Docker image to use for ZAP baseline.",
    )
    args = parser.parse_args()

    return run_zap_baseline(
        project_path=Path(args.path),
        target_url=args.target_url,
        spider_minutes=args.minutes,
        ignore_info=not args.no_ignore_info,
        html_report=args.html,
        json_report=args.json,
        image=args.image,
    )


if __name__ == "__main__":
    sys.exit(main())
