#!/usr/bin/env python3
"""
Optional external checks execution (best effort).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict


def _cmd_exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _run(cmd: list[str], cwd: Path) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
        )
        out = (completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else "")
        return int(completed.returncode), out[:8000]
    except OSError as exc:
        return 1, str(exc)


def run_selected_external_checks(
    project_path: str,
    selected_checks: set[str],
    target_api_url: str | None,
    scan_id: int,
) -> Dict[str, Any]:
    project = Path(project_path)
    results: Dict[str, Any] = {}
    api_url = (target_api_url or "").strip()

    if "schemathesis" in selected_checks:
        if not api_url:
            results["schemathesis"] = {"status": "skipped", "reason": "missing_api_url"}
        elif not _cmd_exists("schemathesis"):
            results["schemathesis"] = {"status": "skipped", "reason": "schemathesis_not_installed"}
        else:
            report = project / f"scan-{scan_id}-schemathesis.json"
            code, out = _run(
                [
                    "schemathesis",
                    "run",
                    f"{api_url.rstrip('/')}/swagger.json",
                    "--checks",
                    "all",
                    "--report",
                    "junit",
                    "--report-junit-path",
                    str(report),
                ],
                project,
            )
            results["schemathesis"] = {
                "status": "completed" if code == 0 else "failed",
                "exit_code": code,
                "output": out,
                "report_file": str(report.name),
            }

    if "nuclei" in selected_checks:
        if not api_url:
            results["nuclei"] = {"status": "skipped", "reason": "missing_api_url"}
        elif not _cmd_exists("nuclei"):
            results["nuclei"] = {"status": "skipped", "reason": "nuclei_not_installed"}
        else:
            report = project / f"scan-{scan_id}-nuclei.json"
            code, out = _run(
                [
                    "nuclei",
                    "-u",
                    api_url,
                    "-json",
                    "-o",
                    str(report),
                ],
                project,
            )
            results["nuclei"] = {
                "status": "completed" if code == 0 else "failed",
                "exit_code": code,
                "output": out,
                "report_file": str(report.name),
            }

    if "semgrep" in selected_checks:
        if not _cmd_exists("semgrep"):
            results["semgrep"] = {"status": "skipped", "reason": "semgrep_not_installed"}
        else:
            report = project / f"scan-{scan_id}-semgrep.json"
            code, out = _run(
                ["semgrep", "scan", "--config", "auto", "--json", "--output", str(report), str(project)],
                project,
            )
            results["semgrep"] = {
                "status": "completed" if code in (0, 1) else "failed",
                "exit_code": code,
                "output": out,
                "report_file": str(report.name),
            }

    if "trivy" in selected_checks:
        if not _cmd_exists("trivy"):
            results["trivy"] = {"status": "skipped", "reason": "trivy_not_installed"}
        else:
            report = project / f"scan-{scan_id}-trivy.json"
            code, out = _run(
                ["trivy", "fs", "--format", "json", "--output", str(report), str(project)],
                project,
            )
            results["trivy"] = {
                "status": "completed" if code in (0, 1) else "failed",
                "exit_code": code,
                "output": out,
                "report_file": str(report.name),
            }

    if "grype" in selected_checks:
        if not _cmd_exists("grype"):
            results["grype"] = {"status": "skipped", "reason": "grype_not_installed"}
        else:
            report = project / f"scan-{scan_id}-grype.json"
            code, out = _run(
                ["grype", "dir:" + str(project), "-o", "json"],
                project,
            )
            if out:
                try:
                    report.write_text(out, encoding="utf-8")
                except OSError:
                    pass
            results["grype"] = {
                "status": "completed" if code in (0, 1) else "failed",
                "exit_code": code,
                "output": out[:2000],
                "report_file": str(report.name),
            }

    if "jwt_toolkit" in selected_checks:
        results["jwt_toolkit"] = {
            "status": "manual_required",
            "reason": "provide_captured_jwt_tokens_for_claims_ttl_audience_validation",
        }

    if "burp_manual" in selected_checks:
        results["burp_manual"] = {
            "status": "manual_required",
            "reason": "run_burp_and_upload_exported_json_for_merge",
        }

    return results

