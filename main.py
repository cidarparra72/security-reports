#!/usr/bin/env python3
"""
Main CLI entry point for the API/Mini Program security scanner.

Examples:
    python main.py sample-mini-program
    python main.py sample-mini-program --output reports/sample.html
    python main.py sample-mini-program --url https://api.example.com --format both
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from security import APISecurityScanner, EthicalHackingReportGenerator  # noqa: E402


def _configure_stdout() -> None:
    """Avoid UnicodeEncodeError on Windows consoles configured as cp1252."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass


def _write_json_report(scan_result: dict, output_file: Path) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as f:
        json.dump(scan_result, f, indent=2, ensure_ascii=False)
    print(f"JSON report saved: {output_file}")


def _write_html_report(
    scan_result: dict,
    output_file: Path,
    project_name: str,
    target_url: str,
    scan_json_file: Path | None = None,
) -> None:
    json_tmp = scan_json_file or output_file.with_suffix(".scan.json")
    if scan_json_file is None:
        _write_json_report(scan_result, json_tmp)

    generator = EthicalHackingReportGenerator(project_name=project_name, target_url=target_url)
    generator.load_from_scan(str(json_tmp))
    output_file.parent.mkdir(parents=True, exist_ok=True)
    generator.generate_html(str(output_file))
    print(f"HTML report saved: {output_file}")


def main() -> int:
    _configure_stdout()

    parser = argparse.ArgumentParser(description="API/Mini Program Security Scanner")
    parser.add_argument("target", help="Path to the project directory to scan")
    parser.add_argument(
        "--output",
        "-o",
        default="security-report.html",
        help="Output file. For --format both, this is the HTML path.",
    )
    parser.add_argument("--url", help="Optional target API URL for dynamic checks")
    parser.add_argument("--project", "-p", help="Project name. Defaults to the directory name.")
    parser.add_argument(
        "--format",
        choices=["html", "json", "both"],
        default="both",
        help="Output format.",
    )

    args = parser.parse_args()
    target = Path(args.target).expanduser().resolve()
    if not target.exists():
        print(f"Error: path does not exist: {target}", file=sys.stderr)
        return 2
    if not target.is_dir():
        print(f"Error: path is not a directory: {target}", file=sys.stderr)
        return 2

    project_name = args.project or target.name
    target_url = (args.url or "").strip()
    out = Path(args.output)

    print(f"Scanning project: {project_name}")
    print(f"Target directory: {target}")
    if target_url:
        print(f"Target API URL: {target_url}")

    scanner = APISecurityScanner(str(target), target_api_url=target_url or None)
    scan_result = scanner.scan()

    if args.format == "json":
        json_out = out if out.suffix.lower() == ".json" else out.with_suffix(".json")
        _write_json_report(scan_result, json_out)
    elif args.format == "html":
        html_out = out if out.suffix.lower() in {".html", ".htm"} else out.with_suffix(".html")
        _write_html_report(scan_result, html_out, project_name, target_url)
    else:
        html_out = out if out.suffix.lower() in {".html", ".htm"} else out.with_suffix(".html")
        json_out = html_out.with_suffix(".json")
        _write_json_report(scan_result, json_out)
        _write_html_report(scan_result, html_out, project_name, target_url, json_out)

    critical_count = int(scan_result.get("summary", {}).get("CRITICAL", 0))
    if critical_count > 0:
        print(f"Found {critical_count} CRITICAL vulnerabilities.")
        return 1

    print("Scan completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
