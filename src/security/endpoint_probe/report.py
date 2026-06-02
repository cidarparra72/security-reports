"""Consolidated report from per-endpoint probe results."""

from __future__ import annotations

from datetime import datetime, timezone
from statistics import mean
from typing import Any, Dict, List


def build_consolidated_report(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    rows: items from run_probes (index, endpoint, result).
    """
    total = len(rows)
    errors = sum(1 for r in rows if r.get("result", {}).get("error"))
    ok_http = sum(
        1
        for r in rows
        if not r.get("result", {}).get("error")
        and isinstance(r.get("result", {}).get("status_code"), int)
        and 200 <= r["result"]["status_code"] < 400
    )
    latencies = [
        r["result"]["elapsed_ms"]
        for r in rows
        if r.get("result", {}).get("elapsed_ms") is not None
    ]
    summary = {
        "total_probed": total,
        "with_error": errors,
        "http_2xx_or_3xx": ok_http,
        "avg_elapsed_ms": round(mean(latencies), 2) if latencies else None,
    }
    table: List[Dict[str, Any]] = []
    for r in rows:
        res = r.get("result") or {}
        ep = r.get("endpoint") or {}
        table.append(
            {
                "index": r.get("index"),
                "method": ep.get("method"),
                "url": ep.get("url"),
                "status_code": res.get("status_code"),
                "elapsed_ms": res.get("elapsed_ms"),
                "error": res.get("error"),
            }
        )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "table": table,
        "results": rows,
    }
