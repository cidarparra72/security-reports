"""Tests for JS function extraction and per-function analysis."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from security.js_code_analysis import run_js_code_analysis
from security.js_function_blocks import extract_js_functions, innermost_block_at


SAMPLE = """
export function merchantRequestWithLog(options) {
  return my.request({ ...options, url: options.url });
}

const fetchUser = async () => {
  const res = await fetch('/api/user');
  return res.json();
};

function safe() {
  const token = getToken();
  return fetch('/api/x', { headers: { Authorization: 'Bearer ' + token } });
}
"""


def test_extract_functions():
    blocks = extract_js_functions(SAMPLE)
    names = {b.name for b in blocks}
    assert "merchantRequestWithLog" in names
    assert "fetchUser" in names
    assert "safe" in names
    inner = innermost_block_at(blocks, 8)
    assert inner and inner.name == "fetchUser"


def test_wrapper_not_flagged(tmp_path):
    p = tmp_path / "api.js"
    p.write_text(SAMPLE, encoding="utf-8")
    findings, meta = run_js_code_analysis(str(tmp_path), ["javascript"])
    titles = [f.title for f in findings]
    assert meta["functions_analyzed"] >= 3
    assert not any("merchantRequestWithLog" in (f.function_name or "") and "HTTP" in f.title for f in findings)
    assert any(f.function_name == "fetchUser" for f in findings)


def test_api_resilience_try_catch(tmp_path):
    p = tmp_path / "remote.js"
    p.write_text(
        "async function load() {\n"
        "  try {\n"
        "    const res = await my.requestLogs({ url: '/x' });\n"
        "    if (!res || res.error) throw new Error('fail');\n"
        "    return res.data;\n"
        "  } catch (e) { return e; }\n"
        "}\n",
        encoding="utf-8",
    )
    findings, meta = run_js_code_analysis(str(tmp_path), ["javascript"])
    audit = meta.get("function_http_audit") or []
    load = next((a for a in audit if a.get("function") == "load"), None)
    assert load is not None
    assert load.get("has_try_catch") is True
    assert load.get("has_validation") is True


def test_auth_in_function_body_suppresses(tmp_path):
    p = tmp_path / "ok.js"
    p.write_text(
        "function load() {\n  const t = getToken();\n  fetch('/x', { headers: { Authorization: t } });\n}\n",
        encoding="utf-8",
    )
    findings, _meta = run_js_code_analysis(str(tmp_path), ["javascript"])
    assert not any("HTTP" in f.title for f in findings)
