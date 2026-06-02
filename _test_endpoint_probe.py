"""Tests for modular API endpoint probe (parse, build, report)."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from security.endpoint_probe import (
    build_consolidated_report,
    parse_endpoints_from_json,
    parse_paths_multiline,
    prepare_endpoints,
    run_probes,
)


def test_parse_json_array():
    raw, errs = parse_endpoints_from_json(
        json.dumps([{"method": "GET", "path": "/a"}, {"url": "https://x.com/b"}])
    )
    assert not errs
    assert len(raw) == 2


def test_parse_paths_multiline():
    raw, errs = parse_paths_multiline("GET /a\n/b\n# c\n")
    assert not errs
    assert raw[0]["method"] == "GET" and raw[0]["path"] == "/a"
    assert raw[1]["method"] == "GET" and raw[1]["path"] == "/b"


def test_prepare_merge_base():
    raw = [{"method": "GET", "path": "v1/x"}]
    norm, errs = prepare_endpoints(raw, "https://api.example.com")
    assert not errs
    assert norm[0]["url"] == "https://api.example.com/v1/x"


def test_parse_openapi_paths_object():
    spec = {
        "openapi": "3.0.0",
        "paths": {"/pets": {"get": {}, "post": {}}, "/pets/{id}": {"get": {}}},
    }
    raw, errs = parse_endpoints_from_json(json.dumps(spec))
    assert not errs
    assert len(raw) == 3
    methods = sorted(x["method"] for x in raw)
    assert methods == ["GET", "GET", "POST"]


def test_parse_paths_array_wrapper():
    raw, errs = parse_endpoints_from_json(
        json.dumps({"paths": [{"method": "GET", "path": "/a"}]})
    )
    assert not errs
    assert raw[0]["path"] == "/a"


def test_normalize_endpoint_alias():
    raw = [{"method": "GET", "endpoint": "/z"}]
    norm, errs = prepare_endpoints(raw, "https://x.com")
    assert not errs
    assert norm[0]["url"] == "https://x.com/z"


def test_run_probes_indices(monkeypatch):
    captured = []

    def fake_probe_one(endpoint, *, timeout_sec, max_response_bytes):
        captured.append(endpoint["url"])
        return {
            "request": {},
            "status_code": 200,
            "elapsed_ms": 1.0,
            "error": None,
            "response_headers": {},
            "body_preview": "",
            "body_truncated": False,
            "validations": [],
            "hints": [],
        }

    import security.endpoint_probe.runner as runner_mod

    monkeypatch.setattr(runner_mod, "probe_one", fake_probe_one)
    eps = [
        {"method": "GET", "url": "https://a.test/1", "params": {}, "headers": {}, "body": None},
        {"method": "GET", "url": "https://a.test/2", "params": {}, "headers": {}, "body": None},
    ]
    rows = run_probes(eps, indices=[1], timeout_sec=5, max_response_bytes=1000)
    assert len(rows) == 1
    assert captured == ["https://a.test/2"]
    rep = build_consolidated_report(rows)
    assert rep["summary"]["total_probed"] == 1
    assert len(rep["table"]) == 1
