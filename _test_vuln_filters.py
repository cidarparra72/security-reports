"""Tests for LAN/WSDL vulnerability filtering."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from security.vuln_filters import filter_vulnerabilities_for_report, is_lan_insecure_http_finding


def test_drops_lan_insecure_http():
    v = {
        "pattern_id": "INSECURE_HTTP",
        "title": "Insecure HTTP Endpoint",
        "code_snippet": "http://192.168.5.25:10021/web/services/X?wsdl",
        "file": "test/foo.test.js",
        "line": 1,
        "severity": "MEDIUM",
    }
    assert is_lan_insecure_http_finding(v)
    assert filter_vulnerabilities_for_report([v]) == []


def test_keeps_public_https_issue():
    v = {
        "pattern_id": "INSECURE_HTTP",
        "title": "Insecure HTTP Endpoint",
        "code_snippet": "http://api.example.com/v1/users",
        "file": "src/client.js",
        "line": 2,
        "severity": "MEDIUM",
    }
    assert not is_lan_insecure_http_finding(v)
    assert len(filter_vulnerabilities_for_report([v])) == 1
