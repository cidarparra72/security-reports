"""Tests for per-endpoint report association."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from security.endpoint_report import _finding_matches_endpoint


def test_dynamic_api_base_finding_matches_card_endpoint():
    v = {
        "file": "<dynamic:api>",
        "title": "Falta X-Content-Type-Options",
        "code_snippet": "https://urs.qa.vettica.co/",
    }
    assert _finding_matches_endpoint(
        v,
        path_norm="/card/valid",
        url_norm="https://urs.qa.vettica.co/card/valid",
        api_url_norm="https://urs.qa.vettica.co",
        endpoint_source_files=set(),
    )


def test_options_snippet_matches_endpoint_url():
    v = {
        "file": "<dynamic:api>",
        "title": "Métodos sensibles",
        "code_snippet": "OPTIONS https://urs.qa.vettica.co/card/valid/",
    }
    assert _finding_matches_endpoint(
        v,
        path_norm="/card/valid",
        url_norm="https://urs.qa.vettica.co/card/valid",
        api_url_norm="https://urs.qa.vettica.co",
        endpoint_source_files=set(),
    )
