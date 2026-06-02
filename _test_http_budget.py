"""Tests for per-endpoint HTTP request budget."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from security.http_probe_budget import HttpRequestBudget


def test_budget_stops_after_limit():
    b = HttpRequestBudget(2)
    url = "https://api.example.com/v1/users"
    assert b.allow(url)
    b.record(url)
    assert b.allow(url)
    b.record(url)
    assert not b.allow(url)
    assert b.exhausted(url)


def test_budget_zero_means_unlimited():
    b = HttpRequestBudget(0)
    url = "https://api.example.com/x"
    for _ in range(50):
        assert b.allow(url)
        b.record(url)
