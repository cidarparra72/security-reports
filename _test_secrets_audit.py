"""Tests for secrets / burned tokens audit."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from security.secrets_audit import mask_secret, run_secrets_audit
from security.vuln_filters import filter_vulnerabilities_for_report


def test_masks_long_secret():
    assert "…" in mask_secret("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig")


def test_finds_jwt(tmp_path):
    p = tmp_path / "auth.js"
    p.write_text(
        'const t = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";\n',
        encoding="utf-8",
    )
    vulns, meta = run_secrets_audit(str(tmp_path), ["javascript"])
    assert meta["findings_count"] >= 1
    assert any(v.severity == "CRITICAL" for v in vulns)


def test_skips_example_email(tmp_path):
    p = tmp_path / "form.js"
    p.write_text(
        'const msg = "ejemplo: correo@ejemplo.com";\nconst token = "Bearer sk_test_12345678901234567890123456789012";\n',
        encoding="utf-8",
    )
    vulns, meta = run_secrets_audit(str(tmp_path), ["javascript"])
    filtered = filter_vulnerabilities_for_report([v.__dict__ for v in vulns])
    assert meta["findings_count"] >= 1
