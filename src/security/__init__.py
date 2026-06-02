# Security Scanner Package

__all__ = [
    "APISecurityScanner",
    "checks_catalog",
    "normalize_selected_checks",
    "EthicalHackingReportGenerator",
    "VulnerabilityReport",
    "merge_external_findings",
    "parse_zap_report",
    "parse_burp_report",
    "manual_checklist_templates",
    "parse_manual_findings",
]


def __getattr__(name):
    if name == "APISecurityScanner":
        from .api_scanner import APISecurityScanner

        return APISecurityScanner
    if name in {"checks_catalog", "normalize_selected_checks"}:
        from .checks_catalog import checks_catalog, normalize_selected_checks

        return {
            "checks_catalog": checks_catalog,
            "normalize_selected_checks": normalize_selected_checks,
        }[name]
    if name in {"EthicalHackingReportGenerator", "VulnerabilityReport"}:
        from .report_generator import EthicalHackingReportGenerator, VulnerabilityReport

        return {
            "EthicalHackingReportGenerator": EthicalHackingReportGenerator,
            "VulnerabilityReport": VulnerabilityReport,
        }[name]
    if name in {"merge_external_findings", "parse_zap_report", "parse_burp_report"}:
        from .external_import import merge_external_findings, parse_burp_report, parse_zap_report

        return {
            "merge_external_findings": merge_external_findings,
            "parse_zap_report": parse_zap_report,
            "parse_burp_report": parse_burp_report,
        }[name]
    if name in {"manual_checklist_templates", "parse_manual_findings"}:
        from .manual_checks import manual_checklist_templates, parse_manual_findings

        return {
            "manual_checklist_templates": manual_checklist_templates,
            "parse_manual_findings": parse_manual_findings,
        }[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
