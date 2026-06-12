#!/usr/bin/env python3
"""Repara report.html con bytes Latin-1 corruptos (\\x9d) y lo guarda en UTF-8."""

from __future__ import annotations

import re
import sys
from pathlib import Path

_TEMPLATE = Path(__file__).parent / "templates" / "report.html"

_REPLACEMENTS = [
    ("INTRODUCCI\x9dN", "INTRODUCCIÓN"),
    ("INFORME T\x9dCNICO", "INFORME TÉCNICO"),
    ("ANEXOS T\x9dCNICOS", "ANEXOS TÉCNICOS"),
    ("Anexos T\x9dcnicos", "Anexos Técnicos"),
    ("Detalle T\x9dcnico", "Detalle Técnico"),
    ("Informe T\x9dcnico", "Informe Técnico"),
    ("Estado t\x9dcnico", "Estado técnico"),
    ("anexo t\x9dcnico", "anexo técnico"),
    ("Alcance del an\x9dlisis est\x9dtico", "Alcance del análisis estático"),
    ("Resumen de an\x9dlisis ejecutados", "Resumen de análisis ejecutados"),
    ("Qu\x9d motores", "Qué motores"),
    ("an\x9dlisis est\x9dtico", "análisis estático"),
    ("de an\x9dlisis ej", "de análisis ej"),
    ("an\x9dlisis de", "análisis de"),
    ("Versi\x9dn", "Versión"),
    ("An\x9dlisis", "Análisis"),
    ("autenticaci\x9dn", "autenticación"),
    ("validaci\x9dn", "validación"),
    ("Validaci\x9dn", "Validación"),
    ("Funci\x9dn", "Función"),
    ("Introducci\x9dn", "Introducción"),
    ("Priorizaci\x9dn", "Priorización"),
    ("supresi\x9dn", "supresión"),
    ("integraci\x9dn", "integración"),
    ("remediaci\x9dn", "remediación"),
    ("c\x9ddigo", "código"),
    ("din\x9dmicas", "dinámicas"),
    ("din\x9dmica", "dinámica"),
    ("est\x9dtico", "estático"),
    ("Cr\x9dtico", "Crítico"),
    ("Despu\x9ds", "Después"),
    ("Categor\x9da", "Categoría"),
    ("Descripci\x9dn", "Descripción"),
    ("Explotaci\x9dn", "Explotación"),
    ("revisi\x9dn", "revisión"),
    ("Mitigaci\x9dn", "Mitigación"),
    ("Soluci\x9dn", "Solución"),
    ("colecci\x9dn", "colección"),
    ("M\x9dtodo", "Método"),
    ("secci\x9dn", "sección"),
    ("est\x9dn", "están"),
    ("limit\x9d", "limitó"),
    ("autom\x9dticamente", "automáticamente"),
    ("ra\x9dz", "raíz"),
    ('{{ "S\x9d"', '{{ "Sí"'),
    (" v{{ version }} \x9d {{", " v{{ version }} · {{"),
    ("an\x9dlisis", "análisis"),
    ("t\x9dcnico", "técnico"),
    ("T\x9dCNICO", "TÉCNICO"),
    ("T\x9dcnico", "Técnico"),
]


def ensure_report_template_utf8(path: Path | None = None) -> bool:
    """
    Si report.html no es UTF-8 válido, aplica reemplazos y reescribe el archivo.
    Devuelve True si hubo que reparar o el archivo ya era válido.
    """
    p = path or _TEMPLATE
    raw = p.read_bytes()
    try:
        raw.decode("utf-8")
        return True
    except UnicodeDecodeError:
        pass

    text = raw.decode("latin-1")
    for old, new in _REPLACEMENTS:
        text = text.replace(old, new)
    if "\x9d" in text:
        for m in re.finditer(r".{0,25}\x9d.{0,25}", text):
            raise ValueError(f"Quedan bytes corruptos en plantilla: {m.group()!r}")
    p.write_text(text, encoding="utf-8")
    return True


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else _TEMPLATE
    ensure_report_template_utf8(path)
    path.read_bytes().decode("utf-8")
    print(f"OK UTF-8: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
