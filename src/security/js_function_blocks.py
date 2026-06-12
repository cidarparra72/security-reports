#!/usr/bin/env python3
"""Extracción heurística de bloques de función en JS/TS (sin parser AST)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

# Líneas enormes / paréntesis anidados en minified JS pueden tumbar el motor regex de Python.
_MAX_REGEX_LINE_LEN = 4_000
_PAREN = r"[^)]{0,512}"

_FUNC_START_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s+(\w+)", re.I),
    re.compile(
        rf"^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\({_PAREN}\)\s*=>)",
        re.I,
    ),
    re.compile(r"^\s*(\w+)\s*:\s*(?:async\s+)?function\b", re.I),
    re.compile(rf"^\s*(\w+)\s*:\s*(?:async\s+)?\({_PAREN}\)\s*=>", re.I),
    re.compile(rf"^\s*(?:async\s+)?(\w+)\s*\({_PAREN}\)\s*\{{", re.I),
)

_RESERVED = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "else",
        "do",
        "try",
        "finally",
        "with",
        "return",
        "throw",
        "new",
        "class",
        "constructor",
        "get",
        "set",
        "static",
        "import",
        "export",
        "default",
    }
)


@dataclass(frozen=True)
class JsFunctionBlock:
    name: str
    start_line: int
    end_line: int
    body_text: str
    signature: str


def _scan_brace_close(text: str, open_idx: int) -> int:
    """Índice (exclusive) del cierre de `{` en open_idx, o -1."""
    depth = 0
    i = open_idx
    n = len(text)
    in_sq = in_dq = in_tpl = False
    in_line_comment = False
    in_block_comment = False
    esc = False

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
        if in_sq:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == "'":
                in_sq = False
            i += 1
            continue
        if in_dq:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_dq = False
            i += 1
            continue
        if in_tpl:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == "`":
                in_tpl = False
            i += 1
            continue

        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        if ch == "'":
            in_sq = True
            i += 1
            continue
        if ch == '"':
            in_dq = True
            i += 1
            continue
        if ch == "`":
            in_tpl = True
            i += 1
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def _line_col_to_offset(lines: Sequence[str], line_idx: int, col: int) -> int:
    off = 0
    for i in range(line_idx):
        off += len(lines[i]) + 1
    return off + col


def _offset_to_line(lines: Sequence[str], offset: int) -> int:
    pos = 0
    for i, ln in enumerate(lines):
        nxt = pos + len(ln) + 1
        if offset < nxt:
            return i + 1
        pos = nxt
    return len(lines)


def _find_open_brace(lines: Sequence[str], from_line_idx: int, search_from_col: int = 0) -> Optional[Tuple[int, int]]:
    """(line_idx 0-based, col) de la primera `{` desde la línea dada."""
    for li in range(from_line_idx, min(from_line_idx + 8, len(lines))):
        line = lines[li]
        start = search_from_col if li == from_line_idx else 0
        col = line.find("{", start)
        if col >= 0:
            return li, col
    return None


def _name_from_line(line: str) -> Optional[str]:
    if len(line) > _MAX_REGEX_LINE_LEN:
        return None
    for pat in _FUNC_START_PATTERNS:
        try:
            m = pat.match(line)
        except RuntimeError:
            return None
        if not m:
            continue
        name = next((g for g in m.groups() if g), None)
        if name and name.lower() not in _RESERVED:
            return name
    return None


def extract_js_functions(text: str) -> List[JsFunctionBlock]:
    """Lista de funciones con rango de líneas y cuerpo (heurística por llaves)."""
    lines = text.splitlines()
    if not lines:
        return []

    joined = "\n".join(lines)
    blocks: List[JsFunctionBlock] = []
    seen_ranges: set[Tuple[int, int]] = set()

    for line_idx, line in enumerate(lines):
        name = _name_from_line(line)
        if not name:
            continue

        brace = _find_open_brace(lines, line_idx)
        if brace:
            b_li, b_col = brace
            open_off = _line_col_to_offset(lines, b_li, b_col)
            close_off = _scan_brace_close(joined, open_off)
            if close_off < 0:
                continue
            end_line = _offset_to_line(lines, close_off - 1)
            body_text = joined[open_off + 1 : close_off - 1]
            key = (line_idx + 1, end_line)
            if key in seen_ranges:
                continue
            seen_ranges.add(key)
            blocks.append(
                JsFunctionBlock(
                    name=name,
                    start_line=line_idx + 1,
                    end_line=end_line,
                    body_text=body_text,
                    signature=line.strip()[:200],
                )
            )
            continue

        if "=>" in line and "{" not in line.split("=>", 1)[-1]:
            stmt = line.split("//")[0].strip()
            if stmt.endswith(","):
                stmt = stmt[:-1]
            key = (line_idx + 1, line_idx + 1)
            if key in seen_ranges:
                continue
            seen_ranges.add(key)
            blocks.append(
                JsFunctionBlock(
                    name=name,
                    start_line=line_idx + 1,
                    end_line=line_idx + 1,
                    body_text=stmt,
                    signature=line.strip()[:200],
                )
            )

    blocks.sort(key=lambda b: (b.start_line, b.end_line))
    return blocks


def innermost_block_at(blocks: Sequence[JsFunctionBlock], line_no: int) -> Optional[JsFunctionBlock]:
    containing = [b for b in blocks if b.start_line <= line_no <= b.end_line]
    if not containing:
        return None
    return max(containing, key=lambda b: b.start_line)


def module_level_segments(text: str, blocks: Sequence[JsFunctionBlock]) -> List[Tuple[int, int, str]]:
    """Trozos de código fuera de funciones: (start_line, end_line, text)."""
    lines = text.splitlines()
    if not lines:
        return []
    covered = [False] * len(lines)
    for b in blocks:
        for i in range(b.start_line - 1, min(b.end_line, len(lines))):
            covered[i] = True
    segments: List[Tuple[int, int, str]] = []
    start: Optional[int] = None
    for i, is_cov in enumerate(covered):
        if not is_cov:
            if start is None:
                start = i
        elif start is not None:
            chunk = "\n".join(lines[start:i])
            if chunk.strip():
                segments.append((start + 1, i, chunk))
            start = None
    if start is not None:
        chunk = "\n".join(lines[start:])
        if chunk.strip():
            segments.append((start + 1, len(lines), chunk))
    return segments
