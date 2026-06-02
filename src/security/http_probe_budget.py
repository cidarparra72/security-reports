"""Limite de peticiones HTTP dinamicas por URL de endpoint (evita rafagas largas)."""

from __future__ import annotations

from typing import Dict
from urllib.parse import urlparse


class HttpRequestBudget:
    """
    Cuenta peticiones por URL normalizada.
    max_per_endpoint <= 0 -> sin tope (comportamiento anterior).
    """

    def __init__(self, max_per_endpoint: int = 0) -> None:
        self.max_per_endpoint = int(max_per_endpoint)
        self._counts: Dict[str, int] = {}

    @property
    def enabled(self) -> bool:
        return self.max_per_endpoint > 0

    def _key(self, url: str) -> str:
        u = (url or "").strip()
        if not u:
            return ""
        try:
            p = urlparse(u)
            if p.scheme in ("http", "https") and p.netloc:
                path = p.path or "/"
                return f"{p.scheme}://{p.netloc}{path.rstrip('/') or '/'}"
        except ValueError:
            pass
        return u.rstrip("/") or u

    def allow(self, url: str) -> bool:
        if not self.enabled:
            return True
        k = self._key(url)
        if not k:
            return True
        return self._counts.get(k, 0) < self.max_per_endpoint

    def record(self, url: str) -> None:
        if not self.enabled:
            return
        k = self._key(url)
        if not k:
            return
        self._counts[k] = self._counts.get(k, 0) + 1

    def remaining(self, url: str) -> int | None:
        if not self.enabled:
            return None
        k = self._key(url)
        if not k:
            return self.max_per_endpoint
        used = self._counts.get(k, 0)
        return max(0, self.max_per_endpoint - used)

    def exhausted(self, url: str) -> bool:
        return self.enabled and not self.allow(url)
