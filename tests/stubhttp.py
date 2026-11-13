"""Response and HTTP doubles for the offline module tests.

The new modules (waf, brute, params, fuzz, jslib) are all written against a
small slice of the HTTP client: ``get(url, headers=...)`` returning an object
with ``status``, ``body``, ``text``, ``url`` and ``headers``. That is enough to
exercise every decision they make without opening a socket, so these tests stay
fast and deterministic.
"""
from __future__ import annotations

import urllib.parse


class Resp:
    """Minimal stand-in for :class:`xssmap.net.Response`."""

    def __init__(self, url: str, status: int = 200, body="", headers=None):
        self.url = url
        self.status = status
        self.body = body.encode("utf-8") if isinstance(body, str) else body
        self.text = self.body.decode("utf-8", "replace")
        self.headers = list(headers or [])
        self.content_type = "text/html; charset=utf-8"
        self.encoding = "utf-8"

    def header(self, name: str, default: str = "") -> str:
        lowered = name.lower()
        for key, value in self.headers:
            if key.lower() == lowered:
                return value
        return default


class FakeHTTP:
    """``router(url) -> Resp``; records every URL it was asked for."""

    def __init__(self, router, headers=None):
        self.router = router
        self.urls: list[str] = []
        self.headers = list(headers or [])
        self.stats = {"requests": 0, "errors": 0, "bytes": 0, "rate_limits": 0}

    def get(self, url: str, headers=None, **kwargs) -> Resp:
        self.urls.append(url)
        self.stats["requests"] += 1
        resp = self.router(url)
        if resp is None:
            raise RuntimeError("no route for " + url)
        return resp

    def post(self, *args, **kwargs):  # pragma: no cover - not used by these modules
        raise NotImplementedError


def query_dict(url: str) -> dict[str, str]:
    """Last value wins, which is what the probes rely on."""
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query,
                                       keep_blank_values=True))


def query_text(url: str) -> str:
    return urllib.parse.urlsplit(url).query
