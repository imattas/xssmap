"""Multibyte charset escaping bypasses (GBK, Big5, Shift_JIS).

Backslash-escaping assumes one byte is one character. In a multibyte encoding
it is not: a lead byte followed by ``0x5C`` is a single character, so an escape
routine that turns ``'`` into ``\\'`` produces a byte sequence the database (or
the template engine) decodes as *one character followed by a bare quote*. The
quote closes the string the developer thought was protected.

The canonical case is the Java/MySQL ``SET NAMES gbk`` bug: the input
``0xBF 0x27`` is escaped to ``0xBF 0x5C 0x27``, which decodes as ``縗`` + ``'``.

Detecting this needs bytes, not text: the check is whether ``lead + 0x5C``
decodes to exactly one character under the page's declared charset, and whether
a quote and the injected code follow it. A page that escapes correctly (or
escapes twice, or never decodes as that charset) fails the test.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_CHARSET_PARAM_RE = re.compile(r"charset\s*=\s*[\"']?\s*([\w.:-]+)", re.I)
_META_CHARSET_RE = re.compile(rb"<meta[^>]+charset\s*=\s*[\"']?\s*([a-z0-9_.:-]+)", re.I)


@dataclass(frozen=True)
class Family:
    """One multibyte encoding that can swallow an escape byte."""

    name: str
    codec: str
    lead: bytes           # lead byte that consumes a following 0x5C
    aliases: tuple[str, ...]
    note: str


FAMILIES: tuple[Family, ...] = (
    Family("GBK", "gbk", b"\xbf",
           ("gbk", "gb2312", "gb_2312-80", "gb18030", "cp936", "x-gbk", "euc-cn"),
           "GBK/GB2312/GB18030 (0xBF 0x5C is one character)"),
    Family("Big5", "big5", b"\xa1",
           ("big5", "big5-hkscs", "cp950", "x-x-big5"),
           "Big5 (0xA1 0x5C is one character)"),
    Family("Shift_JIS", "shift_jis", b"\x81",
           ("shift_jis", "shift-jis", "sjis", "x-sjis", "windows-31j", "cp932", "ms_kanji"),
           "Shift_JIS (0x81 0x5C is one character)"),
)

BY_NAME = {alias: family for family in FAMILIES for alias in family.aliases}


def family_for(charset: str | None) -> Family | None:
    """Map a charset label to the multibyte family it belongs to."""
    if not charset:
        return None
    return BY_NAME.get(charset.strip().strip("\"'").lower())


def detect(content_type: str | None, body: bytes = b"") -> Family | None:
    """Find the response charset from the header, then from a <meta> tag."""
    match = _CHARSET_PARAM_RE.search(content_type or "")
    if match:
        family = family_for(match.group(1))
        if family:
            return family
    meta = _META_CHARSET_RE.search(body[:4096])
    if meta:
        return family_for(meta.group(1).decode("ascii", "ignore"))
    return None


def pair_is_one_character(family: Family, lead: bytes, trail: bytes = b"\\") -> bool:
    """Does ``lead + trail`` decode to a single character in this encoding?"""
    try:
        decoded = (lead + trail).decode(family.codec)
    except (UnicodeDecodeError, LookupError):
        return False
    return len(decoded) == 1


def escape_observed(body: bytes, quote: bytes = b"'") -> bool:
    """Did the application backslash-escape the quote at all?"""
    return b"\\" + quote in (body or b"")


def probe_bytes(family: Family, js: str) -> bytes:
    """Bytes that break a single-quoted JS string through the escape byte.

    ``lead`` + ``'`` is escaped to ``lead + \\ + '``; that pair decodes to one
    character, so ``'`` terminates the string, ``;`` starts our statement and
    the trailing ``//`` comments out whatever the template appended.
    """
    return family.lead + b"';" + js.encode("ascii", "ignore") + b"//"


def bypass_in_body(body: bytes, family: Family, js_head: bytes = b"document.") -> bool:
    """Is the escaped quote decoded as a bare quote followed by our code?

    Requires the exact byte pattern the probe produces after escaping:
    ``lead 0x5C 0x27 ;`` -- and that ``lead 0x5C`` really is one character in
    the declared encoding. Anything else (double escaping, utf-8, quote
    stripping) fails the check.
    """
    needle = family.lead + b"\\';"
    body = body or b""
    index = body.find(needle)
    while index != -1:
        if pair_is_one_character(family, family.lead):
            tail = body[index + len(needle):index + len(needle) + len(js_head)]
            if tail == js_head:
                return True
        index = body.find(needle, index + 1)
    return False


def describe(family: Family) -> str:
    return f"{family.name} ({family.note})"
