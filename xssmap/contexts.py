"""One registry for reflection contexts, shared by every stage.

Reflection contexts used to be implied in four places - the payload ladder, the
WAF markup filter, the brute-force executor list and its rawtext set - each with
its own opinion about what a context means. They drifted: a strategy could be
offered for a context where it could never work. This module makes the context
name the only identifier and puts the facts next to it.

A context answers three questions:

``executable``   can markup or script placed here actually run in a browser?
``markup``       is HTML markup meaningful at this position (so tag-level
                 obfuscation like case or comment padding has an effect)?
``break_quote``  which quote, if any, has to be closed to escape the position?

Anything not in :data:`CONTEXTS` is treated as non-executable and non-markup: a
reflection in an unknown position is reported as a reflection, never as code
execution.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Context:
    name: str
    executable: bool = False
    markup: bool = False
    break_quote: str = ""
    rawtext: str = ""           # closing tag needed to escape this element
    note: str = ""

    @property
    def needs_closing_tag(self) -> bool:
        return bool(self.rawtext)


# The names here are the values produced by
# payloads.classify_reflections(); nothing else should invent a context.
CONTEXTS: dict[str, Context] = {
    # --- HTML body -------------------------------------------------------
    "html_text": Context("html_text", executable=True, markup=True,
                         note="markup is parsed directly"),
    "generic": Context("generic", executable=True, markup=True,
                       note="unknown position; assume markup until disproved"),
    "tag_space": Context("tag_space", executable=True, markup=True,
                         note="inside a tag between attributes; a new attribute works"),
    "comment": Context("comment", executable=True, markup=True, break_quote=">",
                       note="needs --> to leave the comment"),
    # --- attribute values ------------------------------------------------
    "attr_double": Context("attr_double", executable=True, markup=True,
                           break_quote='"'),
    "attr_single": Context("attr_single", executable=True, markup=True,
                           break_quote="'"),
    "attr_unquoted": Context("attr_unquoted", executable=True, markup=True,
                             break_quote=" ",
                             note="a space ends an unquoted value"),
    "attr_url": Context("attr_url", executable=True, markup=True,
                        break_quote='"',
                        note="javascript:/data: executes when the attribute is followed"),
    "url_attr": Context("url_attr", executable=True, markup=True, break_quote='"',
                        note="alias of attr_url used by the synthesizer"),
    # --- script bodies ---------------------------------------------------
    "js_code": Context("js_code", executable=True, markup=False,
                       note="statement position: break out of the statement"),
    "js_string_double": Context("js_string_double", executable=True, markup=False,
                                break_quote='"'),
    "js_string_single": Context("js_string_single", executable=True, markup=False,
                                break_quote="'"),
    "js_template": Context("js_template", executable=True, markup=False,
                           break_quote="`"),
    "script_data": Context("script_data", executable=True, markup=False,
                           rawtext="script",
                           note="JSON/LD+JSON block: only </script> escapes it"),
    # --- RCDATA / rawtext elements --------------------------------------
    "textarea": Context("textarea", executable=True, markup=True, rawtext="textarea"),
    "title": Context("title", executable=True, markup=True, rawtext="title"),
    "style": Context("style", executable=True, markup=True, rawtext="style"),
    "xmp": Context("xmp", executable=True, markup=True, rawtext="xmp"),
    "noscript": Context("noscript", executable=True, markup=True, rawtext="noscript"),
    # Obsolete rawtext elements: still parsed as text, still escaped by their
    # own end tag, and previously invisible to the classifier entirely.
    "noembed": Context("noembed", executable=True, markup=True, rawtext="noembed"),
    "noframes": Context("noframes", executable=True, markup=True, rawtext="noframes"),
    # Template content is inert until cloned, but its own end tag ends the
    # element in the HTML parser, so `</template>` + markup is live markup.
    "template": Context("template", executable=True, markup=True, rawtext="template"),
}

# Contexts that exist in reports but can never execute markup: kept so that
# "this reflected but is not code execution" stays sayable.
NON_EXECUTABLE: tuple[str, ...] = ("json_body", "header", "plain_text",
                                   "json_value", "css_value", "xml_text")

_FALLBACK = Context("unknown", executable=False, markup=False)

EXECUTABLE_CONTEXTS: tuple[str, ...] = tuple(
    name for name, ctx in CONTEXTS.items() if ctx.executable)
MARKUP_CONTEXTS: frozenset[str] = frozenset(
    name for name, ctx in CONTEXTS.items() if ctx.markup)
RAWTEXT_CONTEXTS: tuple[str, ...] = tuple(
    name for name, ctx in CONTEXTS.items() if ctx.rawtext)


def get(name: str) -> Context:
    """Context record for *name*; unknown names are inert by design."""
    return CONTEXTS.get(name or "", _FALLBACK)


def executable(name: str) -> bool:
    return get(name).executable


def markup(name: str) -> bool:
    return get(name).markup


def break_quote(name: str) -> str:
    return get(name).break_quote


def rawtext(name: str) -> str:
    return get(name).rawtext


def describe(name: str) -> str:
    ctx = get(name)
    if ctx.note:
        return f"{name} ({ctx.note})"
    return name or "unknown"
