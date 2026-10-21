"""Shared payload normalization applied before deterministic signature matching."""
from __future__ import annotations
import html
import re
from urllib.parse import unquote

_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})|\\x([0-9a-fA-F]{2})")
_SQL_COMMENTS = re.compile(r"/\*.*?\*/|<!--.*?-->|--[ \t][^\r\n]*|#[^\r\n]*", re.S)
_WHITESPACE = re.compile(r"\s+")


def _decode_unicode(match: re.Match[str]) -> str:
    digits = next(value for value in match.groups() if value is not None)
    try:
        return chr(int(digits, 16))
    except (ValueError, OverflowError):
        return match.group(0)


def _strip_sql_comment(match: re.Match[str]) -> str:
    token=match.group(0)
    if token.startswith(("/*", "<!--")):
        before=match.string[match.start()-1:match.start()]
        after=match.string[match.end():match.end()+1]
        # Join comment-split keywords (UN/**/ION) while preserving token
        # separation when a comment sits between independent SQL tokens.
        if before and after and (before[-1].isalnum() or before[-1]=="_") and (after[0].isalnum() or after[0]=="_"):
            return ""
        return " "
    return " "


def normalize_payload(value: str) -> str:
    """Decode nested encodings in three bounded passes, strip comments, collapse spaces."""
    current = str(value)
    for _ in range(3):
        decoded = unquote(current)
        decoded = html.unescape(decoded)
        decoded = _UNICODE_ESCAPE.sub(_decode_unicode, decoded)
        if decoded == current:
            break
        current = decoded
    current = _SQL_COMMENTS.sub(_strip_sql_comment, current)
    return _WHITESPACE.sub(" ", current).strip()


def normalize_request(event: dict) -> str:
    return normalize_payload(f"{event.get('path', '')}?{event.get('query', '')}")
