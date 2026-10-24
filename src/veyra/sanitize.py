"""One shared escaper for text Veyra did not author.

``evidence``, ``matched_text``, rule titles, file names and semantic node
labels all originate in the scanned repository, so they are untrusted input to
a terminal and to a CI log. The dangerous part is the control characters: a
newline lets a repository print a line of its own choosing (for example a fake
``suppressed: yes``), and ESC/CSI sequences can move the cursor, recolour or
erase arbitrary text.

Every character that is not printable is therefore rendered as a visible
``\\xNN`` / ``\\uNNNN`` / ``\\UNNNNNNNN`` escape instead of being emitted raw,
and a backslash is doubled so the escape form itself cannot be forged by the
input. Printable text -- including non-ASCII -- is left alone: this is an
escaper, not a transliterator.

This module is the single place that decides how such text is escaped.
``veyra.explain`` uses it; a report renderer that needs to show the same bytes
must call it rather than grow a second, subtly different filter.
"""

from __future__ import annotations

from typing import Any

#: Upper bound on one escaped field. A rule can quote a whole 1 MiB line;
#: printing it in a CI log helps nobody, and the bound is stated rather than
#: silent because the marker below says the value was cut.
MAX_TEXT_CHARS = 500

TRUNCATION_MARKER = " [truncated]"


def escape_untrusted(value: Any, limit: int = MAX_TEXT_CHARS) -> str:
    """Return ``value`` with every non-printable character made visible.

    ``limit`` bounds the length of the *escaped* result, because one raw byte
    can expand to ten. ``None`` disables the bound (used by tests).
    """
    text = value if isinstance(value, str) else str(value)
    out = []
    for char in text:
        if char == "\\":
            out.append("\\\\")
        elif char.isprintable():
            out.append(char)
        else:
            code = ord(char)
            if code <= 0xFF:
                out.append("\\x%02x" % code)
            elif code <= 0xFFFF:
                out.append("\\u%04x" % code)
            else:
                out.append("\\U%08x" % code)
    escaped = "".join(out)
    if limit is not None and len(escaped) > limit:
        escaped = escaped[:limit] + TRUNCATION_MARKER
    return escaped
