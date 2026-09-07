"""Shared, escaped report presentation helpers."""
from __future__ import annotations

from html import escape
from typing import Any


def _evidence_value(entry: dict[str, Any], *keys: str) -> str:
    values: list[str] = []
    for metadata in entry.get("evidence", []):
        for key in keys:
            raw = metadata.get(key)
            if isinstance(raw, bool):
                value = "yes" if raw else "no"
            elif isinstance(raw, list):
                value = ", ".join(str(item).strip() for item in raw if str(item).strip())
            elif raw is not None:
                value = str(raw).strip()
            else:
                value = ""
            if value and value not in values:
                values.append(value)
    return ", ".join(values)


def _table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{escape(value)}</th>" for value in headers)
    if rows:
        body = "".join(
            "<tr>" + "".join(f"<td>{escape(str(value))}</td>" for value in row) + "</tr>"
            for row in rows
        )
    else:
        body = f'<tr><td colspan="{len(headers)}" class="empty">No findings</td></tr>'
    return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


