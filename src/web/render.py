"""Turn the pandas display tables from ``src.visualization.tables`` into template data.

Only links to the two reference sites are ever made clickable, and only when the URL was
built by ``tables.attack_url`` / ``tables.nvd_url`` (validated ids). Extracted URLs and
domains are untrusted and always stay plain text.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import pandas as pd

LINK_PREFIXES = ("https://attack.mitre.org/", "https://nvd.nist.gov/vuln/detail/")
LINK_LABELS = {"ATT&CK": "ATT&CK ↗", "Reference": "ATT&CK ↗", "NVD": "NVD ↗"}
NUMERIC_KINDS = "iuf"


@dataclass(frozen=True)
class Cell:
    text: str
    href: str | None = None


@dataclass
class Table:
    columns: list[str]
    rows: list[list[Cell]]
    numeric: set[int] = field(default_factory=set)
    details: list[Table | None] | None = None  # one expandable sub-table per row
    total_rows: int = 0  # rows before truncation

    @property
    def truncated(self) -> bool:
        return self.total_rows > len(self.rows)


def format_value(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, float):
        if math.isnan(value):
            return ""
        return f"{value:,.0f}" if value.is_integer() else f"{value:,.2f}"
    if isinstance(value, int):
        return f"{value:,}" if abs(value) >= 10_000 else str(value)
    if isinstance(value, (list, tuple, set, frozenset)):
        return ", ".join(map(str, value))
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    return str(value)


def _cell(column: str, value: object) -> Cell:
    if column in LINK_LABELS:
        if isinstance(value, str) and value.startswith(LINK_PREFIXES):
            return Cell(LINK_LABELS[column], value)
        return Cell("")
    return Cell(format_value(value))


def table(frame: pd.DataFrame, details: list[pd.DataFrame | None] | None = None,
          max_rows: int | None = None) -> Table:
    """A template table. ``details`` gives an optional evidence sub-table per row."""
    total = len(frame)
    if max_rows is not None:
        frame = frame.head(max_rows)
        if details is not None:
            details = details[:max_rows]
    columns = [str(c) for c in frame.columns]
    numeric = {i for i, c in enumerate(frame.columns)
               if frame[c].dtype.kind in NUMERIC_KINDS and c not in LINK_LABELS}
    rows = [[_cell(c, v) for c, v in zip(columns, row, strict=True)]
            for row in frame.itertuples(index=False, name=None)]
    sub = None
    if details is not None:
        sub = [None if d is None or d.empty else table(d) for d in details]
    return Table(columns, rows, numeric, sub, total)


def key_values(pairs) -> Table:
    """A two-column Field / Value table."""
    return table(pd.DataFrame(list(pairs), columns=["Field", "Value"]))
