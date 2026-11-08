"""Plotly figures for the dashboard and explorers.

Colour decisions (validated against the app's dark surface ``#0e1117`` with the dataviz
palette validator):

* Single-series bars use one hue, blue ``#3987e5`` (passes band, chroma and ≥3:1 contrast).
  The chart title names the series, so no legend is shown.
* Risk bands are **not** colour-coded by status hues. The warning/serious pair fails the
  normal-vision separation floor (ΔE 13.6 < 15). Severity is carried by the band label and
  its icon instead.
* Heatmaps use the single-hue sequential blue ramp, anchored dark-at-zero for the dark
  surface (lightness monotone, adjacent ΔL ≥ 0.06).

Marks: thin bars with 4 px rounded ends, recessive grid, no dual axes, hover tooltips on
every mark. Every chart is paired with a table view in the UI.
"""

from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go

SERIES = "#3987e5"
TEXT_PRIMARY = "#f0efec"
TEXT_SECONDARY = "#c3c2b7"
MUTED = "#898781"
GRID = "#2c2c2a"
BASELINE = "#383835"
# Dark-mode sequential blue: near-zero recedes into the surface, high values are light.
SEQUENTIAL = ["#0e1117", "#0d366b", "#1c5cab", "#3987e5", "#86b6ef", "#cde2fb"]
BAND_ICONS = {"Low": "🟢 Low", "Moderate": "🟡 Moderate", "High": "🟠 High",
              "Critical": "🔴 Critical"}
FONT = 'system-ui, -apple-system, "Segoe UI", sans-serif'


def _layout(fig: go.Figure, title: str, height: int) -> go.Figure:
    fig.update_layout(
        title={"text": title, "x": 0, "font": {"size": 15, "color": TEXT_PRIMARY}},
        height=height, margin={"l": 8, "r": 16, "t": 44, "b": 8},
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font={"family": FONT, "color": TEXT_SECONDARY, "size": 12},
        showlegend=False, barcornerradius=4, bargap=0.35,
        hoverlabel={"font": {"family": FONT}},
    )
    fig.update_xaxes(gridcolor=GRID, zerolinecolor=BASELINE, linecolor=BASELINE,
                     tickfont={"color": MUTED}, rangemode="tozero")
    fig.update_yaxes(gridcolor="rgba(0,0,0,0)", linecolor=BASELINE, tickfont={"color": MUTED})
    return fig


def horizontal_bar(frame: pd.DataFrame, label: str, value: str, title: str,
                   unit: str) -> go.Figure:
    """Single-series magnitude bars, largest at the top."""
    data = frame.iloc[::-1]
    fig = go.Figure(go.Bar(
        x=data[value], y=data[label], orientation="h", marker={"color": SERIES},
        hovertemplate=f"%{{y}}: %{{x}} {unit}<extra></extra>",
    ))
    fig.update_xaxes(dtick=1 if (frame[value].max() if len(frame) else 0) <= 10 else None)
    return _layout(fig, title, height=max(180, 40 + 34 * len(frame)))


def risk_band_bar(frame: pd.DataFrame) -> go.Figure:
    """Documents per risk band, in severity order. Identity comes from the labels, not hue."""
    fig = go.Figure(go.Bar(
        x=[BAND_ICONS.get(b, b) for b in frame["Band"]], y=frame["Documents"],
        marker={"color": SERIES},
        hovertemplate="%{x}: %{y} documents<extra></extra>",
    ))
    fig.update_yaxes(gridcolor=GRID, dtick=1 if frame["Documents"].max() <= 10 else None,
                     rangemode="tozero")
    fig.update_xaxes(gridcolor="rgba(0,0,0,0)")
    fig = _layout(fig, "Documents by risk band (latest analysis)", height=260)
    fig.update_layout(bargap=0.6)  # few categories: keep the marks thin
    return fig


def tactic_heatmap(matrix: pd.DataFrame) -> go.Figure:
    fig = go.Figure(go.Heatmap(
        z=matrix.values, x=list(matrix.columns), y=list(matrix.index),
        colorscale=[[i / (len(SEQUENTIAL) - 1), c] for i, c in enumerate(SEQUENTIAL)],
        zmin=0, xgap=2, ygap=2,
        colorbar={"title": {"text": "Techniques"}, "tickfont": {"color": MUTED}, "dtick": 1},
        hovertemplate="%{y} · %{x}: %{z} techniques<extra></extra>",
    ))
    fig.update_xaxes(tickangle=-30, gridcolor="rgba(0,0,0,0)")
    fig.update_yaxes(autorange="reversed")  # most active tactic on top, read top-down
    return _layout(fig, "ATT&CK tactics per document (explicit or confirmed techniques)",
                   height=max(260, 60 + 30 * len(matrix.index)))
