"""The dashboard's look: the stylesheet, page headers, tiles and small charts.

Charts are HTML and inline SVG built here rather than a chart library. The browser downloads nothing
extra (Plotly alone was 4 MB), a page of six charts is a few kilobytes, and the colours come from the
same CSS variables as the rest of the page, so light and dark mode need no second set of charts.
Hover read-outs are plain CSS.

Anything that can come from a log line (hostnames, finding titles, user names, addresses) is escaped
with esc() before it goes into HTML: the page must never run what an attacker wrote into a log.
"""
from __future__ import annotations

import html
import math
import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Optional, Sequence

import streamlit as st

ASSETS = Path(__file__).parent / "assets"
SEVERITY_CLASS = {6: "critical", 5: "critical", 4: "high", 3: "medium", 2: "low", 1: "low", 0: "low", 99: "low"}
SEVERITY_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}


def esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


@lru_cache(maxsize=1)
def _stylesheet() -> str:
    """theme.css without its comments and spare whitespace: it is sent with every full page run."""
    css = re.sub(r"/\*.*?\*/", "", (ASSETS / "theme.css").read_text(encoding="utf-8"), flags=re.S)
    return re.sub(r"\s*([{};,>])\s*", r"\1", re.sub(r"\s+", " ", css)).strip()


def apply_theme() -> None:
    """Load the stylesheet, in a hidden container at the top of the page.

    Not st.html: a style-only st.html goes to Streamlit's event container, which a fragment rerun (the
    overview refreshes itself every 30 s) clears, and the page would lose its styling. A <style> element
    applies wherever it sits, even inside a hidden container.
    """
    with st.container(key="tl-theme"):
        st.markdown(f"<style>{_stylesheet()}</style>", unsafe_allow_html=True)


# ------------------------------------------------------------------ numbers and times
def num(n) -> str:
    return f"{int(n or 0):,}"


def compact(n) -> str:
    n = float(n or 0)
    for size, suffix in ((1e9, "B"), (1e6, "M"), (1e3, "K")):
        if abs(n) >= size:
            v = n / size
            return f"{v:.1f}{suffix}".replace(".0" + suffix, suffix) if v < 100 else f"{v:.0f}{suffix}"
    return f"{n:.0f}"


def pct(v, digits: int = 1) -> str:
    v = float(v or 0)
    return f"{v:.0f}%" if v in (0, 100) else f"{v:.{digits}f}%"


def utc(ms: Optional[int], fmt: str = "%d %b %H:%M") -> str:
    """A UTC time; a day of the month loses its leading zero (Windows strftime has no %-d)."""
    if ms is None:
        return "-"
    text = datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime(fmt)
    return text[1:] if fmt.startswith("%d") and text.startswith("0") else text


def severity_class(severity_id) -> str:
    return SEVERITY_CLASS.get(int(severity_id or 0), "low")


# ------------------------------------------------------------------ page furniture
def page_header(title: str, meta: str = "", dot: Optional[str] = None, controls: float = 0.0):
    """The title row every page starts with. `meta` is trusted HTML (callers escape their values).

    With controls > 0 the row is split and the right-hand part (that share of the width) is returned as
    a horizontal container for the page's controls; otherwise nothing is returned.
    """
    dot_html = f'<span class="tl-dot tl-dot--{dot}"></span>' if dot else ""
    head = (f'<div class="tl-head"><h1>{dot_html}{esc(title)}</h1>'
            + (f'<div class="tl-head__meta">{meta}</div>' if meta else "") + "</div>")
    if controls <= 0:
        st.markdown(head, unsafe_allow_html=True)
        return None
    left, right = st.columns([1 - controls, controls], vertical_alignment="center")
    left.markdown(head, unsafe_allow_html=True)
    return right.container(horizontal=True, horizontal_alignment="right", vertical_alignment="center", gap="small")


# What a hosted demo (backend/hosted_demo.py) cannot do, said where it matters.
HOSTED_INPUTS_NOTE = ("Hosted demo: these inputs listen inside this app's container, so no device on the internet "
                      "can reach them. To receive logs from devices, run TRACELOG on your own network "
                      "(python run_app.py, or Docker).")
HOSTED_WITNESSES_NOTE = ("Hosted demo: both witnesses run inside this app's container. That shows how witnessing "
                         "works; witnesses protect an archive only on machines its administrators do not control.")


def status_block(online: bool, direct: bool, host: str, port: int, hosted: Optional[dict] = None) -> str:
    if online and hosted is not None:
        loading = hosted.get("data") == "loading"
        state, dot = "API connected", "good"
        sub = "hosted demo, loading the demo data" if loading else "hosted demo, inside this app"
    elif hosted is not None:   # HOSTED_DEMO is on, but its API is not answering: say why
        reason = hosted.get("error") or "still starting, or stopped"
        state, dot, sub = "Hosted demo: API not running", "critical", esc(reason[:160])
    elif online:
        state, dot, sub = "API connected", "good", f"{esc(host)}:{port}"
    elif direct:
        state, dot, sub = "Running without the API", "warning", "this window reads the database directly"
    else:
        state, dot, sub = "API not answering", "critical", f"{esc(host)}:{port}"
    return (f'<div class="tl-status"><div class="tl-status__row"><span class="tl-dot tl-dot--{dot}"></span>{state}</div>'
            f'<div class="tl-status__sub">{sub}</div></div>')


def tile(title: str, body: str, aside: str = "", span: int = 4, extra_class: str = "") -> str:
    """A glass card for the dashboard grid. `body` and `aside` are trusted HTML."""
    return (f'<article class="tl-tile tl-span-{span} {extra_class}"><header class="tl-tile__head">'
            f'<span class="tl-tile__title">{esc(title)}</span><span class="tl-tile__aside">{aside}</span></header>'
            f'<div class="tl-tile__body">{body}</div></article>')


def kpi(label: str, value: str, foot: str = "", extra: str = "", dot: Optional[str] = None) -> str:
    """A number with its label; `value`, `foot` and `extra` are trusted HTML."""
    dot_html = f'<span class="tl-dot tl-dot--{dot}"></span>' if dot else ""
    return (f'<article class="tl-kpi"><div class="tl-kpi__label">{esc(label)}</div>'
            f'<div class="tl-kpi__value">{dot_html}{value}</div>{extra}'
            f'<div class="tl-kpi__foot">{foot}</div></article>')


def link(label: str, page: str) -> str:
    """A link to another page of the dashboard, followed without reloading the app."""
    return f'<a class="tl-link" href="{esc(page)}" target="_self">{esc(label)}</a>'


def meter(share: float) -> str:
    share = max(0.0, min(100.0, float(share or 0)))
    return f'<div class="tl-meter" role="presentation"><span style="width:{share:.1f}%"></span></div>'


def empty(title: str, text: str = "") -> str:
    return f'<div class="tl-empty"><b>{esc(title)}</b><span>{text}</span></div>'


# ------------------------------------------------------------------ charts
def _nice_max(v: float) -> float:
    if v <= 0:
        return 1.0
    exp = 10 ** math.floor(math.log10(v))
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * exp:
            return m * exp
    return 10 * exp


def sparkline(values: Sequence[float]) -> str:
    vals = list(values)
    if len(vals) < 2:
        return ""
    top = max(vals) or 1
    pts = [(i / (len(vals) - 1) * 100, 20 - v / top * 18) for i, v in enumerate(vals)]
    line = "M" + " L".join(f"{x:.2f},{y:.2f}" for x, y in pts)
    area = line + " L100,20 L0,20 Z"
    return (f'<svg class="tl-spark" viewBox="0 0 100 20" preserveAspectRatio="none" aria-hidden="true">'
            f'<path class="a" d="{area}"/><path class="l" d="{line}"/></svg>')


def timeseries(points: Sequence[dict], step_ms: int, marks: Optional[dict] = None,
               series: Sequence[tuple] = (("events", "Events", 1), ("denied", "Denied", 2)),
               label: str = "Events over time") -> str:
    """An area for the first series, lines for the others, and a lane of detection markers beneath.

    points: [{"t": slot start ms, key: count, ...}]; marks: {slot index: {"count", "worst", "titles"}}.
    Each time slot is a hover target showing every series and the detections in it.
    """
    n = len(points)
    if n == 0:
        return empty("No events in this range")
    marks = marks or {}
    top = _nice_max(max((p.get(k, 0) for p in points for k, _, _ in series), default=0))
    ticks = [top * f for f in (0, .25, .5, .75, 1)]

    def xy(i, v):
        return (i + .5) / n * 1000, 1000 - (v / top) * 1000

    svg = ['<svg viewBox="0 0 1000 1000" preserveAspectRatio="none" aria-hidden="true">']
    for t in ticks[1:]:
        y = 1000 - t / top * 1000
        svg.append(f'<line class="grid" x1="0" x2="1000" y1="{y:.1f}" y2="{y:.1f}"/>')
    for idx, (key, _, color) in enumerate(series):
        pts = [xy(i, p.get(key, 0)) for i, p in enumerate(points)]
        d = "M" + " L".join(f"{x:.1f},{y:.1f}" for x, y in pts)
        if idx == 0:
            svg.append(f'<path class="area-{color}" d="{d} L{pts[-1][0]:.1f},1000 L{pts[0][0]:.1f},1000 Z"/>')
            svg.append(f'<path class="line-1" style="stroke:var(--tl-s{color})" d="{d}"/>')
        else:
            svg.append(f'<path class="line-2" style="stroke:var(--tl-s{color})" d="{d}"/>')
    svg.append("</svg>")

    hits = ['<div class="tl-hits">']
    for i, p in enumerate(points):
        rows = "".join(f'<div><i style="background:var(--tl-s{c})"></i>{esc(name)} <b>{num(p.get(k, 0))}</b></div>'
                       for k, name, c in series)
        m = marks.get(i)
        if m:
            rows += (f'<div><i class="sv-{m["worst"]}" style="height:7px;width:7px;transform:rotate(45deg)"></i>'
                     f'Detections <b>{num(m["count"])}</b></div>')
            rows += "".join(f'<div class="f">{esc(t)}</div>' for t in m["titles"][:3])
        span = f'{utc(p["t"], "%d %b %H:%M")} to {utc(p["t"] + step_ms, "%H:%M")} UTC'
        side = " tl-hit--r" if i >= n / 2 else ""
        hits.append(f'<div class="tl-hit{side}"><div class="tl-tip"><div class="t">{span}</div>{rows}</div></div>')
    hits.append("</div>")

    ylab = "".join(f'<span style="top:{100 - t / top * 100:.2f}%">{compact(t)}</span>' for t in ticks)
    lane = "".join(f'<span class="tl-mark tl-mark--{m["worst"]}" style="left:{(i + .5) / n * 100:.2f}%"></span>'
                   for i, m in marks.items() if 0 <= i < n)
    every = max(1, math.ceil(n / 6))
    fmt = "%d %b" if step_ms >= 6 * 3_600_000 else "%H:%M"
    xlab = "".join(f'<span style="left:{i / n * 100:.2f}%">{utc(points[i]["t"], fmt)}</span>'
                   for i in range(0, n, every))
    return (f'<div class="tl-ts" role="img" aria-label="{esc(label)}">'
            f'<div class="tl-ts__y">{ylab}</div>'
            f'<div class="tl-ts__plot">{"".join(svg)}{"".join(hits)}</div>'
            f'<div class="tl-ts__lane">{lane}</div>'
            f'<div class="tl-ts__x">{xlab}</div></div>')


def timeseries_table(points: Sequence[dict], step_ms: int, series: Sequence[tuple] = (("events", "Events", 1),
                                                                                    ("denied", "Denied", 2))) -> str:
    """The time series as a table behind a "Table" toggle, for reading the numbers without hovering."""
    head = "<th>Time (UTC)</th>" + "".join(f'<th style="text-align:right">{esc(name)}</th>' for _, name, _ in series)
    body = "".join(f'<tr><td class="t">{utc(p["t"], "%d %b %H:%M")}</td>'
                   + "".join(f'<td class="n">{num(p.get(k, 0))}</td>' for k, _, _ in series) + "</tr>"
                   for p in points if any(p.get(k) for k, _, _ in series))
    return (f'<details class="tl-twin"><summary>Table</summary><div class="tl-twin__panel">'
            f'<table class="tl-table"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div></details>')


def legend(items: Iterable[tuple]) -> str:
    """items: (label, css class for the colour, shape) with shape "line", "box" or "dia"."""
    out = "".join(f'<span><i class="{shape} {cls}"></i>{esc(text)}</span>' for text, cls, shape in items)
    return f'<div class="tl-legend">{out}</div>'


def bar_list(rows: Sequence[tuple], color: int = 1, mono: bool = False, limit: int = 8) -> str:
    """Horizontal bars as a list: value, then the label over a bar as long as the value (longest = full)."""
    rows = [r for r in rows if r[1]][:limit]
    if not rows:
        return empty("Nothing in this range")
    top = max(v for _, v in rows) or 1
    items = []
    for name, v in rows:
        label = f'<span class="tl-mono">{esc(name)}</span>' if mono else esc(name)
        items.append(f'<li class="c{color}" title="{esc(name)}: {num(v)}"><span class="v">{compact(v)}</span>'
                     f'<span class="b" style="--w:{max(v / top * 100, 1.5):.1f}%"><span>{label}</span></span></li>')
    return f'<ul class="tl-bars">{"".join(items)}</ul>'


def parts(rows: Sequence[tuple], limit: int = 5, inline: bool = False) -> str:
    """Part-to-whole: one stacked bar and its legend with counts and shares. Past `limit`, the rest is Other."""
    rows = [r for r in rows if r[1]]
    if not rows:
        return empty("Nothing in this range")
    if len(rows) > limit:
        rows = rows[:limit - 1] + [("Other", sum(v for _, v in rows[limit - 1:]))]
    total = sum(v for _, v in rows) or 1
    colors = [0 if name == "Other" else i + 1 for i, (name, _) in enumerate(rows)]
    bar = "".join(f'<span class="c{c}" style="flex:{v}" title="{esc(name)}: {num(v)}"></span>'
                  for (name, v), c in zip(rows, colors))
    legend_rows = "".join(f'<li><i class="c{c}"></i><span>{esc(name)}</span><b>{num(v)}</b><em>{pct(v / total * 100)}</em></li>'
                          for (name, v), c in zip(rows, colors))
    return (f'<div class="tl-stack" aria-hidden="true">{bar}</div>'
            f'<ul class="tl-parts{" tl-parts--inline" if inline else ""}">{legend_rows}</ul>')


def severity_bar(rows: Sequence[dict]) -> str:
    """The share of each severity, in status colours, highest first."""
    counts = {}
    for r in rows:
        key = "info" if int(r.get("id") or 0) <= 1 else severity_class(r.get("id"))
        counts[key] = counts.get(key, 0) + int(r.get("events") or 0)
    order = [k for k in ("critical", "high", "medium", "low", "info") if counts.get(k)]
    if not order:
        return ""
    return '<div class="tl-sev" aria-hidden="true">' + "".join(
        f'<span class="sv-{k}" style="flex:{counts[k]}" title="{k}: {num(counts[k])}"></span>' for k in order) + "</div>"


def table(headers: Sequence[tuple], rows: Sequence[Sequence[str]]) -> str:
    """headers: (label, css width or ""); rows: cells of trusted HTML (escape values with esc())."""
    cols = "".join(f'<col style="width:{w}">' if w else "<col>" for _, w in headers)
    head = "".join(f"<th>{esc(h)}</th>" for h, _ in headers)
    body = "".join("<tr>" + "".join(r) + "</tr>" for r in rows)
    return (f'<div class="tl-table-wrap"><table class="tl-table"><colgroup>{cols}</colgroup>'
            f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>")


def sev_tag(severity_id, name: str = "") -> str:
    cls = severity_class(severity_id)
    return f'<span class="tl-sevtag"><i class="sv-{cls}"></i>{esc(name or SEVERITY_LABEL[cls])}</span>'


def lanes(rows: Sequence[tuple], start_ms: int, end_ms: int) -> str:
    """A timeline with one lane per device: each event a diamond at its time, coloured by severity.

    rows: (lane label, [{"t": epoch ms, "severity_id", "title", "detail"}]). Hovering an event shows its read-out.
    """
    span = max(end_ms - start_ms, 1)
    lanes_html = []
    for label, items in rows:
        marks = []
        for it in items:
            x = (it["t"] - start_ms) / span * 100
            side = " tl-ev--r" if x > 55 else ""
            marks.append(
                f'<div class="tl-ev{side}" style="left:{x:.2f}%"><i class="tl-mark tl-mark--{severity_class(it.get("severity_id"))}"></i>'
                f'<div class="tl-tip"><div class="t">{utc(it["t"], "%H:%M:%S")} UTC · {esc(it.get("title"))}</div>'
                f'<div class="f">{esc(it.get("detail"))}</div></div></div>')
        lanes_html.append(f'<div class="tl-lane"><div class="tl-lane__label" title="{esc(label)}">{esc(label)}</div>'
                          f'<div class="tl-lane__track">{"".join(marks)}</div></div>')
    ticks = "".join(f'<span style="left:{p}%">{utc(start_ms + span * p / 100, "%H:%M:%S")}</span>'
                    for p in (0, 25, 50, 75, 100))
    return (f'<div class="tl-lanes" role="img" aria-label="Events by device over time">{"".join(lanes_html)}'
            f'<div class="tl-lane tl-lane--axis"><div></div><div class="tl-lane__axis">{ticks}</div></div></div>')
