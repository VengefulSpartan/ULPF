"""Render the audit report (see reconcile.audit_report) as a PDF with ReportLab."""
import io
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

INK = colors.HexColor("#0F172A")
MUTED = colors.HexColor("#475569")
LINE = colors.HexColor("#CBD5E1")
HEAD_BG = colors.HexColor("#E2E8F0")
OK_BG, OK_FG = colors.HexColor("#DCFCE7"), colors.HexColor("#166534")
BAD_BG, BAD_FG = colors.HexColor("#FEE2E2"), colors.HexColor("#991B1B")

_ss = getSampleStyleSheet()
H1 = ParagraphStyle("h1", parent=_ss["Title"], fontName="Helvetica-Bold", fontSize=18, leading=22,
                    alignment=TA_LEFT, textColor=INK, spaceAfter=2)
H2 = ParagraphStyle("h2", parent=_ss["Heading2"], fontName="Helvetica-Bold", fontSize=12, leading=15,
                    textColor=INK, spaceBefore=10, spaceAfter=4)
BODY = ParagraphStyle("body", parent=_ss["BodyText"], fontName="Helvetica", fontSize=8.8, leading=11.5,
                      textColor=INK)
SMALL = ParagraphStyle("small", parent=BODY, fontSize=7.6, leading=9.6, textColor=MUTED)
CELL = ParagraphStyle("cell", parent=BODY, fontSize=7.8, leading=9.6)
CELL_R = ParagraphStyle("cell_r", parent=CELL, alignment=TA_RIGHT)


def _esc(v: Any) -> str:
    s = "" if v is None else str(v)
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # built-in PDF fonts lack some symbols; keep the text readable
    return s.replace("→", "->").replace("✓", "OK").replace("✗", "X")


def _n(v: Any) -> str:
    return f"{v:,}" if isinstance(v, int) else _esc(v)


def _table(rows: List[List[Any]], widths: List[float], numeric=()) -> Table:
    numeric = set(numeric)
    data = [[Paragraph(_esc(c) if i == 0 else (_n(c) if isinstance(c, int) else _esc(c)),
                       CELL_R if (i > 0 and j in numeric) else CELL)
             for j, c in enumerate(r)] for i, r in enumerate(rows)]
    t = Table(data, colWidths=widths, repeatRows=1)
    style = [("BACKGROUND", (0, 0), (-1, 0), HEAD_BG), ("GRID", (0, 0), (-1, -1), 0.4, LINE),
             ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 3),
             ("BOTTOMPADDING", (0, 0), (-1, -1), 3), ("LEFTPADDING", (0, 0), (-1, -1), 4),
             ("RIGHTPADDING", (0, 0), (-1, -1), 4)]
    t.setStyle(TableStyle(style))
    return t


def _footer(report_id: str):
    def draw(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(doc.leftMargin, 10 * mm, f"TRACELOG log delivery audit report {report_id}")
        canvas.drawRightString(doc.pagesize[0] - doc.rightMargin, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()
    return draw


def render_pdf(r: Dict[str, Any]) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=14 * mm, rightMargin=14 * mm,
                            topMargin=13 * mm, bottomMargin=16 * mm, title=f"TRACELOG audit report {r['report_id']}",
                            author="TRACELOG", subject="Log delivery reconciliation")
    W = doc.width
    p = r["pipeline"]
    story: List[Any] = [
        Paragraph("Log delivery audit report", H1),
        Paragraph(f"TRACELOG &middot; report {_esc(r['report_id'])} &middot; generated {_esc(r['generated_at'][:19])} UTC"
                  f" on {_esc(r['host'])} &middot; events from {_esc((p['period']['first_event'] or '-')[:19])} to "
                  f"{_esc((p['period']['last_event'] or '-')[:19])} UTC", SMALL),
        Spacer(1, 6),
    ]
    ok = r["all_accounted"]
    verdict = Table([[Paragraph(f"<b>{'ACCOUNTED FOR' if ok else 'ATTENTION NEEDED'}</b> &nbsp; {_esc(r['verdict'])}",
                                ParagraphStyle("v", parent=BODY, fontSize=10, leading=13,
                                               textColor=OK_FG if ok else BAD_FG))]], colWidths=[W])
    verdict.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), OK_BG if ok else BAD_BG),
                                 ("BOX", (0, 0), (-1, -1), 0.6, OK_FG if ok else BAD_FG),
                                 ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                                 ("LEFTPADDING", (0, 0), (-1, -1), 8)]))
    story += [verdict]

    # 1. chain of custody
    integ, deliv = r.get("integrity") or {}, r.get("delivery_ledger") or {}
    story += [Paragraph("1. Chain of custody inside TRACELOG", H2), _table([
        ["Check", "Result", "Detail"],
        ["Raw log lines archived byte-for-byte", p["raw_archived"],
         f"{p['streamed']:,} streamed from devices and forwarders, {p['uploaded_or_api']:,} uploaded or sent to the API"],
        ["Normalised OCSF 1.1.0 events", p["normalized"],
         "one per archived line; unparsable lines kept as Base Events"
         + (f"; plus {p.get('revisions', 0):,} revisions of earlier events re-parsed with an approved parser (the "
            f"originals stay in the chain)" if p.get("revisions") else "")],
        ["Hash-chain records", p["hash_chained"],
         ("one per event: archive, events, revisions and chain add up" if p.get("revisions") else
          "archive, events and chain are the same size") if p["consistent"] else "COUNTS DO NOT ADD UP"],
        ["Integrity chain verification", "valid" if integ.get("is_valid") else "FAILED",
         f"{integ.get('verified_records', 0):,} of {integ.get('total_records', 0):,} records verified"
         + (f"; first bad record {integ.get('first_corrupted_seq')}" if integ.get("first_corrupted_seq") else "")],
        ["Delivery ledger verification", "valid" if deliv.get("is_valid") else "FAILED",
         f"{deliv.get('batches', 0):,} hash-chained delivery records"
         + (f"; {deliv.get('issue_count')} issues" if deliv.get("issue_count") else "")],
    ], [W * 0.30, W * 0.12, W * 0.58])]

    # 2. per-output reconciliation
    rows = [["Output", "Type", "Owed", "Delivered", "of which re-sent", "Via other output", "Filtered out",
             "Dead letters waiting", "In flight", "Unaccounted", "Status"]]
    for o in r["outputs"]:
        rows.append([o["output"], o["type"] or "", o["owed"], o["delivered"], o["resent"], o["rerouted"],
                     o["filtered"], o["dead_letter_waiting"], o["in_flight"], o["unaccounted"],
                     "balanced" if o["status"] == "balanced" else "UNACCOUNTED"])
    widths = [0.13, 0.10, 0.07, 0.08, 0.08, 0.08, 0.08, 0.09, 0.07, 0.09, 0.13]
    story += [Paragraph("2. Delivery reconciliation per output", H2),
              _table(rows, [W * w for w in widths], numeric=range(2, 10)),
              Paragraph("Owed = stored events since the output was first configured. Owed = delivered + via other "
                        "output + filtered out + dead letters waiting + in flight + unaccounted. Every outcome is a "
                        "record in the hash-chained delivery ledger.", SMALL)]
    notes = [f"<b>{_esc(o['output'])}</b>: {_esc('; '.join(o['notes']))}" for o in r["outputs"] if o["notes"]]
    rec_ = r.get("recovery") or {}
    if rec_.get("requeued") or rec_.get("filtered"):
        notes.append(f"<b>Restart recovery</b>: after the last restart ({_esc((rec_.get('started_at') or '')[:19])} UTC), "
                     f"{rec_.get('requeued', 0):,} events that outputs still owed were sent again from the archive "
                     f"and {rec_.get('filtered', 0):,} were recorded as filtered out ({_esc(rec_.get('state'))}).")
    for n_ in notes:
        story.append(Paragraph(n_, SMALL))

    # 3. dead letters
    dls = r.get("dead_letters") or []
    story.append(Paragraph("3. Dead letters waiting", H2))
    if dls:
        rows = [["Output", "Waiting", "Undeliverable", "Queue full", "Rejected", "Main reason", "Oldest"]]
        for d in dls:
            k = d.get("by_kind") or {}
            reason = (d.get("top_reasons") or [{}])[0].get("reason", "")
            rows.append([d["output"], d["waiting"], k.get("undeliverable", 0), k.get("queue_full", 0),
                         k.get("rejected", 0), reason[:120], (d.get("oldest") or "")[:19]])
        story.append(_table(rows, [W * w for w in (0.12, 0.07, 0.09, 0.08, 0.07, 0.43, 0.14)], numeric=(1, 2, 3, 4)))
    else:
        story.append(Paragraph("None. Every event an output could not deliver has since been delivered.", BODY))

    # 4. delivery exceptions
    ex = r.get("exceptions") or []
    story.append(Paragraph("4. Delivery exceptions: outages, rejections, re-sends and re-routes (newest first)", H2))
    if ex:
        rows = [["From (UTC)", "To (UTC)", "Output", "Outcome", "Trigger", "Batches", "Events", "Detail"]]
        for e in ex:
            rows.append([e["from"][:19].replace("T", " "), e["to"][11:19], e["output"],
                         e["outcome"].replace("_", " "), e["trigger"], e["batches"], e["count"],
                         (e.get("detail") or "")[:150]])
        story.append(_table(rows, [W * w for w in (0.13, 0.07, 0.10, 0.10, 0.08, 0.07, 0.07, 0.38)],
                            numeric=(5, 6)))
    else:
        story.append(Paragraph("None: every batch was delivered at the first attempt.", BODY))

    # 5. sources
    srcs = r.get("sources") or []
    if srcs:
        rows = [["Source device", "Vendor", "Product", "Category", "Events", "Last event (UTC)"]]
        for s in srcs[:40]:
            rows.append([s["name"], s["vendor"], s["product"], s["category"], s["event_count"],
                         (s.get("last_event_at") or "")[:19]])
        story += [Paragraph("5. Log sources", H2),
                  _table(rows, [W * w for w in (0.32, 0.15, 0.17, 0.1, 0.08, 0.18)], numeric=(4,))]

    # 6. fingerprint
    fp = r["fingerprint"]
    story.append(KeepTogether([
        Paragraph("6. Fingerprint", H2),
        _table([["Item", "Value"],
                ["Report SHA-256 (JSON version)", fp["report_sha256"]],
                ["Integrity chain head", fp["integrity_chain_head"] or "-"],
                ["Delivery ledger head", fp["delivery_ledger_head"] or "-"]], [W * 0.25, W * 0.75]),
        Paragraph(_esc(fp["how_to_check"]), SMALL)]))
    doc.build(story, onFirstPage=_footer(r["report_id"]), onLaterPages=_footer(r["report_id"]))
    return buf.getvalue()
