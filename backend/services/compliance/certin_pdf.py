"""The CERT-In incident report draft (certin.draft_report) as a PDF, for review before it is sent."""
import io
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from backend.services.integrity.audit_pdf import BODY, CELL, H1, H2, HEAD_BG, LINE, MUTED, SMALL, _esc

WARN_BG, WARN_FG = colors.HexColor("#FEF3C7"), colors.HexColor("#92400E")
BAD_BG, BAD_FG = colors.HexColor("#FEE2E2"), colors.HexColor("#991B1B")
OK_BG, OK_FG = colors.HexColor("#DCFCE7"), colors.HexColor("#166534")
LABEL = ParagraphStyle("label", parent=CELL, textColor=MUTED)
MONO = ParagraphStyle("mono", parent=CELL, fontName="Courier", fontSize=6.4, leading=8)
BLANK = "_" * 30


def _kv(rows: List[List[str]], width: float, share: float = 0.3) -> Table:
    t = Table([[Paragraph(_esc(a), LABEL), Paragraph(b, CELL)] for a, b in rows],
              colWidths=[width * share, width * (1 - share)])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("TOPPADDING", (0, 0), (-1, -1), 3.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
                           ("LEFTPADDING", (0, 0), (-1, -1), 5)]))
    return t


def _box(text: str, width: float, bg, fg) -> Table:
    t = Table([[Paragraph(text, ParagraphStyle("b", parent=BODY, textColor=fg))]], colWidths=[width])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), bg), ("BOX", (0, 0), (-1, -1), 0.6, fg),
                           ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                           ("LEFTPADDING", (0, 0), (-1, -1), 8)]))
    return t


def _v(value: str) -> str:
    return _esc(value) if value else BLANK


def render_report(r: Dict[str, Any]) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=13 * mm,
                            bottomMargin=15 * mm, title=f"CERT-In incident report draft {r['report_id']}",
                            author="TRACELOG", subject="Cyber security incident report (draft)")
    W = doc.width
    inc, ent, ev, ret = r["incident"], r["reporting_entity"], r["evidence"], r["retention"]

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(d.leftMargin, 9 * mm, f"TRACELOG {r['report_id']} - draft, not a submission")
        canvas.drawRightString(d.pagesize[0] - d.rightMargin, 9 * mm, f"Page {d.page}")
        canvas.restoreState()

    clock = (f"<b>Report by {_esc(inc['report_by_ist'])}</b> (6 hours after it was noticed, "
             f"{_esc(inc['noticed_at_ist'])}: {_esc(inc['noticed_basis'])}). "
             + (f"<b>Overdue by {abs(inc['hours_left']):g} h.</b>" if inc["overdue"] else f"{inc['hours_left']:g} h left."))
    story: List[Any] = [
        Paragraph("Cyber security incident: report draft for CERT-In", H1),
        Paragraph(f"{_esc(r['report_id'])} &middot; prepared {_esc(r['generated_at_ist'])} by TRACELOG &middot; "
                  f"send to {_esc(r['report_to'])} with the CERT-In incident reporting form ({_esc(r['form'])})", SMALL),
        Spacer(1, 5),
        _box(_esc(r["status"]), W, WARN_BG, WARN_FG), Spacer(1, 4),
        _box(clock, W, BAD_BG if inc["overdue"] or inc["hours_left"] < 1 else OK_BG,
             BAD_FG if inc["overdue"] or inc["hours_left"] < 1 else OK_FG),
        Paragraph("1. Reporting entity and point of contact", H2),
        _kv([["Organisation", _v(ent.get("organisation"))], ["Sector", _v(ent.get("sector"))],
             ["Address", _v(ent.get("address"))],
             ["Contact person and designation", _v(" / ".join(x for x in (ent.get("contact_name"), ent.get("designation")) if x))],
             ["Phone and email", _v(" / ".join(x for x in (ent.get("phone"), ent.get("email")) if x))]], W),
        Paragraph("2. The incident", H2),
        _kv([["Summary", _esc(inc.get("title"))], ["Highest severity reported", _esc(inc.get("severity"))],
             ["Type (Annexure I of the directions)",
              "<br/>".join(f"({_esc(t['code'])}) {_esc(t['type'])}" for t in inc["types"]) or
              "None suggested by the evidence: choose from Annexure I"],
             ["First event", _esc(inc.get("first_event_ist") or "-")],
             ["Last event", _esc(inc.get("last_event_ist") or "-")],
             ["Noticed", f"{_esc(inc['noticed_at_ist'])} ({_esc(inc['noticed_basis'])})"],
             ["Report by", _esc(inc["report_by_ist"])]], W),
    ]
    if inc.get("suggested_types"):
        story.append(Paragraph("Why these types: " + "; ".join(
            f"({_esc(s['code'])}) {_esc(s['because'])}" for s in inc["suggested_types"]) + ". A person confirms the type.",
            SMALL))
    aff, ind, act = r["affected"], r["indicators"], r["actions_observed"]
    story += [
        Paragraph("3. Affected systems and indicators", H2),
        _kv([["Internal addresses involved", _esc(", ".join(aff["internal_addresses"]) or "-")],
             ["Users involved", _esc(", ".join(aff["users"]) or "-")],
             ["Devices that reported it", _esc(", ".join(aff["devices_reporting"]) or "-")],
             ["External addresses (indicators)", _esc(", ".join(ind["external_addresses"]) or "-")],
             ["Detection signatures", _esc("; ".join(ind["signatures"]) or "-")],
             ["What the devices did", f"{act['blocked']} blocked or failed, {act['allowed']} allowed, "
                                      f"{act['other']} other"]], W),
        Paragraph(f"4. Timeline ({min(len(r['timeline']), r['timeline_total'])} of {r['timeline_total']} events)", H2),
    ]
    rows = [[Paragraph(h, CELL) for h in ("#", "Time (IST)", "Device", "What was logged", "Raw line SHA-256")]]
    for t in r["timeline"]:
        rows.append([Paragraph(str(t["sequence_num"]), CELL), Paragraph(_esc(t["time_ist"]), CELL),
                     Paragraph(_esc(t["device"]), CELL), Paragraph(_esc((t["what"] or "")[:220]), CELL),
                     Paragraph(_esc(t["raw_sha256"] or ""), MONO)])
    tl = Table(rows, colWidths=[W * w for w in (0.06, 0.15, 0.15, 0.39, 0.25)], repeatRows=1)
    tl.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), HEAD_BG), ("GRID", (0, 0), (-1, -1), 0.4, LINE),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5), ("LEFTPADDING", (0, 0), (-1, -1), 3)]))
    story.append(tl)
    if r["rule_matches"]:
        story.append(Paragraph("5. What the correlation rules link", H2))
        for m in r["rule_matches"]:
            story.append(Paragraph(f"<b>{_esc(m['rule'])}</b>: {_esc(m['what'])} <i>Limits: {_esc(m['limits'])}</i>",
                                   BODY))
    story += [
        Paragraph("6. Actions taken and next steps", H2),
        Paragraph("Actions taken so far (containment, blocking, accounts disabled): " + BLANK * 2, BODY),
        Spacer(1, 3),
    ] + [Paragraph(f"&bull; {_esc(s)}", BODY) for s in r["next_steps"]] + [
        Paragraph("7. Evidence kept", H2),
        _kv([["Records", f"{ev['records']} (chain #{ev['first_seq']} to #{ev['last_seq']}); "
                         f"{ev['records_matching_their_hashes']} match their raw line and chain hashes now"],
             ["Signed checkpoints", f"{ev['in_signed_checkpoints']} of {ev['records']} records sealed"
                                    + (f", witnessed by {_esc(', '.join(ev['witnesses']))}" if ev["witnesses"] else "")],
             ["Evidence bundle", f"Correlation page, or GET {_esc(ev['bundle'])}"],
             ["Log retention", _esc(ret["summary"]) + (f"; kept in {_esc(ret['data_location'])} (as declared)"
                                                       if ret.get("data_location") else "")],
             ["Clocks", _esc(r["clock"])]], W),
    ]
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
