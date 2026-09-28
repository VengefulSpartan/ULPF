"""
The particulars a certificate under Section 63(4) of the Bharatiya Sakshya Adhiniyam, 2023 asks for,
filled in from an evidence bundle, with the hash report as an annexure.

The Adhiniyam's Schedule sets out the certificate itself: Part A, by the party producing the
electronic record, and Part B, by an expert, each naming the device or source, the hash values
and the algorithm, and each signed with the date, time (IST) and place. This page does not
reproduce that form. It gives the signatories what TRACELOG knows (the record, the system it
came from, every hash, how to check them) and leaves blank what only they can state and sign.
"""
import io
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from backend.services.evidence.bundle import ist
from backend.services.integrity.audit_pdf import BODY, CELL, H1, H2, HEAD_BG, LINE, MUTED, SMALL, _esc

WARN_BG, WARN_FG = colors.HexColor("#FEF3C7"), colors.HexColor("#92400E")
BLANK = "_" * 38
ALG_NAMES = {"ed25519": "Ed25519", "ml-dsa-65": "ML-DSA-65"}
MONO = ParagraphStyle("mono", parent=CELL, fontName="Courier", fontSize=6.6, leading=8.2)
LABEL = ParagraphStyle("label", parent=CELL, textColor=MUTED)


def _rows(rows: List[List[str]], width: float, label_share: float = 0.3) -> Table:
    data = [[Paragraph(_esc(a), LABEL), Paragraph(b, CELL)] for a, b in rows]
    t = Table(data, colWidths=[width * label_share, width * (1 - label_share)])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                           ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5)]))
    return t


def _or_blank(v: str) -> str:
    return _esc(v) if v else BLANK


def render_certificate(manifest: Dict[str, Any], manifest_sha: str) -> bytes:
    b, recs, case = manifest["bundle"], manifest["records"], manifest["bundle"].get("case") or {}
    checks, cps = manifest["checks_at_export"], manifest.get("checkpoints") or {}
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=14 * mm, rightMargin=14 * mm, topMargin=12 * mm,
                            bottomMargin=15 * mm, title=f"Section 63(4) particulars, evidence bundle {b['id']}",
                            author="TRACELOG", subject="Certificate particulars and hash report")
    W = doc.width

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(d.leftMargin, 9 * mm, f"TRACELOG evidence bundle {b['id']} - manifest.json SHA-256 "
                                                f"{manifest_sha}")
        canvas.drawRightString(d.pagesize[0] - d.rightMargin, 9 * mm, f"Page {d.page}")
        canvas.restoreState()

    times = sorted(r["event_time"] for r in recs if r.get("event_time"))
    sources = sorted({r["source"] or "unknown device" for r in recs})
    transports = sorted({r["transport"] or "unknown" for r in recs})
    by_signer: Dict[str, set] = {}
    for c in cps.values():
        for s in c["signatures"]:
            name = "this node" if s.get("role") == "node" else s.get("name") or "a witness"
            by_signer.setdefault(name, set()).add(ALG_NAMES.get(s.get("alg"), s.get("alg")))
    signers = [f"{name} ({', '.join(sorted(algs))})" for name, algs in by_signer.items()]
    node_key = next((s.get("key_id") for c in cps.values() for s in c["signatures"]
                     if s.get("role") == "node" and s.get("alg") == "ed25519"), None)

    notice = Table([[Paragraph(
        "<b>Draft for signature.</b> TRACELOG filled in what it knows about the electronic record and the system that "
        "produced it. These particulars become a certificate under Section 63(4) only when the person in charge of "
        "the system (Part A) and an expert (Part B) have checked them, set them out in the form given in the Schedule "
        "to the Adhiniyam, and signed. Whether the record is admitted is for the court.",
        ParagraphStyle("n", parent=BODY, textColor=WARN_FG))]], colWidths=[W])
    notice.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), WARN_BG), ("BOX", (0, 0), (-1, -1), 0.6, WARN_FG),
                                ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                                ("LEFTPADDING", (0, 0), (-1, -1), 8)]))

    story: List[Any] = [
        Paragraph("Certificate particulars and hash report", H1),
        Paragraph(f"Section 63(4), Bharatiya Sakshya Adhiniyam, 2023 &middot; evidence bundle {_esc(b['id'])} &middot; "
                  f"prepared {_esc(b['created_at_ist'])} by {_esc(b['created_by'])}"
                  + (f" &middot; case {_esc(case.get('case_ref'))}" if case.get("case_ref") else ""), SMALL),
        Spacer(1, 5), notice,
        Paragraph("1. The electronic record", H2),
        _rows([
            ["Evidence bundle", f"{_esc(b['id'])}: {len(recs)} log record(s), chain sequence #{recs[0]['sequence_num']} "
                                f"to #{recs[-1]['sequence_num']}"],
            ["Events between", f"{_esc(ist(times[0]) if times else '-')} and {_esc(ist(times[-1]) if times else '-')}"],
            ["Sent by", _esc(", ".join(sources))],
            ["Received over", _esc(", ".join(transports)) + ", and stored by TRACELOG byte for byte on arrival"],
            ["Hash algorithm", "SHA-256"],
            ["Hash of the whole record", f"<font face='Courier'>{manifest_sha}</font> (SHA-256 of manifest.json, which "
                                         f"lists the SHA-256 of every log line and event: see the Annexure)"],
            ["Checked when exported", f"{checks['raw_hash_matches']} of {checks['records']} log lines matched the SHA-256 "
                                      f"taken on arrival; {checks['record_hash_matches']} of {checks['records']} chain "
                                      f"records matched; {checks['in_signed_checkpoint']} were in a signed checkpoint"
                                      + (f" signed by {_esc(' and '.join(signers))}" if signers else "")],
        ], W, 0.22),
        Paragraph("2. Part A: to be completed by the party producing the record", H2),
        _rows([
            ["Name", _or_blank(case.get("prepared_by"))],
            ["Son / daughter / spouse of", BLANK],
            ["Residing at / employed at", _or_blank(case.get("organisation"))],
            ["Designation", _or_blank(case.get("designation"))],
            ["Device or source of the record", f"Server: the TRACELOG log archive on host {_esc(b['host'])}, which "
                                               f"received the lines from the devices named in section 1"],
            ["Make, model and identifiers", f"{_esc(b['created_by'])}; archive log id {_esc(b['log_id'])}"
                                            + (f"; node signing key {_esc(node_key)}" if node_key else "")],
            ["Lawful control, regular use and proper working", "To be stated by the signatory in the words of the "
                                                               "Schedule."],
            ["Owned / maintained / managed / operated by the signatory", "[ ] owned &nbsp; [ ] maintained &nbsp; "
                                                                          "[ ] managed &nbsp; [ ] operated"],
            ["Hash value(s) and algorithm", f"SHA-256. Every record's hash is in the Annexure; manifest.json: "
                                            f"<font face='Courier'>{manifest_sha}</font>"],
            ["Name and signature", BLANK],
            ["Date (DD/MM/YYYY), time (IST, 24-hour), place", f"{BLANK} &nbsp; {_or_blank(case.get('place'))}"],
        ], W, 0.3),
    ]
    story += [KeepTogether([
        Paragraph("3. Part B: to be completed by the expert", H2),
        _rows([
            ["Name and designation", BLANK],
            ["Record examined", f"Evidence bundle {_esc(b['id'])}, from the source named in Part A"],
            ["How the hash values were checked", "In the bundle folder: <font face='Courier'>python verify.py</font> "
                                                 "(checks every file, log line, chain record, Merkle proof and "
                                                 "signature); result: " + BLANK],
            ["Hash value(s) and algorithm", f"SHA-256, as in the Annexure; manifest.json: "
                                            f"<font face='Courier'>{manifest_sha}</font>"],
            ["Name, designation and signature", BLANK],
            ["Date (DD/MM/YYYY), time (IST, 24-hour), place", BLANK],
        ], W, 0.3)])]

    story += [PageBreak(), Paragraph("Annexure: hash report", H2),
              Paragraph("One row per log record. The raw line hash is SHA-256 of the bytes the device sent, taken when "
                        "TRACELOG received them. The chain record hash is SHA-256(previous record hash : sequence number "
                        ": raw line hash : stored event) and links each record to the one before it.", SMALL),
              Spacer(1, 4)]
    head = ["#", "Received (IST)", "Sent by", "Event", "Raw line SHA-256", "Chain record SHA-256"]
    data = [[Paragraph(h, CELL) for h in head]]
    for r in recs:
        what = r.get("finding") or f"{r.get('class_name') or ''} {r.get('src_ip') or ''} -> {r.get('dst_ip') or ''}"
        data.append([Paragraph(str(r["sequence_num"]), CELL), Paragraph(_esc(ist(r.get("received_at"))), CELL),
                     Paragraph(_esc(r.get("source") or "-"), CELL), Paragraph(_esc(what.strip()[:80]), CELL),
                     Paragraph(r["raw_sha256"], MONO), Paragraph(r["record_hash"], MONO)])
    t = Table(data, colWidths=[W * w for w in (0.05, 0.12, 0.15, 0.18, 0.25, 0.25)], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), HEAD_BG), ("GRID", (0, 0), (-1, -1), 0.4, LINE),
                           ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5), ("LEFTPADDING", (0, 0), (-1, -1), 3),
                           ("RIGHTPADDING", (0, 0), (-1, -1), 3)]))
    story += [t, Spacer(1, 6),
              Paragraph(_esc(manifest.get("how_to_check", "")), SMALL)]
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
