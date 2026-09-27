"""
Parser Studio > New log formats: formats no parser knows, grouped by structure, and the
review that turns one into an approved parser (learn -> review -> approve -> re-parse).
"""
from typing import Any, Dict

import pandas as pd
import streamlit as st

from frontend import ui
from frontend.api_client import APIClient

FIELDS = {"src_ip": "source IP", "src_port": "source port", "dst_ip": "destination IP", "dst_port": "destination port",
          "protocol": "protocol", "action": "action", "time": "time", "severity": "severity", "user": "user",
          "signature": "threat / signature"}
NONE = "(not a field)"
LABEL_TO_ROLE = {v: k for k, v in FIELDS.items()}
STATUS = {"new": "new", "learned": "parser in use", "ignored": "ignored"}


def _short(text: str, n: int = 90) -> str:
    return text if len(text) <= n else text[:n - 1] + "…"


def _kpis(cards) -> str:
    return f'<div class="tl-kpis" style="grid-template-columns:repeat({len(cards)}, minmax(0, 1fr))">{"".join(cards)}</div>'


def render_new_formats() -> None:
    all_formats = APIClient.list_formats()
    new = [f for f in all_formats if f["status"] == "new"]
    learned = [f for f in all_formats if f["status"] == "learned"]
    drifted = [f for f in all_formats if f.get("drift_from")]
    st.markdown(_kpis([
        ui.kpi("New formats", ui.num(len(new)), "<span>waiting for a parser</span>", dot="warning" if new else "good"),
        ui.kpi("Lines without a parser", ui.num(sum(f["count"] for f in new)), "<span>read by the generic parser</span>"),
        ui.kpi("Learned parsers in use", ui.num(len({f["parser_id"] for f in learned})),
               f"<span>{ui.num(len(learned))} formats covered</span>"),
        ui.kpi("Formats that changed", ui.num(len(drifted)), "<span>a known device's format changed</span>",
               dot="critical" if drifted else "good"),
    ]), unsafe_allow_html=True)
    st.caption("Lines no parser recognizes, grouped by structure: a new device or a firmware change is one format, "
               "not thousands of lines. Learn a parser from one, check it, approve it.")
    if not all_formats:
        st.info("Nothing to review. Every line so far matched a vendor parser.")
        return

    show = st.segmented_control("Show", ["New", "In use", "Ignored", "All"], default="New", key="fmt_filter",
                                required=True)
    want = {"New": "new", "In use": "learned", "Ignored": "ignored"}.get(show)
    rows = [f for f in all_formats if want is None or f["status"] == want]
    focus = st.session_state.pop("fmt_focus", None)   # the format just approved or ignored stays open
    if focus:
        rows += [f for f in all_formats if f["format_id"] == focus and f not in rows]
        st.session_state["fmt_pick"] = focus
    if not rows:
        st.caption("No formats in this view.")
        return
    table = pd.DataFrame([{
        "Status": STATUS.get(f["status"], f["status"]), "Lines": f["count"], "Structure": f["kind"],
        "Format": _short(f["template"], 110), "Devices": ", ".join(list(f["sources"])[:3]),
        "Last seen (UTC)": (f["last_seen"] or "")[:19].replace("T", " "),
        "Evidence score": f["avg_confidence"],
        "Changed from": f.get("drift_from") or "",
    } for f in rows])
    st.dataframe(table, width="stretch", hide_index=True)

    labels = {f["format_id"]: f"{f['count']:,} lines · {_short(f['template'], 80)}" for f in rows}
    fid = st.selectbox("Review a format", list(labels), format_func=labels.get, key="fmt_pick")
    if fid:
        _format_panel(fid)


def _format_panel(fid: str) -> None:
    fmt = APIClient.format_detail(fid)
    if fmt.get("error"):
        st.error(fmt["error"])
        return
    devices = ", ".join(f"{k} ({v})" for k, v in fmt["sources"].items()) or "-"
    st.markdown(
        f'<div class="tl-facts"><span>Format <b class="tl-mono">{ui.esc(fid)}</b></span>'
        f'<span>{ui.esc(fmt["kind"])}</span><span><b>{ui.num(fmt["count"])}</b> lines</span>'
        f'<span>{ui.num(fmt["samples"])} samples kept</span>'
        f'<span>first seen {ui.esc((fmt["first_seen"] or "")[:19].replace("T", " "))} UTC</span>'
        f'<span>from {ui.esc(devices)}</span></div>', unsafe_allow_html=True)
    st.code(fmt["template"], language="text")
    if fmt.get("drift_from"):
        st.warning(f"The **{fmt['drift_from']}** parser claimed these lines but produced impossible values (an address "
                   "that is not an IP, a port above 65535), so its output was not used. The device's format has "
                   "probably changed, for example after a firmware update.")
    with st.expander(f"Sample lines ({len(fmt.get('samples_shown') or [])} of {fmt['samples']})"):
        st.code("\n".join(s["raw_text"] for s in fmt.get("samples_shown") or []), language="text")
    now = (fmt.get("parsed_now") or [None])[0]
    if now:
        st.markdown('<div class="tl-subhead">How the generic parser reads the first sample</div>',
                    unsafe_allow_html=True)
        cols = st.columns(3)
        cols[0].markdown("**Filled**, with evidence")
        cols[0].json(now["filled"] or {}, expanded=True)
        cols[1].markdown("**Left empty**, evidence too weak")
        cols[1].json(now["not_filled"] or {}, expanded=True)
        cols[2].markdown("**Addresses with unknown direction**")
        cols[2].write(", ".join(now["unassigned_ips"]) or "none")
        st.caption(f"Parser: {now['parser']}")

    parser = fmt.get("parser")
    top = st.columns([1, 1, 1, 1], vertical_alignment="bottom")
    vendor = top[0].text_input("Vendor", value=(parser or {}).get("vendor") if parser and parser["vendor"] != "Unknown"
                               else "", key=f"v_{fid}", placeholder="WatchGuard")
    product = top[1].text_input("Product", value=(parser or {}).get("product") or "", key=f"p_{fid}",
                                placeholder="Firebox")
    if not parser or parser["status"] == "rejected":
        if top[2].button(f"Learn a parser from {fmt['samples']} lines", type="primary", key=f"learn_{fid}",
                         width="stretch", disabled=fmt["samples"] < 2):
            with st.spinner("Learning from the samples and testing on held-out lines…"):
                res = APIClient.learn_format(fid, vendor, product)
            if res.get("error"):
                st.error(res["error"])
            else:
                st.rerun()
    if fmt["status"] != "ignored":
        if top[3].button("Ignore this format", key=f"ign_{fid}", width="stretch"):
            APIClient.ignore_format(fid)
            st.session_state["fmt_focus"] = fid
            st.rerun()
    elif top[3].button("Stop ignoring", key=f"unign_{fid}", width="stretch"):
        APIClient.ignore_format(fid, undo=True)
        st.session_state["fmt_focus"] = fid
        st.rerun()
    if parser and parser["status"] != "rejected":
        _review(fid, parser, vendor, product)


def _review(fid: str, parser: Dict[str, Any], vendor: str, product: str) -> None:
    pid, spec, val = parser["id"], parser["spec"], parser.get("validation") or {}
    state = {"candidate": "not applied yet", "approved": "approved, in use"}.get(parser["status"], parser["status"])
    approved = (f' · approved by <b>{ui.esc(parser["approved_by"])}</b> on '
                f'{ui.esc(parser["approved_at"][:19].replace("T", " "))} UTC' if parser["status"] == "approved" else "")
    st.markdown(f'<div class="tl-subhead">Learned parser</div><div class="tl-facts"><span><b>{ui.esc(parser["name"])}</b>'
                f'</span><span>{state}</span><span>OCSF class {ui.esc(parser["class_uid"])} '
                f'{ui.esc(parser["class_name"])}</span><span>learned from {ui.esc(spec.get("samples_learned", "?"))} '
                f'lines{approved}</span></div>', unsafe_allow_html=True)

    total, ok = val.get("total_samples", 0), val.get("passed_samples", 0)
    gained, dis = val.get("gained") or {}, val.get("disagreements") or []
    st.markdown(_kpis([
        ui.kpi("Held-out lines", ui.num(total),
               "<span>not used for learning</span>" if val.get("held_out") else "<span>too few samples to hold out</span>"),
        ui.kpi("Recognized", ui.num(val.get("recognised", 0)), f"<span>of {ui.num(total)}</span>"),
        ui.kpi("Parsed cleanly", ui.num(ok), "<span>valid values, OCSF checked</span>",
               dot="good" if total and ok == total else "warning"),
        ui.kpi("Fields gained", ui.num(len(gained)),
               f"<span>{ui.esc(', '.join(FIELDS.get(k, k) for k in gained) or 'over the generic parser')}</span>"),
        ui.kpi("Disagreements", ui.num(len(dis)), "<span>with values the generic parser proved</span>",
               dot="critical" if dis else "good"),
    ]), unsafe_allow_html=True)
    for d in dis[:3]:
        st.error(f"{FIELDS.get(d['field'], d['field'])}: learned {d['learned']!r}, generic parser {d['generic']!r} · "
                 f"`{d['line'][:160]}`")
    for e in val.get("validation_errors") or []:
        st.warning(e)

    st.caption("Each part of the line that varies, the field proposed for it, and why. Rows that need review rest on "
               "position or weak evidence: tick Confirm if the proposal is right, or pick the right field. Every one "
               "must be confirmed or changed before approval.")
    slots = sorted(spec["slots"], key=lambda s: (not s.get("role"), s.get("source", {}).get("cell", -1)))
    slots = [s for s in slots if s.get("role") or s.get("distinct", 0) > 1 or s.get("alternatives")]
    df = pd.DataFrame([{
        "slot": s["id"], "Field": FIELDS.get(s.get("role"), NONE), "Needs review": bool(s.get("needs_review")),
        "Confirm": False, "Part of the line": s["label"],
        "Examples": ", ".join(str(x) for x in s.get("examples", [])[:3]),
        "Why": s.get("why") or "; ".join(s.get("alternatives", [])), "Evidence score": s.get("confidence") or 0.0,
    } for s in slots])
    edited = st.data_editor(
        df, key=f"slots_{pid}", hide_index=True, width="stretch",
        disabled=["slot", "Part of the line", "Examples", "Evidence score", "Needs review", "Why"],
        column_config={
            "slot": None,
            "Field": st.column_config.SelectboxColumn(options=[NONE] + list(FIELDS.values()), required=True,
                                                      width="medium"),
            "Needs review": st.column_config.CheckboxColumn(width="small"),
            "Confirm": st.column_config.CheckboxColumn(help="The proposed field is right", width="small"),
            "Part of the line": st.column_config.TextColumn(width="medium"),
            "Examples": st.column_config.TextColumn(width="medium"),
            "Why": st.column_config.TextColumn(width="large"),
            "Evidence score": st.column_config.ProgressColumn(
                min_value=0.0, max_value=1.0, format="%.2f", width="small",
                help="How strong the kind of evidence is (a standard field name, a named key, what the values "
                     "are, position alone). A rule weight checked against a threshold, not a probability. "
                     "Measured accuracy is in docs/PARSING.md and docs/PUBLIC_SAMPLES.md."),
        })
    original = {s["id"]: s.get("role") for s in slots}
    roles = {r["slot"]: LABEL_TO_ROLE.get(r["Field"]) for _, r in edited.iterrows()
             if LABEL_TO_ROLE.get(r["Field"]) != original.get(r["slot"])}
    confirmed = [r["slot"] for _, r in edited.iterrows() if r["Confirm"]]

    b = st.columns([1.2, 1, 1, 1], vertical_alignment="bottom")
    reviewer = b[0].text_input("Your name, recorded with the approval", key=f"who_{pid}")
    if b[1].button("Save and re-test", key=f"save_{pid}", width="stretch",
                   disabled=not (roles or confirmed or vendor or product)):
        res = APIClient.edit_learned(pid, roles, confirmed, reviewer or "reviewer", vendor, product)
        if res.get("error"):
            st.error(res["error"])
        else:
            st.rerun()
    if b[2].button("Approve & apply", type="primary", key=f"approve_{pid}", width="stretch",
                   disabled=parser["status"] == "approved" and not roles):
        if not reviewer.strip():
            st.error("Enter your name: every approval records who made it.")
        else:
            if roles or vendor or product:
                res = APIClient.edit_learned(pid, roles, [], reviewer, vendor, product)
                if res.get("error"):
                    st.error(res["error"])
                    return
            res = APIClient.approve_learned(pid, reviewer, confirmed)
            if res.get("error"):
                st.error("Not approved yet:\n\n" + "\n".join(f"- {x}" for x in res.get("blockers") or [res["error"]]))
            else:
                st.session_state[f"approved_{pid}"] = res.get("reparse_candidates", 0)
                st.session_state["fmt_focus"] = fid
                st.rerun()
    if b[3].button("Reject", key=f"reject_{pid}", width="stretch"):
        APIClient.reject_learned(pid)
        st.rerun()

    if parser["status"] == "approved":
        waiting = st.session_state.get(f"approved_{pid}")
        st.success("In use: new lines in this format are parsed with it within seconds, marked verified with the "
                   "approver's name." + (f" {waiting:,} earlier lines were stored before it existed." if waiting else ""))
        st.caption("Re-parsing reads past lines again from the archive. Nothing is overwritten: each result is a new "
                   "chained event that names the one it replaces, and it goes to the outputs too.")
        if st.button("Re-parse past lines", key=f"reparse_{pid}"):
            with st.spinner("Re-parsing from the archive…"):
                res = APIClient.reparse_learned(pid)
            if res.get("error"):
                st.error(res["error"])
            else:
                st.success(f"{res['revised']:,} events revised (#{res['first_sequence']} to #{res['last_sequence']}), "
                           f"{res['unchanged']:,} lines of other formats unchanged, {res['failed']} failed.")

    example = next((r for r in val.get("sample_results") or [] if r.get("passed")), None)
    if example:
        with st.expander("A held-out line and what the learned parser extracts"):
            st.code(example["sample_log"], language="text")
            st.json(example["extracted_fields"] or {})
