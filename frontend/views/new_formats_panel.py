"""
Parser Studio > New log formats: formats no parser knows, grouped by structure, and the
review that turns one into an approved parser (learn -> review -> approve -> re-parse).
"""
from typing import Any, Dict, List, Optional

import pandas as pd
import streamlit as st

from frontend.api_client import APIClient

FIELDS = {"src_ip": "source IP", "src_port": "source port", "dst_ip": "destination IP", "dst_port": "destination port",
          "protocol": "protocol", "action": "action", "time": "time", "severity": "severity", "user": "user",
          "signature": "threat / signature"}
NONE = "— (not a field)"
LABEL_TO_ROLE = {v: k for k, v in FIELDS.items()}
STATUS = {"new": "🟠 new", "learned": "🟢 parser live", "ignored": "⚪ ignored"}


def _card(title: str, value: str, sub: str = "", color: str = "#0F172A") -> str:
    return (f'<div class="metric-card"><div class="metric-title">{title}</div>'
            f'<div class="metric-value" style="font-size:1.35rem; color:{color};">{value}</div>'
            f'<div class="metric-subtext">{sub}</div></div>')


def _short(text: str, n: int = 90) -> str:
    return text if len(text) <= n else text[:n - 1] + "…"


def render_new_formats() -> None:
    st.markdown("##### Log formats no parser knows")
    st.caption("Lines no parser pack recognises are archived and parsed by the generic parser, which fills only "
               "fields it can prove and leaves the rest empty. They are grouped here by structure, so a new device "
               "or a changed firmware shows up as one format, not thousands of lines. Learn a parser from its "
               "samples, review it, approve it: it applies to new lines within seconds, and past lines can be "
               "re-parsed.")
    all_formats = APIClient.list_formats()
    new = [f for f in all_formats if f["status"] == "new"]
    c = st.columns(4)
    c[0].markdown(_card("New formats", f"{len(new):,}", "waiting for a parser",
                        "#B45309" if new else "#0F172A"), unsafe_allow_html=True)
    c[1].markdown(_card("Lines without a parser", f"{sum(f['count'] for f in new):,}",
                        "parsed by the generic parser"), unsafe_allow_html=True)
    c[2].markdown(_card("Learned parsers live", f"{len({f['parser_id'] for f in all_formats if f['status'] == 'learned'}):,}",
                        f"{sum(1 for f in all_formats if f['status'] == 'learned'):,} formats covered"),
                  unsafe_allow_html=True)
    drifted = [f for f in all_formats if f.get("drift_from")]
    c[3].markdown(_card("Format changes", f"{len(drifted):,}", "a known device's format drifted",
                        "#B91C1C" if drifted else "#0F172A"), unsafe_allow_html=True)
    if not all_formats:
        st.info("Nothing to review: every line received so far was recognised by a parser pack.")
        return

    show = st.radio("Show", ["New", "Parser live", "Ignored", "All"], horizontal=True, key="fmt_filter")
    want = {"New": "new", "Parser live": "learned", "Ignored": "ignored"}.get(show)
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
        "Last seen": (f["last_seen"] or "")[:19].replace("T", " "),
        "Generic evidence score": f["avg_confidence"],
        "Drifted from": f.get("drift_from") or "",
    } for f in rows])
    st.dataframe(table, use_container_width=True, hide_index=True)

    labels = {f["format_id"]: f"{f['count']:,} lines · {_short(f['template'], 80)}" for f in rows}
    fid = st.selectbox("Review a format", list(labels), format_func=labels.get, key="fmt_pick")
    if fid:
        _format_panel(fid)


def _format_panel(fid: str) -> None:
    fmt = APIClient.format_detail(fid)
    if fmt.get("error"):
        st.error(fmt["error"])
        return
    st.markdown("---")
    st.markdown(f"**Format `{fid}`** · {fmt['kind']} · {fmt['count']:,} lines · {fmt['samples']:,} samples kept · "
                f"first seen {(fmt['first_seen'] or '')[:19].replace('T', ' ')} UTC · devices: "
                f"{', '.join(f'{k} ({v})' for k, v in fmt['sources'].items()) or '-'}")
    st.code(fmt["template"], language="text")
    if fmt.get("drift_from"):
        st.warning(f"These lines were claimed by the **{fmt['drift_from']}** parser pack, which produced impossible "
                   "values (an address that is not an IP, a port above 65535), so its output was not used. The "
                   "device's log format has probably changed, for example after a firmware update.")
    with st.expander(f"Sample lines ({len(fmt.get('samples_shown') or [])} of {fmt['samples']})"):
        st.code("\n".join(s["raw_text"] for s in fmt.get("samples_shown") or []), language="text")
    now = (fmt.get("parsed_now") or [None])[0]
    if now:
        st.markdown("###### How the first sample is parsed now")
        cols = st.columns(3)
        cols[0].markdown("**Filled** (with evidence)")
        cols[0].json(now["filled"] or {}, expanded=True)
        cols[1].markdown("**Evidence too weak, left empty**")
        cols[1].json(now["not_filled"] or {}, expanded=True)
        cols[2].markdown("**Addresses with unknown direction**")
        cols[2].write(", ".join(now["unassigned_ips"]) or "none")
        st.caption(f"Parser: {now['parser']}")

    parser = fmt.get("parser")
    top = st.columns([1, 1, 1, 1])
    vendor = top[0].text_input("Vendor", value=(parser or {}).get("vendor") if parser and parser["vendor"] != "Unknown"
                               else "", key=f"v_{fid}", placeholder="e.g. WatchGuard")
    product = top[1].text_input("Product", value=(parser or {}).get("product") or "", key=f"p_{fid}",
                                placeholder="e.g. Firebox")
    if not parser or parser["status"] == "rejected":
        if top[2].button(f"🧠 Learn a parser from {fmt['samples']} lines", type="primary", key=f"learn_{fid}",
                         use_container_width=True, disabled=fmt["samples"] < 2):
            with st.spinner("Profiling every part of the line across the samples and testing on held-out lines…"):
                res = APIClient.learn_format(fid, vendor, product)
            if res.get("error"):
                st.error(res["error"])
            else:
                st.rerun()
    if fmt["status"] != "ignored":
        if top[3].button("Ignore this format", key=f"ign_{fid}", use_container_width=True):
            APIClient.ignore_format(fid)
            st.session_state["fmt_focus"] = fid
            st.rerun()
    elif top[3].button("Stop ignoring", key=f"unign_{fid}", use_container_width=True):
        APIClient.ignore_format(fid, undo=True)
        st.session_state["fmt_focus"] = fid
        st.rerun()
    if parser and parser["status"] != "rejected":
        _review(fid, parser, vendor, product)


def _review(fid: str, parser: Dict[str, Any], vendor: str, product: str) -> None:
    pid, spec, val = parser["id"], parser["spec"], parser.get("validation") or {}
    st.markdown("###### Learned parser")
    state = {"candidate": "🟠 candidate, not applied yet", "approved": "🟢 approved and live"}.get(parser["status"],
                                                                                               parser["status"])
    st.markdown(f"**{parser['name']}** · {state} · OCSF class {parser['class_uid']} {parser['class_name']} · learned "
                f"from {spec.get('samples_learned', '?')} lines"
                + (f" · approved by **{parser['approved_by']}** at {parser['approved_at'][:19].replace('T', ' ')} UTC"
                   if parser["status"] == "approved" else ""))

    total = val.get("total_samples", 0)
    c = st.columns(5)
    c[0].markdown(_card("Held-out lines", f"{total:,}", "not used for learning" if val.get("held_out")
                        else "too few samples to hold any out"), unsafe_allow_html=True)
    c[1].markdown(_card("Recognised", f"{val.get('recognised', 0):,}", f"of {total:,}"), unsafe_allow_html=True)
    ok = val.get("passed_samples", 0)
    c[2].markdown(_card("Parsed cleanly", f"{ok:,}", "all values valid, OCSF checked",
                        "#2E7D32" if total and ok == total else "#B45309"), unsafe_allow_html=True)
    gained = val.get("gained") or {}
    c[3].markdown(_card("Fields gained", f"{len(gained)}", ", ".join(FIELDS.get(k, k) for k in gained) or
                        "vs the generic parser"), unsafe_allow_html=True)
    dis = val.get("disagreements") or []
    c[4].markdown(_card("Disagreements", f"{len(dis)}", "with values the generic parser proved",
                        "#B91C1C" if dis else "#2E7D32"), unsafe_allow_html=True)
    for d in dis[:3]:
        st.error(f"{FIELDS.get(d['field'], d['field'])}: learned {d['learned']!r}, generic parser {d['generic']!r} · "
                 f"`{d['line'][:160]}`")
    for e in val.get("validation_errors") or []:
        st.warning(e)

    st.markdown("**Fields.** Each part of the line that varies, what it is proposed to be, and why. Rows marked "
                "*needs review* rest on position or weak evidence: tick **Confirm** if the proposal is right, or "
                "pick the correct field. The parser cannot be approved until every one is confirmed or changed.")
    slots = sorted(spec["slots"], key=lambda s: (not s.get("role"), s.get("source", {}).get("cell", -1)))
    slots = [s for s in slots if s.get("role") or s.get("distinct", 0) > 1 or s.get("alternatives")]
    df = pd.DataFrame([{
        "slot": s["id"], "Field": FIELDS.get(s.get("role"), NONE), "Needs review": bool(s.get("needs_review")),
        "Confirm": False, "Part of the line": s["label"],
        "Examples": ", ".join(str(x) for x in s.get("examples", [])[:3]),
        "Why": s.get("why") or "; ".join(s.get("alternatives", [])), "Evidence score": s.get("confidence") or 0.0,
    } for s in slots])
    edited = st.data_editor(
        df, key=f"slots_{pid}", hide_index=True, use_container_width=True,
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
                     "are, position alone) — a rule weight used against a threshold, not a measured probability. "
                     "The parser's measured accuracy is in docs/PARSING.md and docs/PUBLIC_SAMPLES.md."),
        })
    original = {s["id"]: s.get("role") for s in slots}
    roles = {r["slot"]: LABEL_TO_ROLE.get(r["Field"]) for _, r in edited.iterrows()
             if LABEL_TO_ROLE.get(r["Field"]) != original.get(r["slot"])}
    confirmed = [r["slot"] for _, r in edited.iterrows() if r["Confirm"]]

    b = st.columns([1.2, 1, 1, 1])
    reviewer = b[0].text_input("Your name (recorded with the approval)", key=f"who_{pid}")
    if b[1].button("💾 Save changes & re-test", key=f"save_{pid}", use_container_width=True,
                   disabled=not (roles or confirmed or vendor or product)):
        res = APIClient.edit_learned(pid, roles, confirmed, reviewer or "reviewer", vendor, product)
        if res.get("error"):
            st.error(res["error"])
        else:
            st.rerun()
    if b[2].button("✅ Approve & apply", type="primary", key=f"approve_{pid}", use_container_width=True,
                   disabled=parser["status"] == "approved" and not roles):
        if not reviewer.strip():
            st.error("Enter your name: approvals are recorded with the approver.")
        else:
            if roles or vendor or product:
                res = APIClient.edit_learned(pid, roles, [], reviewer, vendor, product)
                if res.get("error"):
                    st.error(res["error"])
                    return
            res = APIClient.approve_learned(pid, reviewer, confirmed)
            if res.get("error"):
                st.error("Approval blocked")
                for blocker in res.get("blockers") or [res["error"]]:
                    st.markdown(f"- {blocker}")
            else:
                st.session_state[f"approved_{pid}"] = res.get("reparse_candidates", 0)
                st.session_state["fmt_focus"] = fid
                st.rerun()
    if b[3].button("Reject", key=f"reject_{pid}", use_container_width=True):
        APIClient.reject_learned(pid)
        st.rerun()

    if parser["status"] == "approved":
        waiting = st.session_state.get(f"approved_{pid}")
        st.success("Live: new lines of this format are parsed by this parser (marked verified, with the approver's "
                   "name) within a few seconds, no restart needed."
                   + (f" {waiting:,} past lines were parsed before it existed." if waiting else ""))
        st.markdown("**Re-parse history.** Past lines of this format are parsed again from the byte-for-byte "
                    "archive. Nothing is overwritten: each result is a new event appended to the integrity chain "
                    "that names the event it supersedes, and it is sent to the configured outputs so SIEMs get the "
                    "corrected fields.")
        if st.button("🔁 Re-parse past lines", key=f"reparse_{pid}"):
            with st.spinner("Re-parsing from the archive…"):
                res = APIClient.reparse_learned(pid)
            if res.get("error"):
                st.error(res["error"])
            else:
                st.success(f"{res['revised']:,} events revised (sequence {res['first_sequence']}–"
                           f"{res['last_sequence']}), {res['unchanged']:,} lines of other formats left as they were, "
                           f"{res['failed']} failures.")

    example = next((r for r in val.get("sample_results") or [] if r.get("passed")), None)
    if example:
        with st.expander("Example: a held-out line and what the learned parser extracts"):
            st.code(example["sample_log"], language="text")
            st.json(example["extracted_fields"] or {})
