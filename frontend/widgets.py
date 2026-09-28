"""Controls several pages share: preparing an evidence bundle and a CERT-In report draft for download."""
from typing import Any, Dict, List, Optional

import streamlit as st

from backend.services.compliance.certin_types import INCIDENT_TYPES, suggest_types
from frontend.api_client import APIClient

CASE_FIELDS = [("case_ref", "Case or reference number"), ("prepared_by", "Prepared by (name)"),
               ("designation", "Designation"), ("organisation", "Organisation"), ("place", "Place")]
ORG_FIELDS = [("organisation", "Organisation"), ("sector", "Sector"), ("contact_name", "Contact person"),
              ("designation", "Designation"), ("phone", "Phone"), ("email", "Email"), ("address", "Address")]


def _fields(fields, key: str) -> Dict[str, str]:
    cols = st.columns(2)
    return {name: cols[i % 2].text_input(label, key=f"{key}-{name}") for i, (name, label) in enumerate(fields)}


def _offer(result: Optional[Dict[str, Any]], key: str, mime: str) -> None:
    if not result:
        return
    if not result.get("ok"):
        st.error(result.get("error") or "Could not prepare the file.")
        return
    st.download_button(f"Download {result['filename']}", data=result["data"], file_name=result["filename"],
                       mime=mime, key=f"{key}-dl", type="primary", width="stretch")
    sha = (result.get("headers") or {}).get("x-manifest-sha256") or \
        (result.get("headers") or {}).get("X-Manifest-SHA256")
    if sha:
        st.caption(f"manifest.json SHA-256 `{sha}`")


def evidence_bundle(key: str, choices: Dict[str, Dict[str, Any]], label: str = "Evidence bundle") -> None:
    """A popover that prepares a bundle for one of `choices` ({label: {"sequences": [...]} or {"incident_id": ...}})."""
    with st.popover(label, icon=":material/folder_zip:"):
        st.markdown("**Evidence bundle**")
        st.caption("A ZIP with the raw lines as received, the stored events, their chain records, Merkle proofs and "
                   "signed checkpoints, a verify.py anyone can run, and the Section 63(4) certificate particulars "
                   "with the hash report, for the person in charge and an expert to complete and sign.")
        pick = list(choices)[0]
        if len(choices) > 1:
            pick = st.segmented_control("Records", list(choices), default=pick, required=True, key=f"{key}-scope")
        case = _fields(CASE_FIELDS, key)
        scope = choices[pick]
        signature = repr(sorted(scope.items()))
        if st.button("Prepare the bundle", key=f"{key}-go", width="stretch"):
            with st.spinner("Collecting the records and their proofs…"):
                res = APIClient.evidence_bundle(scope.get("sequences"), scope.get("incident_id"), case)
            st.session_state[f"{key}-res"] = (signature, res)
        stored = st.session_state.get(f"{key}-res")
        if stored and stored[0] == signature:
            _offer(stored[1], key, "application/zip")


def certin_report(key: str, incident: Dict[str, Any]) -> None:
    with st.popover("CERT-In report draft", icon=":material/report:"):
        st.markdown("**CERT-In incident report (draft)**")
        st.caption("The facts a report to CERT-In needs, from this correlation: the Annexure I type, when it was "
                   "noticed and when the 6-hour window closes, what was affected, the indicators, the timeline and "
                   "the evidence kept. A person checks it and sends it to incident@cert-in.org.in; TRACELOG sends "
                   "nothing.")
        suggested = suggest_types(incident)
        types: List[str] = st.multiselect("Incident type (Annexure I)", list(INCIDENT_TYPES),
                                          default=[s["code"] for s in suggested],
                                          format_func=lambda c: f"({c}) {INCIDENT_TYPES[c]}", key=f"{key}-types")
        if suggested:
            st.caption("Suggested from the evidence: " + "; ".join(f"({s['code']}) {s['because']}" for s in suggested))
        org = _fields(ORG_FIELDS, key)
        signature = repr((incident.get("incident_id"), tuple(types), tuple(sorted(org.items()))))
        c1, c2 = st.columns(2)
        for fmt, col in (("pdf", c1), ("json", c2)):
            if col.button(f"Prepare {fmt.upper()}", key=f"{key}-{fmt}", width="stretch"):
                st.session_state[f"{key}-res"] = (signature, fmt, APIClient.certin_report(
                    incident["incident_id"], fmt, org, types))
        stored = st.session_state.get(f"{key}-res")
        if stored and stored[0] == signature:
            _offer(stored[2], key, "application/pdf" if stored[1] == "pdf" else "application/json")
