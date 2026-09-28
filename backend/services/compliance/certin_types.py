"""
The cyber security incident types of Annexure I to the CERT-In directions of 28 April 2022, and a
first guess at which ones a correlation result points to. No database: the dashboard imports it.
"""
import re
from typing import Any, Dict, List

# Annexure I of the directions: the types of cyber security incidents to be reported
INCIDENT_TYPES = {
    "i": "Targeted scanning/probing of critical networks/systems",
    "ii": "Compromise of critical systems/information",
    "iii": "Unauthorised access of IT systems/data",
    "iv": "Defacement of website or intrusion into a website and unauthorised changes",
    "v": "Malicious code attacks (virus, worm, Trojan, bots, spyware, ransomware, cryptominers)",
    "vi": "Attack on servers such as database, mail and DNS, and network devices such as routers",
    "vii": "Identity theft, spoofing and phishing attacks",
    "viii": "Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks",
    "ix": "Attacks on critical infrastructure, SCADA and operational technology systems and wireless networks",
    "x": "Attacks on applications such as e-Governance, e-Commerce etc.",
    "xi": "Data breach",
    "xii": "Data leak",
    "xiii": "Attacks on Internet of Things (IoT) devices and associated systems, networks, software, servers",
    "xiv": "Attacks or incidents affecting digital payment systems",
    "xv": "Attacks through malicious mobile apps",
    "xvi": "Fake mobile apps",
    "xvii": "Unauthorised access to social media accounts",
    "xviii": "Attacks or malicious/suspicious activities affecting cloud computing systems/servers/software/applications",
    "xix": "Attacks or malicious/suspicious activities affecting systems/servers/networks/software/applications related "
           "to Big Data, Blockchain, virtual assets, virtual asset exchanges, custodian wallets, robotics, 3D and 4D "
           "printing, additive manufacturing, drones",
    "xx": "Attacks or malicious/suspicious activities affecting systems/servers/software/applications related to "
          "Artificial Intelligence and Machine Learning",
}

# (type, words in a detection's title or a rule's name that point to it)
_HINTS = [
    ("i", r"scan|nmap|nikto|probe|sweep|recon|port ?scan|PORT_SWEEP"),
    ("iii", r"brute|password|spray|login|logon|auth|credential|unauthori[sz]ed|LOGIN_THEN_ACTIVITY"),
    ("x", r"sql|injection|traversal|xss|cross.site|web attack|http|php|wordpress|struts|log4j|apache"),
    ("ii", r"code execution|remote code|rce|exploit|overflow|shellcode|privilege|smb|eternal"),
    ("v", r"malware|trojan|ransom|worm|botnet|\bbot\b|miner|beacon|c2|command.and.control|backdoor|virus"),
    ("viii", r"\bdos\b|ddos|flood|denial"),
    ("xii", r"exfil|leak|large (upload|transfer)|data transfer"),
    ("vii", r"phish|spoof|impersonat"),
    ("vi", r"dns|smtp|mail server|database|mysql|mssql|router"),
]


def suggest_types(incident: Dict[str, Any]) -> List[Dict[str, str]]:
    """Annexure I types the evidence points to, each with what pointed there. A suggestion only."""
    texts = [(f.get("fact_description") or "", f"event #{f.get('sequence_num')}") for f in incident.get("observed_facts") or []]
    texts += [(l.get("relationship_type") or "", "the correlation rule " + (l.get("relationship_type") or ""))
              for l in incident.get("inferred_relationships") or []]
    out = []
    for code, pattern in _HINTS:
        rx = re.compile(pattern, re.I)
        hits = [where for text, where in texts if rx.search(text)]
        if hits:
            out.append({"code": code, "type": INCIDENT_TYPES[code],
                        "because": f"{len(hits)} item(s) match, first {hits[0]}"})
    return out


