import re
from typing import Dict, Any, Tuple
from datetime import datetime

class SyslogParser:
    """
    Parses RFC 3164 (BSD syslog) and RFC 5424 (IETF syslog) messages.
    """
    # RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
    RFC5424_REGEX = re.compile(
        r'^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(?:\[(.*?)\])?\s*(.*)$'
    )

    # RFC 3164: <PRI>Mmm dd hh:mm:ss HOSTNAME TAG[PID]: MSG or <PRI>Mmm dd hh:mm:ss HOSTNAME MSG
    RFC3164_REGEX = re.compile(
        r'^<(\d{1,3})>([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[\s]+)?(?:\[(\d+)\])?:\s*(.*)$'
    )
    
    # Simpler fallback RFC 3164 without tag
    RFC3164_NO_TAG = re.compile(
        r'^<(\d{1,3})>([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$'
    )

    # Cisco ASA style: %ASA-6-302013: ... or %FTNTFGT-...
    CISCO_CODE_REGEX = re.compile(r'%([A-Z0-9_-]+):')

    @classmethod
    def parse_pri(cls, pri_str: str) -> Tuple[int, int]:
        """Returns (facility, severity) from numeric PRI"""
        try:
            pri = int(pri_str)
            facility = pri >> 3
            severity = pri & 7
            return facility, severity
        except Exception:
            return 1, 6 # Default User, Informational

    @classmethod
    def parse(cls, line: str) -> Tuple[bool, Dict[str, Any]]:
        line = line.strip()
        data: Dict[str, Any] = {"_format": "syslog"}

        # 1. Try RFC 5424
        match5424 = cls.RFC5424_REGEX.match(line)
        if match5424:
            pri, version, ts, host, app, procid, msgid, sd, msg = match5424.groups()
            facility, severity = cls.parse_pri(pri)
            data.update({
                "syslog_standard": "RFC5424",
                "pri": int(pri),
                "facility": facility,
                "severity_code": severity,
                "version": version,
                "timestamp": ts,
                "hostname": host,
                "app_name": app,
                "proc_id": procid if procid != "-" else None,
                "msg_id": msgid if msgid != "-" else None,
                "structured_data": sd,
                "message": msg,
            })
            return True, data

        # 2. Try RFC 3164
        match3164 = cls.RFC3164_REGEX.match(line)
        if match3164:
            pri, ts, host, tag, pid, msg = match3164.groups()
            facility, severity = cls.parse_pri(pri)
            data.update({
                "syslog_standard": "RFC3164",
                "pri": int(pri),
                "facility": facility,
                "severity_code": severity,
                "timestamp": ts,
                "hostname": host,
                "app_name": tag or "",
                "proc_id": pid,
                "message": msg,
            })
            return True, data

        match3164_notag = cls.RFC3164_NO_TAG.match(line)
        if match3164_notag:
            pri, ts, host, msg = match3164_notag.groups()
            facility, severity = cls.parse_pri(pri)
            data.update({
                "syslog_standard": "RFC3164",
                "pri": int(pri),
                "facility": facility,
                "severity_code": severity,
                "timestamp": ts,
                "hostname": host,
                "message": msg,
            })
            return True, data

        return False, {}
