import json
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, status
from pydantic import BaseModel
from typing import List, Optional
from backend.services.ingestion.pipeline import IngestionPipeline
from backend.services.storage.db import db
from backend.models.source import Source

router = APIRouter(prefix="/ingest", tags=["Log Ingestion"])

class SingleLogRequest(BaseModel):
    raw_text: str
    source_id: str
    source_vendor: Optional[str] = "Generic"
    source_product: Optional[str] = "Network Device"

class BatchLogRequest(BaseModel):
    raw_logs: List[str]
    source_id: str
    source_vendor: Optional[str] = "Generic"
    source_product: Optional[str] = "Network Device"

@router.post("/single")
def ingest_single(req: SingleLogRequest):
    try:
        res = IngestionPipeline.ingest_single_log(
            raw_text=req.raw_text,
            source_id=req.source_id,
            source_vendor=req.source_vendor or "Generic",
            source_product=req.source_product or "Device"
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/batch")
def ingest_batch(req: BatchLogRequest):
    try:
        res = IngestionPipeline.ingest_batch(
            lines=req.raw_logs,
            source_id=req.source_id,
            source_vendor=req.source_vendor or "Generic",
            source_product=req.source_product or "Device"
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/file")
async def ingest_file(
    file: UploadFile = File(...),
    source_id: str = Form(...),
    source_vendor: str = Form("Generic"),
    source_product: str = Form("Device")
):
    try:
        content = await file.read()
        lines = content.decode("utf-8", errors="replace").splitlines()
        res = IngestionPipeline.ingest_batch(
            lines=lines,
            source_id=source_id,
            source_vendor=source_vendor,
            source_product=source_product
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"File processing error: {str(e)}")

@router.post("/seed-samples")
def seed_sample_datasets():
    """
    Loads realistic, clearly labeled synthetic perimeter logs from Cisco, Palo Alto,
    Fortinet, and Suricata for immediate out-of-the-box demonstration.
    """
    sources_to_seed = [
        ("src-palo-alto", "Palo Alto NGFW", "Palo Alto Networks", "PAN-OS PA-5200", "cef", "firewall"),
        ("src-cisco-asa", "Cisco ASA Edge", "Cisco", "ASA 5585-X", "syslog", "firewall"),
        ("src-forti-vpn", "FortiGate SSL-VPN", "Fortinet", "FortiGate 100F", "kv", "vpn"),
        ("src-suricata-ids", "Suricata Perimeter IDS", "Suricata", "Suricata 7.0", "json", "ids"),
    ]

    with db.get_connection() as conn:
        cursor = conn.cursor()
        for s_id, s_name, s_vend, s_prod, s_fmt, s_cat in sources_to_seed:
            cursor.execute(
                """
                INSERT OR IGNORE INTO sources (id, name, vendor, product, format_type, category, description, is_active, created_at, event_count)
                VALUES (?, ?, ?, ?, ?, ?, 'Perimeter network appliance (Synthetic demo source)', 1, datetime('now'), 0)
                """,
                (s_id, s_name, s_vend, s_prod, s_fmt, s_cat)
            )
        conn.commit()

    # Synthetic logs representing normal traffic and a coordinated 4-phase incident:
    # Phase 1: External contractor VPN login from 198.51.100.22
    # Phase 2: Internal scanning from 10.0.1.15 to server 192.168.1.50
    # Phase 3: Suricata IDS detects EternalBlue exploit attempt
    # Phase 4: Palo Alto firewall flags and blocks outbound egress
    sample_logs = [
        ("src-forti-vpn", "Fortinet", "FortiGate", 'date=2026-09-20 time=14:00:01 devname="FGT-VPN" type="vpn" action="login" status="success" user="contractor_bob" srcip=198.51.100.22 dstip=10.0.1.15 auth_method="MFA-OTP"'),
        ("src-cisco-asa", "Cisco", "ASA", '<166>Sep 20 14:00:15 ciscoasa %ASA-6-302013: Built inbound TCP connection 88123 for outside:198.51.100.22/51200 to inside:10.0.1.15/443'),
        ("src-cisco-asa", "Cisco", "ASA", '<166>Sep 20 14:00:30 ciscoasa %ASA-6-302013: Built inside TCP connection 88124 for inside:10.0.1.15/49152 to dmz:192.168.1.50/445'),
        ("src-palo-alto", "Palo Alto Networks", "PAN-OS", 'CEF:0|Palo Alto Networks|PAN-OS|10.1|TRAFFIC|start|3|src=10.0.1.15 dst=192.168.1.50 spt=49152 dpt=445 proto=TCP act=allow deviceReceiptTime=2026-09-20T14:00:32Z'),
        ("src-suricata-ids", "Suricata", "Suricata", '{"timestamp":"2026-09-20T14:00:45.000000+0000","event_type":"alert","src_ip":"10.0.1.15","src_port":49152,"dest_ip":"192.168.1.50","dest_port":445,"proto":"TCP","alert":{"action":"alerted","signature":"ET EXPLOIT EternalBlue SMB MS17-010","severity":"High","category":"Attempted Administrator Privilege Gain"}}'),
        ("src-palo-alto", "Palo Alto Networks", "PAN-OS", 'CEF:0|Palo Alto Networks|PAN-OS|10.1|THREAT|vulnerability|5|src=10.0.1.15 dst=192.168.1.50 spt=49152 dpt=445 proto=TCP act=drop deviceReceiptTime=2026-09-20T14:00:46Z threat_name="SMB Remote Code Execution"'),
        ("src-palo-alto", "Palo Alto Networks", "PAN-OS", 'CEF:0|Palo Alto Networks|PAN-OS|10.1|TRAFFIC|end|2|src=192.168.1.10 dst=8.8.8.8 spt=53000 dpt=53 proto=UDP act=allow deviceReceiptTime=2026-09-20T14:01:00Z bytes_sent=64 bytes_received=128'),
        ("src-cisco-asa", "Cisco", "ASA", '<166>Sep 20 14:01:10 ciscoasa %ASA-4-106023: Deny tcp src outside:203.0.113.88/44321 dst inside:192.168.1.10/22 by access-group "OUTSIDE_IN"')
    ]

    ingested = 0
    for s_id, s_vend, s_prod, log_line in sample_logs:
        IngestionPipeline.ingest_single_log(log_line, s_id, s_vend, s_prod)
        ingested += 1

    return {
        "status": "success",
        "message": f"Successfully initialized 4 perimeter sources and ingested {ingested} synthetic multi-device events.",
        "ingested_count": ingested
    }
