"""
Connector configuration (inputs, source mapping, outputs), loaded from YAML.

The file path comes from TRACELOG_CONFIG (default: config/tracelog.yaml).
Any ${VAR} or ${VAR:-default} in the file is replaced from the environment,
so tokens and passwords never have to be written into the file itself.
With no file present TRACELOG starts with no listeners and no outputs; the
HTTP receivers (HEC, OTLP, NDJSON) are always mounted on the API port.
"""
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import yaml
from pydantic import BaseModel, Field

_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), value)
    if isinstance(value, list):
        return [_expand(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    return value


class SyslogInput(BaseModel):
    name: str
    protocol: Literal["udp", "tcp", "tls"] = "udp"
    host: str = "0.0.0.0"
    port: int = 5514
    certfile: Optional[str] = None     # tls
    keyfile: Optional[str] = None      # tls
    client_ca: Optional[str] = None    # tls: require client certificates signed by this CA
    max_message_bytes: int = 65536


class HttpInput(BaseModel):
    enabled: bool = True
    tokens: List[str] = Field(default_factory=list)   # empty = no authentication (lab use only)


class FileInput(BaseModel):
    name: str
    paths: List[str]
    start_at: Literal["beginning", "end"] = "end"
    poll_seconds: float = 1.0


class KafkaInput(BaseModel):
    name: str
    bootstrap_servers: List[str]
    topics: List[str]
    group_id: str = "tracelog"
    options: Dict[str, Any] = Field(default_factory=dict)   # passed to KafkaConsumer (security_protocol, sasl_*)


class Inputs(BaseModel):
    syslog: List[SyslogInput] = Field(default_factory=list)
    http: HttpInput = Field(default_factory=HttpInput)
    files: List[FileInput] = Field(default_factory=list)
    kafka: List[KafkaInput] = Field(default_factory=list)


class StaticSource(BaseModel):
    name: str
    match_ip: Optional[str] = None
    match_hostname: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    category: Optional[str] = None


class OutputFilter(BaseModel):
    classes: List[int] = Field(default_factory=list)       # OCSF class_uid allow-list; empty = all
    min_severity_id: int = 0
    sources: List[str] = Field(default_factory=list)       # source names; empty = all


class Output(BaseModel):
    """Common settings; everything type-specific lives in `settings`."""
    name: str
    type: str
    enabled: bool = True
    batch_size: int = 200
    flush_seconds: float = 1.0
    queue_size: int = 50000
    max_retries: int = 5
    retry_backoff_seconds: float = 1.0
    timeout_seconds: float = 10.0
    include_raw: bool = True
    filter: OutputFilter = Field(default_factory=OutputFilter)
    settings: Dict[str, Any] = Field(default_factory=dict)


class Pipeline(BaseModel):
    batch_size: int = 500
    flush_seconds: float = 0.5
    queue_size: int = 200000


class TracelogConfig(BaseModel):
    inputs: Inputs = Field(default_factory=Inputs)
    sources: List[StaticSource] = Field(default_factory=list)
    outputs: List[Output] = Field(default_factory=list)
    pipeline: Pipeline = Field(default_factory=Pipeline)
    data_dir: str = "data"


def load_config(path: Optional[str] = None) -> TracelogConfig:
    path = path or os.environ.get("TRACELOG_CONFIG", "config/tracelog.yaml")
    p = Path(path)
    if not p.exists():
        return TracelogConfig()
    raw = yaml.safe_load(p.read_text()) or {}
    raw = raw.get("tracelog", raw)
    outputs = []
    for o in raw.get("outputs", []) or []:
        common = {k: o[k] for k in Output.model_fields if k in o and k != "settings"}
        extra = {k: v for k, v in o.items() if k not in Output.model_fields}
        outputs.append({**common, "settings": {**extra, **(o.get("settings") or {})}})
    raw["outputs"] = outputs
    return TracelogConfig.model_validate(_expand(raw))
