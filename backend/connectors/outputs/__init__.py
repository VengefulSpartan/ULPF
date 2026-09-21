"""Output connector registry."""
from typing import Dict, Type

from backend.connectors.config import Output

from .base import DeliveryError, Sink
from .file_sinks import FileSink, ParquetSink
from .http_sinks import ElasticsearchSink, LokiSink, OtlpHttpSink, SentinelSink, SplunkHecSink, WebhookSink
from .stream_sinks import GelfSink, KafkaSink, SyslogSink

SINK_TYPES: Dict[str, Type[Sink]] = {
    "splunk_hec": SplunkHecSink,
    "elasticsearch": ElasticsearchSink,
    "opensearch": ElasticsearchSink,
    "wazuh_indexer": ElasticsearchSink,
    "loki": LokiSink,
    "otlp_http": OtlpHttpSink,
    "sentinel": SentinelSink,
    "webhook": WebhookSink,
    "datadog": WebhookSink,
    "newrelic": WebhookSink,
    "syslog": SyslogSink,
    "gelf": GelfSink,
    "kafka": KafkaSink,
    "file": FileSink,
    "parquet": ParquetSink,
}

# Which downstream products each output type reaches (shown in the UI and README).
COMPATIBILITY = [
    {"output": "splunk_hec", "reaches": "Splunk Enterprise / Cloud, Splunk ES, Cribl Stream (HEC source)"},
    {"output": "elasticsearch / opensearch", "reaches": "Elastic Stack / Elastic Security, OpenSearch, "
                                                        "Wazuh indexer, Graylog (OpenSearch backend)"},
    {"output": "syslog (cef)", "reaches": "ArcSight, LogRhythm/Exabeam, Securonix, Trellix, most SIEM syslog inputs"},
    {"output": "syslog (leef)", "reaches": "IBM QRadar"},
    {"output": "syslog (json)", "reaches": "Wazuh manager, rsyslog/syslog-ng relays, Google SecOps forwarder"},
    {"output": "gelf", "reaches": "Graylog"},
    {"output": "loki", "reaches": "Grafana Loki / Grafana"},
    {"output": "otlp_http", "reaches": "OpenTelemetry Collector, Grafana, Elastic, Dynatrace, New Relic, "
                                       "SigNoz, OpenObserve, Datadog (via Agent/Collector)"},
    {"output": "sentinel", "reaches": "Microsoft Sentinel / Azure Monitor (Logs Ingestion API)"},
    {"output": "datadog / newrelic", "reaches": "Datadog Logs, New Relic Logs (direct HTTPS intake)"},
    {"output": "webhook", "reaches": "Any HTTPS JSON endpoint (SOAR, custom collectors)"},
    {"output": "kafka", "reaches": "Kafka-based data pipelines and lakes"},
    {"output": "file / parquet", "reaches": "Data lakes (DuckDB, Spark, Athena, Trino), removable-media hand-off"},
]


def build_sink(cfg: Output, data_dir: str = "data") -> Sink:
    try:
        cls = SINK_TYPES[cfg.type]
    except KeyError:
        raise ValueError(f"unknown output type '{cfg.type}'; choose one of {', '.join(sorted(SINK_TYPES))}")
    return cls(cfg, data_dir=data_dir)


__all__ = ["COMPATIBILITY", "DeliveryError", "SINK_TYPES", "Sink", "build_sink"]
