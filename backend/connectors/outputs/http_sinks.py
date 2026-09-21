"""
HTTP outputs: Splunk HEC, Elasticsearch / OpenSearch / Wazuh indexer bulk API,
Grafana Loki push API, OpenTelemetry OTLP/HTTP, Microsoft Sentinel Logs
Ingestion API and a generic webhook (with Datadog and New Relic presets).
"""
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from .base import DeliveryError, Sink
from .formats import hostname_of, key_attributes, otlp_logs, summary, ts_iso


def _client(sink: Sink) -> httpx.Client:
    s = sink.s
    verify: Any = s.get("verify_tls", True)
    if s.get("ca_file"):
        verify = s["ca_file"]
    cert = (s["client_cert"], s["client_key"]) if s.get("client_cert") and s.get("client_key") else None
    auth = (s["username"], s.get("password", "")) if s.get("username") else None
    return httpx.Client(verify=verify, cert=cert, auth=auth, timeout=sink.cfg.timeout_seconds,
                        headers={"User-Agent": "TRACELOG/1.0", **(s.get("headers") or {})})


def _check(resp: httpx.Response, what: str) -> None:
    if resp.status_code in (408, 429) or resp.status_code >= 500:
        raise DeliveryError(f"{what} HTTP {resp.status_code}: {resp.text[:200]}", retryable=True)
    if resp.status_code >= 400:
        raise DeliveryError(f"{what} HTTP {resp.status_code}: {resp.text[:200]}", retryable=False)


class HttpSink(Sink):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._http: Optional[httpx.Client] = None

    @property
    def http(self) -> httpx.Client:
        if self._http is None:
            self._http = _client(self)
        return self._http

    def close(self) -> None:
        if self._http is not None:
            self._http.close()

    def require(self, *keys: str) -> None:
        missing = [k for k in keys if not self.s.get(k)]
        if missing:
            raise ValueError(f"output '{self.cfg.name}' ({self.type_name}) needs: {', '.join(missing)}")


class SplunkHecSink(HttpSink):
    """Splunk HTTP Event Collector. Also accepted by Cribl Stream and other HEC-compatible receivers."""
    type_name = "splunk_hec"

    def validate_settings(self):
        self.require("url", "token")

    def send(self, batch):
        s = self.s
        # HEC takes concatenated JSON objects; whitespace between them is allowed and keeps bodies readable.
        body = "\n".join(json.dumps({
            "time": (e.get("time") or 0) / 1000.0, "host": hostname_of(e), "source": s.get("source", "tracelog"),
            "sourcetype": s.get("sourcetype", "ocsf:tracelog"), **({"index": s["index"]} if s.get("index") else {}),
            "event": e,
        }, default=str) for e in batch)
        url = s["url"].rstrip("/")
        if not url.endswith("/services/collector/event"):
            url += "/services/collector/event"
        r = self.http.post(url, content=body, headers={"Authorization": f"Splunk {s['token']}",
                                                       "Content-Type": "application/json"})
        _check(r, "Splunk HEC")


class ElasticsearchSink(HttpSink):
    """Elasticsearch / OpenSearch / Wazuh indexer `_bulk` API. `index` may contain strftime codes.

    Each document's _id is the OCSF event uid and the op is `create`, so sending an event twice (a
    re-sent dead letter, a batch repeated after a crash) is refused with 409 and counted as delivered:
    re-sends never create duplicates in the index."""
    type_name = "elasticsearch"

    def validate_settings(self):
        self.require("url")

    def describe_target(self):
        return f"{self.s['url']} index={self.s.get('index', 'tracelog-ocsf-%Y.%m.%d')}"

    def send(self, batch):
        s = self.s
        pattern = s.get("index", "tracelog-ocsf-%Y.%m.%d")
        lines = []
        for e in batch:
            dt = datetime.fromtimestamp((e.get("time") or 0) / 1000.0, tz=timezone.utc)
            uid = (e.get("metadata") or {}).get("uid")
            lines.append(json.dumps({"create": {"_index": dt.strftime(pattern), **({"_id": uid} if uid else {})}}))
            lines.append(json.dumps({"@timestamp": ts_iso(e), **e}, default=str))
        headers = {"Content-Type": "application/x-ndjson"}
        if s.get("api_key"):
            headers["Authorization"] = f"ApiKey {s['api_key']}"
        r = self.http.post(s["url"].rstrip("/") + "/_bulk", content="\n".join(lines) + "\n", headers=headers)
        _check(r, "bulk")
        result = r.json()
        if not result.get("errors"):
            return
        rejected, retry = [], False
        for e, item in zip(batch, result.get("items", [])):
            status = next(iter(item.values())).get("status", 200)
            if status == 409:  # already indexed under this uid: delivered earlier
                continue
            if status == 429 or status >= 500:
                retry = True
            elif status >= 400:
                rejected.append(e)
        if retry:
            raise DeliveryError("bulk: some documents were throttled or failed on the server", retryable=True)
        if rejected:
            raise DeliveryError(f"bulk: {len(rejected)} documents rejected (mapping/validation)", rejected=rejected)


class LokiSink(HttpSink):
    """Grafana Loki push API. Labels are kept low-cardinality: job, class, vendor, severity."""
    type_name = "loki"

    def validate_settings(self):
        self.require("url")

    def send(self, batch):
        s = self.s
        streams: Dict[tuple, List[List[str]]] = {}
        for e in batch:
            labels = {"job": s.get("job", "tracelog"),
                      "ocsf_class": str(e.get("class_name", "unknown")).lower().replace(" ", "_"),
                      "vendor": str((e.get("metadata") or {}).get("product", {}).get("vendor_name", "unknown")),
                      "severity": str(e.get("severity", "unknown")).lower(), **(s.get("labels") or {})}
            key = tuple(sorted(labels.items()))
            streams.setdefault(key, []).append([str(int(e.get("time") or 0) * 1_000_000),
                                                json.dumps(e, default=str, separators=(",", ":"))])
        payload = {"streams": [{"stream": dict(k), "values": v} for k, v in streams.items()]}
        headers = {"X-Scope-OrgID": s["tenant"]} if s.get("tenant") else {}
        url = s["url"].rstrip("/")
        if not url.endswith("/loki/api/v1/push"):
            url += "/loki/api/v1/push"
        _check(self.http.post(url, json=payload, headers=headers), "Loki")


class OtlpHttpSink(HttpSink):
    """
    OpenTelemetry OTLP/HTTP (JSON encoding). Works with an OpenTelemetry Collector and with
    backends that accept OTLP directly (Grafana, Elastic, Dynatrace, New Relic, SigNoz,
    OpenObserve, ...); set vendor auth in `headers`.
    """
    type_name = "otlp_http"

    def validate_settings(self):
        self.require("url")

    def send(self, batch):
        url = self.s["url"].rstrip("/")
        if not url.endswith("/v1/logs"):
            url += "/v1/logs"
        payload = otlp_logs(batch, self.s.get("service_name", "tracelog"), self.s.get("resource_attributes"))
        _check(self.http.post(url, json=payload), "OTLP")


class SentinelSink(HttpSink):
    """Microsoft Sentinel / Azure Monitor Logs Ingestion API (DCE + DCR, Entra ID app credentials)."""
    type_name = "sentinel"

    def validate_settings(self):
        self.require("tenant_id", "client_id", "client_secret", "dce_endpoint", "dcr_immutable_id", "stream_name")
        self._token: Optional[str] = None
        self._token_expiry = 0.0

    def describe_target(self):
        return f"{self.s['dce_endpoint']} stream={self.s['stream_name']}"

    def _bearer(self) -> str:
        if self._token and time.time() < self._token_expiry - 60:
            return self._token
        authority = self.s.get("authority", "https://login.microsoftonline.com").rstrip("/")
        r = self.http.post(f"{authority}/{self.s['tenant_id']}/oauth2/v2.0/token", data={
            "client_id": self.s["client_id"], "client_secret": self.s["client_secret"],
            "grant_type": "client_credentials", "scope": self.s.get("scope", "https://monitor.azure.com//.default")})
        _check(r, "Entra ID token")
        tok = r.json()
        self._token, self._token_expiry = tok["access_token"], time.time() + int(tok.get("expires_in", 3600))
        return self._token

    def send(self, batch):
        rows = []
        for e in batch:
            src, dst = e.get("src_endpoint") or {}, e.get("dst_endpoint") or {}
            rows.append({
                "TimeGenerated": ts_iso(e), "ClassUid": e.get("class_uid"), "ClassName": e.get("class_name"),
                "ActivityName": e.get("activity_name"), "SeverityId": e.get("severity_id"),
                "Severity": e.get("severity"), "SrcIp": src.get("ip"), "SrcPort": src.get("port"),
                "DstIp": dst.get("ip"), "DstPort": dst.get("port"), "UserName": (e.get("user") or {}).get("name"),
                "Action": e.get("action"), "Vendor": (e.get("metadata") or {}).get("product", {}).get("vendor_name"),
                "Product": (e.get("metadata") or {}).get("product", {}).get("name"), "Message": summary(e),
                "Ocsf": e,
            })
        url = (f"{self.s['dce_endpoint'].rstrip('/')}/dataCollectionRules/{self.s['dcr_immutable_id']}"
               f"/streams/{self.s['stream_name']}?api-version={self.s.get('api_version', '2023-01-01')}")
        r = self.http.post(url, content=json.dumps(rows, default=str),
                           headers={"Authorization": f"Bearer {self._bearer()}", "Content-Type": "application/json"})
        if r.status_code == 401:
            self._token = None
        _check(r, "Sentinel")


class WebhookSink(HttpSink):
    """
    Generic HTTPS webhook. `format`: json_array (default), ndjson or single.
    Presets (`preset: datadog | newrelic`) shape the body for those vendors' log intake APIs.
    """
    type_name = "webhook"
    PRESETS = {
        "datadog": "https://http-intake.logs.datadoghq.com/api/v2/logs",
        "newrelic": "https://log-api.newrelic.com/log/v1",
    }

    def validate_settings(self):
        preset = self.s.get("preset") or (self.cfg.type if self.cfg.type in self.PRESETS else None)
        self.s["preset"] = preset
        if preset and not self.s.get("url"):
            self.s["url"] = self.PRESETS[preset]
        self.require("url")
        if preset:
            self.require("api_key")

    def _body(self, batch) -> (Any, Dict[str, str]):
        preset = self.s.get("preset")
        if preset == "datadog":
            return [{"ddsource": "tracelog", "service": self.s.get("service", "tracelog"), "hostname": hostname_of(e),
                     "ddtags": f"ocsf_class:{e.get('class_uid')},severity:{str(e.get('severity', '')).lower()}",
                     "message": json.dumps(e, default=str)} for e in batch], {"DD-API-KEY": self.s["api_key"]}
        if preset == "newrelic":
            return [{"common": {"attributes": {"logtype": "ocsf", "service": "tracelog"}},
                     "logs": [{"timestamp": e.get("time"), "message": summary(e),
                               "attributes": {**key_attributes(e), "ocsf": json.dumps(e, default=str)}}
                              for e in batch]}], {"Api-Key": self.s["api_key"]}
        return batch, {}

    def send(self, batch):
        fmt = self.s.get("format", "json_array")
        body, headers = self._body(batch)
        if self.s.get("bearer_token"):
            headers["Authorization"] = f"Bearer {self.s['bearer_token']}"
        method = self.s.get("method", "POST").upper()
        if self.s.get("preset") or fmt == "json_array":
            r = self.http.request(method, self.s["url"], content=json.dumps(body, default=str),
                                  headers={"Content-Type": "application/json", **headers})
            _check(r, "webhook")
        elif fmt == "ndjson":
            r = self.http.request(method, self.s["url"], content="\n".join(json.dumps(e, default=str) for e in body),
                                  headers={"Content-Type": "application/x-ndjson", **headers})
            _check(r, "webhook")
        else:
            for e in body:
                r = self.http.request(method, self.s["url"], content=json.dumps(e, default=str),
                                      headers={"Content-Type": "application/json", **headers})
                _check(r, "webhook")
