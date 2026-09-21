"""
Setup guides for connecting log sources to TRACELOG and TRACELOG to downstream tools.

One source of truth for the dashboard's "Connect" tabs and for docs/CONNECTORS.md
(regenerate with `python scripts/generate_connector_docs.py`).

Placeholders filled by `render()`:
  {host}         address of the TRACELOG server as the device or tool sees it
  {syslog_port}  syslog port devices send to (514 with docker-compose, 5514 when run directly)
  {tls_port}     syslog-over-TLS port (6514)
  {api_port}     HTTP port of the TRACELOG API, which also serves the HEC and OTLP receivers (8000)
"""
from typing import Dict, List

DEFAULTS = {"host": "TRACELOG_IP", "syslog_port": "514", "tls_port": "6514", "api_port": "8000"}


def render(text: str, **values: str) -> str:
    vals = {**DEFAULTS, **{k: str(v) for k, v in values.items() if v}}
    for k, v in vals.items():
        text = text.replace("{" + k + "}", v)
    return text


# ---------------------------------------------------------------------------------------------
# Log sources: perimeter devices send syslog straight to TRACELOG
# ---------------------------------------------------------------------------------------------
SOURCES: List[Dict[str, object]] = [
    {
        "key": "paloalto", "name": "Palo Alto Networks (PAN-OS / Panorama)", "pack": "paloalto_panos",
        "transport": "UDP or TCP syslog, BSD or IETF format",
        "steps": [
            "Device > Server Profiles > Syslog > Add a profile named TRACELOG. Server {host}, transport UDP "
            "(or TCP / SSL to port {tls_port}), port {syslog_port}, format BSD, facility LOG_USER.",
            "Objects > Log Forwarding > Add a profile with match lists for Traffic, Threat, URL, WildFire and "
            "Auth, each sending to the TRACELOG syslog profile.",
            "Policies > Security: on each rule set Actions > Log Forwarding to that profile and keep "
            "'Log at Session End' enabled.",
            "Device > Log Settings: send System, Configuration, User-ID and GlobalProtect logs to TRACELOG too.",
            "Commit. With Panorama, do the same in the device-group and template, then push.",
        ],
        "snippet": "", "lang": "",
    },
    {
        "key": "fortinet", "name": "Fortinet FortiGate (FortiOS)", "pack": "fortinet_fortigate",
        "transport": "UDP, or TCP with 'reliable' mode (RFC 6587)",
        "steps": [
            "Run the commands below in the FortiGate CLI (or Log & Report > Log Settings > Remote Logging).",
            "Make sure firewall policies log traffic: Policy & Objects > Firewall Policy > Log Allowed Traffic "
            "= All Sessions (CLI: set logtraffic all).",
        ],
        "snippet": """config log syslogd setting
    set status enable
    set server "{host}"
    set port {syslog_port}
    set mode udp            # "reliable" sends over TCP with RFC 6587 framing
    set format default      # key=value; TRACELOG also reads cef and rfc5424
end
config log syslogd filter
    set severity information
    set forward-traffic enable
    set local-traffic enable
end""", "lang": "bash",
    },
    {
        "key": "cisco_asa", "name": "Cisco ASA", "pack": "cisco_asa",
        "transport": "UDP syslog, or TCP on port 5514 (ASA accepts TCP ports 1025-65535 only)",
        "steps": [
            "Run in configuration mode. Replace 'inside' with the interface that faces TRACELOG.",
            "'logging device-id hostname' puts the firewall's name in every message, so TRACELOG names the "
            "source after the device even behind a relay.",
        ],
        "snippet": """logging enable
logging timestamp
logging device-id hostname
logging trap informational
logging host inside {host} udp/{syslog_port}
! Over TCP instead (ASA allows TCP ports 1025-65535 only, so use TRACELOG's 5514):
!   logging host inside {host} tcp/5514
!   logging permit-hostdown     (without it the ASA blocks new connections while the collector is down)
write memory""", "lang": "text",
    },
    {
        "key": "cisco_ftd", "name": "Cisco Firepower Threat Defense (FTD, managed by FMC)", "pack": "cisco_asa",
        "transport": "UDP or TCP syslog",
        "steps": [
            "FMC > Devices > Platform Settings > edit the FTD policy > Syslog.",
            "Logging Setup: enable logging. Logging Destinations: add Syslog Servers at level Informational.",
            "Syslog Servers: add {host}, protocol UDP (or TCP), port {syslog_port}, and the interface that "
            "reaches TRACELOG. Save and deploy.",
            "Policies > Access Control: on each rule tick 'Log at End of Connection' and send to the syslog server.",
        ],
        "snippet": "", "lang": "",
    },
    {
        "key": "checkpoint", "name": "Check Point Quantum (Log Exporter)", "pack": "checkpoint_log_exporter",
        "transport": "UDP or TCP syslog from the Management / Log Server",
        "steps": [
            "Run in Expert mode on the Security Management Server or the dedicated Log Server.",
            "format 'syslog' is the Log Exporter's [key:\"value\"; ...] layout that TRACELOG parses; "
            "'cef' and 'leef' also work.",
        ],
        "snippet": """cp_log_export add name tracelog target-server {host} target-port {syslog_port} \\
    protocol udp format syslog read-mode semi-unified
cp_log_export restart name tracelog
cp_log_export status name tracelog""", "lang": "bash",
    },
    {
        "key": "juniper", "name": "Juniper SRX (Junos)", "pack": "juniper_srx",
        "transport": "Stream mode syslog from the data plane",
        "steps": [
            "Stream mode sends session logs straight from the data plane. Use an SRX interface address that "
            "can reach TRACELOG as the source address.",
            "Add 'then log session-init / session-close' to every policy you want to see.",
        ],
        "snippet": """set security log mode stream
set security log format sd-syslog
set security log source-address <SRX-INTERFACE-IP>
set security log stream TRACELOG format sd-syslog
set security log stream TRACELOG category all
set security log stream TRACELOG host {host}
set security log stream TRACELOG host port {syslog_port}
set security policies from-zone trust to-zone untrust policy <POLICY> then log session-init
set security policies from-zone trust to-zone untrust policy <POLICY> then log session-close
commit""", "lang": "text",
    },
    {
        "key": "sophos", "name": "Sophos Firewall (SFOS / XG)", "pack": "sophos_firewall",
        "transport": "UDP or TCP syslog",
        "steps": [
            "System services > Log settings > Syslog servers > Add. Name TRACELOG, IP {host}, port "
            "{syslog_port}, facility DAEMON, severity Information, format 'Device standard format' (labelled "
            "'Device standard format (legacy)' from SFOS 20).",
            "Back in Log settings, tick the TRACELOG column for Firewall, IPS, ATP, Anti-virus, Web filter, "
            "SSL VPN / IPsec and Authentication. Apply.",
        ],
        "snippet": "", "lang": "",
    },
    {
        "key": "sonicwall", "name": "SonicWall (SonicOS 6.5 / 7)", "pack": "sonicwall_sonicos",
        "transport": "UDP syslog",
        "steps": [
            "SonicOS 7: Device > Log > Syslog > Syslog Servers > Add (SonicOS 6.5: Manage > Log Settings > "
            "SYSLOG). Server {host}, port {syslog_port}, format Default or Enhanced Syslog.",
            "Device > Log > Settings: logging level Informational, and make sure the Network, Security "
            "Services, VPN and Users categories have Syslog ticked.",
        ],
        "snippet": "", "lang": "",
    },
    {
        "key": "pfsense", "name": "pfSense / OPNsense", "pack": "pfsense_filterlog",
        "transport": "UDP syslog (RFC 3164 or 5424)",
        "steps": [
            "pfSense: Status > System Logs > Settings > Remote Logging Options. Tick 'Send log messages to "
            "remote syslog server', remote server {host}:{syslog_port}, contents 'Firewall Events' (add "
            "System and VPN events if wanted). Save.",
            "OPNsense: System > Settings > Logging, Remote tab > Add. Transport UDP(4), applications "
            "'filterlog' (and others as needed), hostname {host}, port {syslog_port}. Save and Apply.",
            "Enable logging on the firewall rules you care about (the 'Log packets' checkbox).",
        ],
        "snippet": "", "lang": "",
    },
    {
        "key": "suricata", "name": "Suricata IDS/IPS (EVE JSON)", "pack": "suricata_eve",
        "transport": "EVE to local syslog, relayed by rsyslog; or TRACELOG's file input on the sensor",
        "steps": [
            "Point EVE at syslog in suricata.yaml, then relay the local5 facility with rsyslog.",
            "If TRACELOG runs on the sensor itself, tail /var/log/suricata/eve.json with a `files` input instead.",
        ],
        "snippet": """# suricata.yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: syslog
      identity: suricata
      facility: local5
      level: Info
      types: [alert, flow, dns, tls, http, anomaly]

# /etc/rsyslog.d/60-tracelog.conf
local5.* action(type="omfwd" target="{host}" port="{syslog_port}" protocol="tcp" TCP_Framing="octet-counted")""",
        "lang": "yaml",
    },
    {
        "key": "zeek", "name": "Zeek network monitor (JSON logs)", "pack": "zeek_json",
        "transport": "JSON log files, shipped by Fluent Bit / Vector, or TRACELOG's file input",
        "steps": [
            "Turn on JSON logging in local.zeek and redeploy (zeekctl deploy).",
            "Ship /opt/zeek/logs/current/*.log with Fluent Bit or Vector (see Forwarders), or run a TRACELOG "
            "`files` input on the sensor.",
        ],
        "snippet": """# /opt/zeek/share/zeek/site/local.zeek
@load policy/tuning/json-logs.zeek""", "lang": "text",
    },
    {
        "key": "snort", "name": "Snort 2 / Snort 3", "pack": "snort_alert",
        "transport": "Alerts to local syslog, relayed by rsyslog",
        "steps": ["Send alerts to syslog, then relay local5 with rsyslog exactly as for Suricata."],
        "snippet": """# Snort 2 (snort.conf)
output alert_syslog: LOG_LOCAL5 LOG_ALERT

-- Snort 3 (snort.lua)
alert_syslog = { facility = 'local5', level = 'alert' }""", "lang": "text",
    },
    {
        "key": "generic", "name": "Any other device (CEF, LEEF, RFC 3164/5424, key=value, JSON)", "pack": "generic",
        "transport": "UDP, TCP or TLS syslog",
        "steps": [
            "Point the device's syslog at {host}:{syslog_port} (UDP/TCP) or {host}:{tls_port} (TLS).",
            "Every line is archived byte-for-byte and hash-chained even when no pack recognises it; CEF and LEEF "
            "headers are mapped automatically, and Parser Studio builds a pack for anything else.",
        ],
        "snippet": "", "lang": "",
    },
]


# ---------------------------------------------------------------------------------------------
# Forwarders and collectors companies already run in front of their SIEM
# ---------------------------------------------------------------------------------------------
FORWARDERS: List[Dict[str, object]] = [
    {
        "key": "rsyslog", "name": "rsyslog relay",
        "steps": ["Forward everything the relay receives. The disk queue holds logs while TRACELOG is unreachable."],
        "snippet": """# /etc/rsyslog.d/60-tracelog.conf
*.* action(type="omfwd" target="{host}" port="{syslog_port}" protocol="tcp" TCP_Framing="octet-counted"
           queue.type="LinkedList" queue.filename="tracelog_fwd" queue.saveOnShutdown="on"
           action.resumeRetryCount="-1")""", "lang": "text",
    },
    {
        "key": "syslog-ng", "name": "syslog-ng relay",
        "steps": ["syslog() sends RFC 5424 with octet counting; network() sends BSD lines. TRACELOG accepts both."],
        "snippet": """destination d_tracelog { syslog("{host}" transport("tcp") port({syslog_port})); };
log { source(s_net); destination(d_tracelog); };""", "lang": "text",
    },
    {
        "key": "fluent-bit", "name": "Fluent Bit (Splunk HEC output)",
        "steps": ["TRACELOG's HEC receiver takes Fluent Bit's splunk output unchanged. Event_Key $log sends the "
                  "original line rather than a wrapper object."],
        "snippet": """[INPUT]
    Name   tail
    Path   /var/log/suricata/eve.json
    Tag    suricata

[OUTPUT]
    Name          splunk
    Match         *
    Host          {host}
    Port          {api_port}
    TLS           Off
    Splunk_Token  ${TRACELOG_HEC_TOKEN}
    Event_Key     $log""", "lang": "ini",
    },
    {
        "key": "vector", "name": "Vector (Splunk HEC sink)",
        "steps": ["A socket source keeps each device line exactly as sent, which the hash chain relies on."],
        "snippet": """sources:
  devices:
    type: socket
    mode: udp
    address: 0.0.0.0:514
sinks:
  tracelog:
    type: splunk_hec_logs
    inputs: [devices]
    endpoint: http://{host}:{api_port}
    default_token: ${TRACELOG_HEC_TOKEN}
    encoding:
      codec: text""", "lang": "yaml",
    },
    {
        "key": "otel", "name": "OpenTelemetry Collector (OTLP/HTTP)",
        "steps": ["Use JSON encoding on the OTLP/HTTP exporter; gzip compression (the default) is accepted. "
                  "Collectors older than the component renames call these udplog and otlphttp."],
        "snippet": """receivers:
  udp_log:
    listen_address: 0.0.0.0:514
exporters:
  otlp_http/tracelog:
    logs_endpoint: http://{host}:{api_port}/v1/logs
    encoding: json
    headers:
      Authorization: "Bearer ${env:TRACELOG_HEC_TOKEN}"
service:
  pipelines:
    logs:
      receivers: [udp_log]
      exporters: [otlp_http/tracelog]""", "lang": "yaml",
    },
    {
        "key": "logstash", "name": "Logstash (http output)",
        "steps": ["message_field=message takes the original line out of each Logstash event; host.name "
                  "becomes the device name."],
        "snippet": """output {
  http {
    url         => "http://{host}:{api_port}/api/ingest/stream?message_field=message"
    http_method => "post"
    format      => "json_batch"
    headers     => { "Authorization" => "Bearer ${TRACELOG_HEC_TOKEN}" }
  }
}""", "lang": "ruby",
    },
    {
        "key": "cribl", "name": "Cribl Stream / Edge",
        "steps": ["Add a Splunk HEC destination with URL http://{host}:{api_port}/services/collector/event and "
                  "the TRACELOG token. Events carrying _raw are unwrapped to the original line."],
        "snippet": "", "lang": "",
    },
    {
        "key": "kafka", "name": "Kafka topic",
        "steps": ["Add a `kafka` input in config/tracelog.yaml (bootstrap_servers, topics, group_id). "
                  "Filebeat and Logstash can publish raw lines to that topic."],
        "snippet": "", "lang": "",
    },
]


# ---------------------------------------------------------------------------------------------
# Destinations: what to set up on the receiving side, and the TRACELOG output block
# ---------------------------------------------------------------------------------------------
DESTINATIONS: List[Dict[str, object]] = [
    {
        "key": "splunk", "name": "Splunk Enterprise / Splunk Cloud / Splunk ES", "type": "splunk_hec",
        "steps": [
            "Settings > Data inputs > HTTP Event Collector > Global Settings: enable HEC.",
            "New Token: name tracelog, source type ocsf:tracelog (or _json), pick the index. Copy the token.",
            "Export it on the TRACELOG host as SPLUNK_HEC_TOKEN and add the output below.",
        ],
        "config": """- name: splunk
  type: splunk_hec
  url: https://splunk.example.internal:8088
  token: ${SPLUNK_HEC_TOKEN}
  index: perimeter
  sourcetype: ocsf:tracelog""",
    },
    {
        "key": "sentinel", "name": "Microsoft Sentinel (Logs Ingestion API)", "type": "sentinel",
        "steps": [
            "Create a Data Collection Endpoint (DCE) in the workspace's region.",
            "Log Analytics workspace > Tables > Create > New custom log (DCR-based): table TracelogOCSF_CL, "
            "new DCR, and a sample from data/export/*.ndjson for the schema.",
            "Entra ID > App registrations > New app; create a client secret.",
            "On the DCR, grant that app the 'Monitoring Metrics Publisher' role.",
            "Copy the DCE logs ingestion URI and the DCR immutable ID into the output below. Secrets come from the "
            "environment.",
        ],
        "config": """- name: sentinel
  type: sentinel
  tenant_id: ${AZURE_TENANT_ID}
  client_id: ${AZURE_CLIENT_ID}
  client_secret: ${AZURE_CLIENT_SECRET}
  dce_endpoint: https://my-dce.centralindia-1.ingest.monitor.azure.com
  dcr_immutable_id: dcr-00000000000000000000000000000000
  stream_name: Custom-TracelogOCSF_CL""",
    },
    {
        "key": "qradar", "name": "IBM QRadar", "type": "syslog (leef)",
        "steps": [
            "Admin > Log Sources > Add: type 'Universal LEEF', protocol Syslog, identifier = the TRACELOG "
            "host's name or IP.",
            "Deploy changes. Events arrive as LEEF 2.0 with OCSF field names as attributes.",
        ],
        "config": """- name: qradar
  type: syslog
  host: qradar.example.internal
  port: 514
  protocol: tcp
  format: leef""",
    },
    {
        "key": "elastic", "name": "Elastic Security / Elasticsearch", "type": "elasticsearch",
        "steps": [
            "Create an API key (or user) allowed to create_doc and create_index on tracelog-ocsf-*.",
            "In Kibana, create a data view for tracelog-ocsf-* with time field @timestamp.",
        ],
        "config": """- name: elastic
  type: elasticsearch
  url: https://elastic.example.internal:9200
  index: tracelog-ocsf-%Y.%m.%d
  api_key: ${ELASTIC_API_KEY}
  ca_file: /etc/tracelog/tls/elastic-ca.crt""",
    },
    {
        "key": "wazuh", "name": "Wazuh (indexer or manager)", "type": "wazuh_indexer / syslog (json)",
        "steps": [
            "Indexer: use the output below, then add an index pattern tracelog-ocsf-* in the Wazuh dashboard.",
            "Manager (to run Wazuh rules): add a syslog remote block to /var/ossec/etc/ossec.conf, restart the "
            "manager, and use a syslog output with format json.",
        ],
        "config": """- name: wazuh
  type: wazuh_indexer
  url: https://wazuh-indexer.example.internal:9200
  index: tracelog-ocsf-%Y.%m.%d
  username: tracelog
  password: ${WAZUH_INDEXER_PASSWORD}

# ossec.conf on the Wazuh manager, for the syslog/json route:
# <remote>
#   <connection>syslog</connection>
#   <port>514</port>
#   <protocol>tcp</protocol>
#   <allowed-ips>TRACELOG_IP</allowed-ips>
# </remote>""",
    },
    {
        "key": "opensearch", "name": "OpenSearch / Amazon OpenSearch Service", "type": "opensearch",
        "steps": ["Create a user or role with write access to tracelog-ocsf-*, then an index pattern in Dashboards."],
        "config": """- name: opensearch
  type: opensearch
  url: https://opensearch.example.internal:9200
  index: tracelog-ocsf-%Y.%m.%d
  username: tracelog
  password: ${OPENSEARCH_PASSWORD}""",
    },
    {
        "key": "arcsight", "name": "ArcSight, LogRhythm / Exabeam, Securonix and other CEF SIEMs",
        "type": "syslog (cef)",
        "steps": ["Create a syslog (CEF) listener on the SIEM or its SmartConnector, then add the output below."],
        "config": """- name: arcsight
  type: syslog
  host: siem.example.internal
  port: 6514
  protocol: tls
  format: cef
  ca_file: /etc/tracelog/tls/siem-ca.crt""",
    },
    {
        "key": "graylog", "name": "Graylog", "type": "gelf",
        "steps": ["System > Inputs > launch a GELF TCP (or GELF UDP) input on port 12201."],
        "config": """- name: graylog
  type: gelf
  host: graylog.example.internal
  port: 12201
  protocol: tcp""",
    },
    {
        "key": "grafana", "name": "Grafana Loki / Grafana", "type": "loki",
        "steps": ["Add Loki as a Grafana data source, then query {job=\"tracelog\"} in Explore. Stream labels: "
                  "job, ocsf_class, vendor, severity."],
        "config": """- name: loki
  type: loki
  url: http://loki.example.internal:3100
  tenant: perimeter""",
    },
    {
        "key": "otlp", "name": "OpenTelemetry Collector and OTLP backends (Dynatrace, SigNoz, Grafana Cloud, "
                               "Honeycomb, OpenObserve)", "type": "otlp_http",
        "steps": ["Point at a Collector's OTLP/HTTP receiver (port 4318), or straight at an OTLP backend with its "
                  "API header. A Collector can then fan out to Google SecOps, CloudWatch, Azure Monitor and more."],
        "config": """- name: otel
  type: otlp_http
  url: http://otel-collector.example.internal:4318
  headers: {}""",
    },
    {
        "key": "datadog", "name": "Datadog Logs", "type": "datadog",
        "steps": ["Organization Settings > API Keys: create a key and export it as DD_API_KEY. Set url for "
                  "non-US1 sites."],
        "config": """- name: datadog
  type: datadog
  api_key: ${DD_API_KEY}
  # url: https://http-intake.logs.datadoghq.eu/api/v2/logs""",
    },
    {
        "key": "newrelic", "name": "New Relic Logs", "type": "newrelic",
        "steps": ["Use an ingest licence key exported as NEW_RELIC_LICENSE_KEY (EU accounts: set url to the EU "
                  "Log API)."],
        "config": """- name: newrelic
  type: newrelic
  api_key: ${NEW_RELIC_LICENSE_KEY}""",
    },
    {
        "key": "soar", "name": "SOAR and custom HTTPS endpoints (webhook)", "type": "webhook",
        "steps": ["Send only high-severity findings to automation with a filter."],
        "config": """- name: soar
  type: webhook
  url: https://soar.example.internal/hooks/tracelog
  bearer_token: ${SOAR_TOKEN}
  format: json_array
  filter: {classes: [2004], min_severity_id: 4}""",
    },
    {
        "key": "lake", "name": "Data lakes and air-gapped hand-off (NDJSON, Parquet, Kafka)",
        "type": "file / parquet / kafka",
        "steps": [
            "NDJSON files work with no other software and can be moved on removable media.",
            "Parquet is partitioned by class_uid and event_day for Athena, Trino, Spark, DuckDB and Amazon "
            "Security Lake custom sources (needs pyarrow).",
        ],
        "config": """- name: ocsf-archive
  type: file
  path: data/export/ocsf-%Y-%m-%d.ndjson

- name: data-lake
  type: parquet
  root: data/lake""",
    },
]
