import yaml
import pytest
import random
from typing import List

from core.miner.template_miner import TemplateMinerWrapper
from core.inference.profiler import VariableProfiler
from core.mapper.ocsf_mapper import OCSFMapper


def generate_unseen_firewall_logs(count: int = 200) -> List[str]:
    """Generate sample lines for an unseen free-text firewall log format.
    Format: '2026-09-15T12:00:00Z [FIREWALL-EDGE-99] Connection from <src_ip>:<src_port> to <dst_ip>:<dst_port> status <action> bytes <bytes>'
    """
    actions = ["ALLOW", "DENY", "DROP", "ACCEPT", "BLOCK"]
    logs = []
    
    for i in range(count):
        ts = f"2026-09-15T18:{i//60:02d}:{i%60:02d}Z"
        src_ip = f"172.16.10.{10 + (i % 50)}"
        dst_ip = f"198.51.100.{1 + (i % 20)}"
        src_port = 40000 + (i % 1000)
        dst_port = 443 if i % 2 == 0 else 80
        act = actions[i % len(actions)]
        bytes_sent = 100 + (i * 15)
        
        line = f"{ts} [FIREWALL-EDGE-99] Connection from {src_ip}:{src_port} to {dst_ip}:{dst_port} status {act} bytes {bytes_sent}"
        logs.append(line)
        
    return logs


def test_zero_touch_parser_engine_unseen_logs(capsys):
    """Test zero-touch parsing engine on 200 unseen free-text firewall log lines."""
    raw_logs = generate_unseen_firewall_logs(200)

    miner = TemplateMinerWrapper()
    profiler = VariableProfiler()
    mapper = OCSFMapper()

    extracted_variables_list = []
    mined_template = None

    for line in raw_logs:
        res = miner.process_line(line)
        mined_template = res["template_mined"]
        if res["extracted_variables"]:
            extracted_variables_list.append(res["extracted_variables"])

    assert mined_template is not None, "Failed to mine template from log lines"
    assert len(extracted_variables_list) >= 190, f"Expected at least 190 extracted tuples, got {len(extracted_variables_list)}"

    # Profile variable positions across sample window
    slot_profiles = profiler.profile_variable_positions(extracted_variables_list)
    assert len(slot_profiles) >= 5, "Expected at least 5 variable slots in template"

    # Map slot profiles to OCSF schema
    ocsf_mappings = mapper.map_slots_to_ocsf(mined_template, slot_profiles)

    # Generate and emit draft plugin YAML
    draft_plugin = mapper.generate_draft_plugin(
        parser_id="plugin_unseen_firewall_v1",
        template_mined=mined_template,
        field_mappings=ocsf_mappings
    )
    plugin_yaml = mapper.emit_plugin_yaml(draft_plugin)

    print("\n" + "=" * 75)
    print(f"{'EMITTED DRAFT OCSF PARSER PLUGIN YAML':^75}")
    print("=" * 75)
    print(plugin_yaml)
    print("=" * 75)

    # Parse output YAML to verify structure
    parsed_yaml = yaml.safe_load(plugin_yaml)
    assert parsed_yaml["parser_id"] == "plugin_unseen_firewall_v1"
    assert parsed_yaml["status"] == "draft_suggested"

    # Map mapped fields to dict for assertions
    mapped_ocsf_fields = {m["ocsf_field"]: m["confidence"] for m in ocsf_mappings}

    # Assert draft mapping covers src ip, dst ip, ports, action, and timestamp with confidence > 0.70
    assert "time" in mapped_ocsf_fields, "Missing 'time' mapping in draft plugin"
    assert mapped_ocsf_fields["time"] > 0.70, f"Low confidence for 'time': {mapped_ocsf_fields['time']}"

    assert "src_endpoint.ip" in mapped_ocsf_fields, "Missing 'src_endpoint.ip' mapping in draft plugin"
    assert mapped_ocsf_fields["src_endpoint.ip"] > 0.70, f"Low confidence for 'src_endpoint.ip': {mapped_ocsf_fields['src_endpoint.ip']}"

    assert "dst_endpoint.ip" in mapped_ocsf_fields, "Missing 'dst_endpoint.ip' mapping in draft plugin"
    assert mapped_ocsf_fields["dst_endpoint.ip"] > 0.70, f"Low confidence for 'dst_endpoint.ip': {mapped_ocsf_fields['dst_endpoint.ip']}"

    assert "src_endpoint.port" in mapped_ocsf_fields or "dst_endpoint.port" in mapped_ocsf_fields, "Missing port mapping in draft plugin"
    if "src_endpoint.port" in mapped_ocsf_fields:
        assert mapped_ocsf_fields["src_endpoint.port"] > 0.70
    if "dst_endpoint.port" in mapped_ocsf_fields:
        assert mapped_ocsf_fields["dst_endpoint.port"] > 0.70

    assert "disposition" in mapped_ocsf_fields, "Missing 'disposition' (action) mapping in draft plugin"
    assert mapped_ocsf_fields["disposition"] > 0.70, f"Low confidence for 'disposition': {mapped_ocsf_fields['disposition']}"
