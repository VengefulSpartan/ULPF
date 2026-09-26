"""
PS item (k): packaged in a container. The image must not carry secrets, data or history, must
not run as root or carry a compiler, and must run one process that Docker can health-check.
scripts/check_image.py proves the same on a built image; these tests hold the build files to it.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_the_image_leaves_out_secrets_data_and_history():
    ignored = {l.strip() for l in (ROOT / ".dockerignore").read_text().splitlines()
               if l.strip() and not l.startswith("#")}
    assert {".env", ".env.*", "data/*", ".git/", ".venv/", "venv/", "tests/"} <= ignored
    dockerfile = (ROOT / "Dockerfile").read_text()
    runtime = dockerfile.split("\nFROM ")[-1]           # the stage that becomes the image
    assert "\nUSER tracelog" in runtime and "build-essential" not in runtime
    assert "HEALTHCHECK" in runtime and " & " not in runtime  # one process, and docker knows its health


def test_compose_runs_each_process_unprivileged_and_read_only():
    import yaml
    services = yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"]
    assert set(services) == {"tracelog-backend", "tracelog-frontend"}
    for name, svc in services.items():
        assert svc["read_only"] is True and svc["cap_drop"] == ["ALL"], name
        assert "no-new-privileges:true" in svc["security_opt"], name
        assert "&" not in " ".join(svc["command"]), name
    assert services["tracelog-frontend"]["depends_on"]["tracelog-backend"]["condition"] == "service_healthy"


def test_the_image_has_what_the_parquet_output_and_the_analytics_need():
    reqs = [l.split("#")[0].strip() for l in (ROOT / "requirements.txt").read_text().splitlines()]
    assert any(r.startswith("pyarrow") for r in reqs)           # not commented out: the image installs it
    assert any(r.startswith("pandas") for r in reqs)


def test_the_build_context_leaves_out_measurement_results_and_has_no_inline_comments():
    lines = [l.strip() for l in (ROOT / ".dockerignore").read_text().splitlines() if l.strip()]
    patterns = [l for l in lines if not l.startswith("#")]
    assert "results/" in patterns
    # .dockerignore has no inline comments: "results/  # x" would be a pattern that matches nothing
    assert not [p for p in patterns if "#" in p]


def test_compose_passes_the_settings_through():
    import yaml
    backend = yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"]["tracelog-backend"]
    env = dict(e.split("=", 1) for e in backend["environment"])
    assert env["BASELINE_EVERY_MINUTES"] == "${BASELINE_EVERY_MINUTES:-0}"
    assert env["SEARCH_INDEX"] == "${SEARCH_INDEX:-true}" and env["OCSF_VERSION"] == "${OCSF_VERSION:-1.1.0}"


def test_the_live_sensor_sees_the_web_server_on_every_docker_platform():
    import yaml
    compose = yaml.safe_load((ROOT / "docker-compose.devices.yml").read_text())
    services = compose["services"]
    assert "version" not in compose                              # obsolete key; compose warns about it
    assert all(s.get("network_mode") != "host" for s in services.values())
    suricata = services["suricata"]
    assert suricata["network_mode"] == "service:target-web"     # the server's own eth0, on any host OS
    assert "./config/suricata:/etc/suricata/tracelog:ro" in suricata["volumes"]
    rules_in_container = suricata["command"][suricata["command"].index("-S") + 1]
    assert rules_in_container == "/etc/suricata/tracelog/tracelog-demo.rules"
    assert "suricata" in services["traffic-generator"]["depends_on"]


def test_the_demo_rules_load_and_each_has_its_own_id():
    import re
    import shutil
    import subprocess
    rules = ROOT / "config" / "suricata" / "tracelog-demo.rules"
    text = [l for l in rules.read_text().splitlines() if l.startswith("alert")]
    sids = re.findall(r"sid:(\d+);", "\n".join(text))
    assert len(text) == 4 and len(set(sids)) == 4
    if shutil.which("suricata"):                                 # checked with Suricata itself where installed
        import tempfile
        with tempfile.TemporaryDirectory() as logs:
            p = subprocess.run(["suricata", "-T", "-S", str(rules), "-l", logs], capture_output=True, text=True)
        assert p.returncode == 0, p.stdout + p.stderr


FAKE_DOCKER = r"""#!/bin/sh
case "$1 $2" in
  "build -t") exit 0 ;;
  "run --rm") echo "ok   runs as uid 10001, not root"; echo "ok   no compiler in the runtime image"
              [ -n "$FAKE_FAIL_INSIDE" ] && { echo "FAIL found /app/results"; exit 1; }; exit 0 ;;
  "run -d") echo "c0ffee" ;;
  "inspect -f") echo "healthy" ;;
  "exec c0ffee") echo "ok   /docs serves Swagger UI from the image, not a CDN"
                 echo "ok   /api/ml/contract answers with 41 columns" ;;
  "rm -f") exit 0 ;;
  "image inspect") echo "412345678" ;;
  *) echo "unexpected: $*" >&2; exit 2 ;;
esac
"""


def _check_image(tmp_path, **env):
    import os
    import subprocess
    fake = tmp_path / "docker"
    fake.write_text(FAKE_DOCKER)
    fake.chmod(0o755)
    return subprocess.run([sys.executable, str(ROOT / "scripts" / "check_image.py"), "tracelog:test"],
                          capture_output=True, text=True,
                          env={**os.environ, "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}", **env})


@pytest.mark.skipif(sys.platform == "win32", reason="the stand-in for docker is a shell script")
def test_the_image_check_reports_every_step_and_the_size(tmp_path):
    """Docker stands in for itself here: a script answers each docker command the check makes, so
    the check's own logic (what it runs, what it prints, when it fails) is tested without an image."""
    p = _check_image(tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
    for line in ("ok   built tracelog:test", "ok   API healthy with --network none", "ok   /api/ml/contract",
                 "412 MB"):
        assert line in p.stdout
    failing = _check_image(tmp_path, FAKE_FAIL_INSIDE="1")
    assert failing.returncode == 1 and "FAIL found /app/results" in failing.stdout
