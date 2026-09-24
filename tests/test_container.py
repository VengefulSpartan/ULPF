"""
PS item (k): packaged in a container. The image must not carry secrets, data or history, must
not run as root or carry a compiler, and must run one process that Docker can health-check.
scripts/check_image.sh proves the same on a built image; these tests hold the build files to it.
"""
from pathlib import Path

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
