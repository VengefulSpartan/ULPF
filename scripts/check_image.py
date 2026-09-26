#!/usr/bin/env python3
"""
Build the TRACELOG image and check what went into it and how it runs.

    python scripts/check_image.py                 # builds tracelog:latest
    python scripts/check_image.py my/tag:1.0
    sh scripts/check_image.sh                     # the same, for existing instructions

Fails (exit 1) if the image holds a secret, a database, version control, tests, measurement
results or a compiler; if it runs as root or its code is writable by the service; if the
libraries the Parquet output and the analytics need are missing; or if the API does not come up
healthy with no network at all, serving Swagger UI from the image and the ML contract.

It is Python rather than shell so that it runs the same from Linux, macOS, WSL or a Windows
PowerShell with Docker Desktop. The checks inside the container are shell, because the container
is always Linux.
"""
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = ["/app/.env", "/app/.git", "/app/data/ulpf.db", "/app/tests", "/app/.venv", "/app/venv",
             "/app/Project outputs", "/app/results", "/app/docs"]
INSIDE = r'''
fail=0
uid=$(id -u)
if [ "$uid" = "0" ]; then echo "FAIL runs as root"; fail=1; else echo "ok   runs as uid $uid, not root"; fi
missing=1
for p in %s; do
  if [ -e "$p" ]; then echo "FAIL found $p"; fail=1; missing=0; fi
done
[ "$missing" = "1" ] && echo "ok   no .env, .git, database, tests, docs, venv, results or notes in the image"
if command -v gcc >/dev/null 2>&1 || command -v cc >/dev/null 2>&1; then echo "FAIL compiler in the runtime image"; fail=1
else echo "ok   no compiler in the runtime image"; fi
if touch /app/backend/x 2>/dev/null; then echo "FAIL code is writable by the service"; fail=1
else echo "ok   code is read-only to the service"; fi
if python -c "import pyarrow, pandas, numpy" 2>/dev/null; then echo "ok   pyarrow, pandas and numpy present: Parquet output and analytics work"
else echo "FAIL pyarrow, pandas or numpy missing"; fail=1; fi
exit $fail
''' % " ".join(f'"{p}"' for p in FORBIDDEN)
PROBE = r'''
import json, urllib.request as u
html = u.urlopen("http://127.0.0.1:8000/docs").read().decode()
assert "cdn." not in html and "/static/swagger-ui/swagger-ui-bundle.js" in html
u.urlopen("http://127.0.0.1:8000/static/swagger-ui/swagger-ui-bundle.js")
print("ok   /docs serves Swagger UI from the image, not a CDN")
cols = json.loads(u.urlopen("http://127.0.0.1:8000/api/ml/contract").read())["columns"]
print(f"ok   /api/ml/contract answers with {len(cols)} columns")
'''


def docker(*args, check=True, capture=True):
    p = subprocess.run(["docker", *args], cwd=ROOT, text=True, capture_output=capture)
    if check and p.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args[:2])} failed: {(p.stderr or '').strip()[-500:]}")
    return p


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    image = args[0] if args else "tracelog:latest"
    t0 = time.perf_counter()
    if subprocess.run(["docker", "build", "-t", image, "."], cwd=ROOT).returncode != 0:
        print("FAIL the image did not build")
        return 1
    print(f"ok   built {image} in {time.perf_counter() - t0:.0f} s")

    print("--- what is inside")
    inside = docker("run", "--rm", "--network", "none", "--entrypoint", "sh", image, "-c", INSIDE, check=False)
    print(inside.stdout.rstrip())
    failed = inside.returncode != 0

    print("--- starts with no network, and reports healthy")
    cid = docker("run", "-d", "--network", "none", "--read-only", "--tmpfs", "/tmp", "--tmpfs", "/home/tracelog",
                 "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", image).stdout.strip()
    try:
        status = "starting"
        for _ in range(45):
            status = docker("inspect", "-f", "{{.State.Health.Status}}", cid).stdout.strip()
            if status == "healthy":
                break
            time.sleep(2)
        if status == "healthy":
            print("ok   API healthy with --network none, a read-only root and no capabilities")
            probe = docker("exec", cid, "python", "-c", PROBE, check=False)
            print(probe.stdout.rstrip())
            if probe.returncode != 0:
                print("FAIL the running API did not answer as expected")
                print(probe.stderr.strip()[-800:])
                failed = True
        else:
            print(f"FAIL health: {status}")
            logs = docker("logs", cid, check=False)
            print(((logs.stdout or "") + (logs.stderr or ""))[-2000:])
            failed = True
    finally:
        docker("rm", "-f", cid, check=False)

    print("--- image size")
    size = int(docker("image", "inspect", "-f", "{{.Size}}", image).stdout.strip())
    print(f"{size / 1000 / 1000:.0f} MB")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
