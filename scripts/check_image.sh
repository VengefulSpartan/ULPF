#!/bin/sh
# Build the TRACELOG image and check what went into it and how it runs.
#
#   sh scripts/check_image.sh              # builds tracelog:latest
#   sh scripts/check_image.sh my/tag:1.0
#
# Fails (exit 1) if the image holds a secret, a database, version control, tests or a compiler,
# if it runs as root, or if the API does not come up healthy with no network at all.
set -eu
IMAGE="${1:-tracelog:latest}"

docker build -t "$IMAGE" .

echo "--- what is inside"
docker run --rm --network none --entrypoint sh "$IMAGE" -c '
  fail=0
  uid=$(id -u)
  if [ "$uid" = "0" ]; then echo "FAIL runs as root"; fail=1; else echo "ok   runs as uid $uid, not root"; fi
  for p in /app/.env /app/.git /app/data/ulpf.db /app/tests /app/.venv /app/venv "/app/Claude outputs"; do
    if [ -e "$p" ]; then echo "FAIL found $p"; fail=1; fi
  done
  [ "$fail" = "0" ] && echo "ok   no .env, .git, database, tests, venv or notes in the image"
  if command -v gcc >/dev/null 2>&1 || command -v cc >/dev/null 2>&1; then echo "FAIL compiler in the runtime image"; fail=1
  else echo "ok   no compiler in the runtime image"; fi
  if touch /app/backend/x 2>/dev/null; then echo "FAIL code is writable by the service"; fail=1
  else echo "ok   code is read-only to the service"; fi
  exit $fail'

echo "--- starts with no network, and reports healthy"
cid=$(docker run -d --network none --read-only --tmpfs /tmp --tmpfs /home/tracelog \
      --cap-drop ALL --security-opt no-new-privileges:true "$IMAGE")
trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
status=starting
for _ in $(seq 1 30); do
  status=$(docker inspect -f '{{.State.Health.Status}}' "$cid")
  [ "$status" = "healthy" ] && break
  sleep 2
done
if [ "$status" = "healthy" ]; then echo "ok   API healthy with --network none, a read-only root and no capabilities"
else echo "FAIL health: $status"; docker logs "$cid" | tail -20; exit 1; fi
docker exec "$cid" python -c "
import urllib.request as u
html = u.urlopen('http://127.0.0.1:8000/docs').read().decode()
assert 'cdn.' not in html and '/static/swagger-ui/swagger-ui-bundle.js' in html
u.urlopen('http://127.0.0.1:8000/static/swagger-ui/swagger-ui-bundle.js')
print('ok   /docs serves Swagger UI from the image, not a CDN')"
echo "--- image size"
docker image inspect -f '{{.Size}}' "$IMAGE" | awk '{printf "%.0f MB\n", $1/1000/1000}'
