#!/bin/sh
# Build the TRACELOG image and check what went into it and how it runs:
#
#   sh scripts/check_image.sh              # builds tracelog:latest
#   sh scripts/check_image.sh my/tag:1.0
#
# The checks live in scripts/check_image.py, so they also run from PowerShell on Windows
# (python scripts\check_image.py). This wrapper keeps the old command working.
set -eu
PY=$(command -v python3 || command -v python)
exec "$PY" "$(dirname "$0")/check_image.py" "$@"
