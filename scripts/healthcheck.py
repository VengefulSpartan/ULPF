"""
Container health check: healthy when the process this container runs answers.

The image runs one process per container, either the API (port 8000) or the dashboard (8501),
so the check asks both and succeeds if either answers. Standard library only, so the runtime
image needs no curl.
"""
import sys
import urllib.request

ENDPOINTS = ("http://127.0.0.1:8000/health", "http://127.0.0.1:8501/_stcore/health")


def main() -> int:
    for url in ENDPOINTS:
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                if response.status == 200:
                    return 0
        except OSError:
            continue
    return 1


if __name__ == "__main__":
    sys.exit(main())
