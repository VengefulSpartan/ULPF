import subprocess
import sys
import time
import os
import socket

# numpy's BLAS: one thread per process (backend/services/ml/__init__.py says why); both children inherit it
for _name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ.setdefault(_name, "1")


def get_lan_ip():
    """This machine's address on the LAN. Connecting a UDP socket sends no packet: it only asks the OS which
    interface it would use, so this works air-gapped too (10.255.255.255 is never actually contacted)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def main():
    # --lan: listen on every interface so other machines on the network can open the dashboard and the API.
    # Off by default: the API has no login, so anyone who can reach the port can upload logs, approve parsers
    # and reset the database. Use it on a network you trust (a demo room, your own LAN), not on public Wi-Fi.
    lan = "--lan" in sys.argv[1:]
    bind = "0.0.0.0" if lan else "127.0.0.1"
    lan_ip = get_lan_ip() if lan else None

    print("=" * 65)
    print("  TRACELOG — Universal Log Pre-processing Framework")
    print("=" * 65)
    # Two witnesses that countersign the collector's checkpoints (backend/witness.py). On one laptop they run
    # here, each with its own keys and records under data/; in production each runs on another machine.
    witnesses = []
    backend_env = dict(os.environ)
    if "--no-witnesses" not in sys.argv[1:] and not os.environ.get("WITNESS_URLS"):
        urls = []
        for i, port in ((1, 8101), (2, 8102)):
            env = dict(os.environ, WITNESS_ID=f"witness-{i}", WITNESS_DATA_DIR=os.path.join("data", f"witness-{i}"))
            witnesses.append(subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "backend.witness:app", "--host", "127.0.0.1", "--port", str(port),
                 "--log-level", "warning"], env=env))
            urls.append(f"http://127.0.0.1:{port}")
        backend_env["WITNESS_URLS"] = ",".join(urls)
        print(f"[*] Started 2 checkpoint witnesses on {', '.join(urls)} (python run_app.py --no-witnesses to skip)")

    print(f"[*] Starting FastAPI Backend on {bind}:8000 ...")
    print("    - Local API:   http://localhost:8000 (Docs: http://localhost:8000/docs)")
    if lan:
        print(f"    - Network API: http://{lan_ip}:8000 (Docs: http://{lan_ip}:8000/docs)")
    backend_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.main:app", "--host", bind, "--port", "8000"], env=backend_env
    )
    time.sleep(2)

    print(f"[*] Starting Streamlit Dashboard on {bind}:8501 ...")
    print("    - Local UI:    http://localhost:8501")
    if lan:
        print(f"    - Network UI:  http://{lan_ip}:8501")
    frontend_proc = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", "frontend/app.py", "--server.port", "8501", "--server.address", bind],
        env=backend_env   # the Settings page lists the witnesses, and runs the backend itself if the API is down
    )

    if lan:
        print("[+] Both services running, reachable from your LAN (no login: use a network you trust).")
    else:
        print("[+] Both services running on this machine only (python run_app.py --lan to share them on your LAN).")
    print("    Press Ctrl+C to terminate.")
    try:
        backend_proc.wait()
        frontend_proc.wait()
    except KeyboardInterrupt:
        print("\n[*] Shutting down TRACELOG...")
        backend_proc.terminate()
        frontend_proc.terminate()
        for w in witnesses:
            w.terminate()
        print("[+] Goodbye.")


if __name__ == "__main__":
    main()
