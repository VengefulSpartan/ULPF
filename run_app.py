import subprocess
import sys
import time
import os
import socket

def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def main():
    lan_ip = get_lan_ip()
    print("=" * 65)
    print("  TRACELOG — Universal Log Pre-processing Framework")
    print("=" * 65)
    print(f"[*] Starting FastAPI Backend on 0.0.0.0:8000 ...")
    print(f"    - Local API:   http://localhost:8000 (Docs: http://localhost:8000/docs)")
    print(f"    - Network API: http://{lan_ip}:8000 (Docs: http://{lan_ip}:8000/docs)")
    backend_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
    )
    time.sleep(2)

    print(f"[*] Starting Streamlit Dashboard on 0.0.0.0:8501 ...")
    print(f"    - Local UI:    http://localhost:8501")
    print(f"    - Network UI:  http://{lan_ip}:8501")
    frontend_proc = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", "frontend/app.py", "--server.port", "8501", "--server.address", "0.0.0.0"]
    )

    print("[+] Both services hosted! Accessible across your LAN.")
    print("    Press Ctrl+C to terminate.")
    try:
        backend_proc.wait()
        frontend_proc.wait()
    except KeyboardInterrupt:
        print("\n[*] Shutting down TRACELOG...")
        backend_proc.terminate()
        frontend_proc.terminate()
        print("[+] Goodbye.")

if __name__ == "__main__":
    main()
