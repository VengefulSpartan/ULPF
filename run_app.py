import subprocess
import sys
import time
import os

def main():
    print("=" * 65)
    print("  ULPF — Universal Log Pre-processing Framework Launcher")
    print("=" * 65)
    print("[*] Starting FastAPI Backend on http://127.0.0.1:8000 ...")
    backend_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "8000"]
    )
    time.sleep(2)

    print("[*] Starting Streamlit Dashboard on http://localhost:8501 ...")
    frontend_proc = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", "frontend/app.py", "--server.port", "8501"]
    )

    print("[+] Both services running! Press Ctrl+C to terminate.")
    try:
        backend_proc.wait()
        frontend_proc.wait()
    except KeyboardInterrupt:
        print("\n[*] Shutting down ULPF services...")
        backend_proc.terminate()
        frontend_proc.terminate()
        print("[+] Goodbye.")

if __name__ == "__main__":
    main()
