import subprocess
import sys
import time
import os

# numpy's BLAS: one thread per process (backend/services/ml/__init__.py says why); both children inherit it
for _name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ.setdefault(_name, "1")

def main():
    print("=" * 65)
    print("  TRACELOG — Universal Log Pre-processing Framework")
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
        print("\n[*] Shutting down TRACELOG...")
        backend_proc.terminate()
        frontend_proc.terminate()
        print("[+] Goodbye.")

if __name__ == "__main__":
    main()
