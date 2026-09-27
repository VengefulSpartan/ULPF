import sys
from pathlib import Path

# Add repository root to Python path
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import runpy
runpy.run_path(str(ROOT / "frontend" / "app.py"), run_name="__main__")
