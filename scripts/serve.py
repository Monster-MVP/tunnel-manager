import os
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "apps/backend"))
os.environ.setdefault("PYTHONPYCACHEPREFIX", str(root / "var/cache/pycache"))
from app.bootstrap import main

if len(sys.argv) == 1:
    sys.argv += ["--data-dir", str(root / "var/data"), "--runtime-dir", str(root / ".run"),
                 "--web-dir", str(root / "var/build/web")]
main()
