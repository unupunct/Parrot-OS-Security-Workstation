"""Development entry point: `python main.py`."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from wifi_center.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
