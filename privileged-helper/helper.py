#!/usr/bin/python3 -I
"""Entry point installed as /usr/lib/wifi-center/wifi-center-helper (root-owned, started by the system bus)."""
import sys

# Isolated mode (-I) ignores PYTHONPATH and the user's site-packages: only root-owned code is importable.
sys.path.insert(0, "/usr/lib/wifi-center/lib")

from wifi_center.privileged.service import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
