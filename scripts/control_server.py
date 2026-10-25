#!/usr/bin/env python3
"""Start the local control room: python scripts/control_server.py  ->  http://127.0.0.1:8765"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.control.server import main  # noqa: E402

if __name__ == "__main__":
    main()
