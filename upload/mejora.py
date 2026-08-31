#!/usr/bin/env python3
"""Alias histórico ejecutable desde el directorio ``upload``."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from safewebheaders import *
from safewebheaders import main

if __name__ == "__main__":
    raise SystemExit(main())
