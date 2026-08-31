"""Permite ejecutar ``python -m safewebheaders``."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
