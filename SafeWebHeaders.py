#!/usr/bin/env python3
"""Fachada compatible para ejecutar SafeWebHeaders como un único script.

El código mantenible vive en el paquete ``safewebheaders/``. Esta fachada se
conserva para quienes aún usan ``python safewebheaders.py`` o cargan el archivo
directamente mediante ``importlib``.
"""

from __future__ import annotations

import importlib.util as _importlib_util
import sys as _sys
from pathlib import Path as _Path
from types import ModuleType as _ModuleType


def _load_package() -> _ModuleType:
    # Algunas integraciones históricas cargan este archivo con el nombre exacto
    # ``safewebheaders``. En ese caso un import normal se resolvería a esta misma
    # fachada; se carga el paquete bajo un alias privado para evitar la colisión.
    if __name__ == "safewebheaders" and not hasattr(_sys.modules[__name__], "__path__"):
        alias = "_safewebheaders_package"
        existing = _sys.modules.get(alias)
        if existing is not None:
            return existing
        package_dir = _Path(__file__).resolve().with_name("safewebheaders")
        spec = _importlib_util.spec_from_file_location(
            alias,
            package_dir / "__init__.py",
            submodule_search_locations=[str(package_dir)],
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("No se pudo cargar el paquete SafeWebHeaders.")
        module = _importlib_util.module_from_spec(spec)
        _sys.modules[alias] = module
        spec.loader.exec_module(module)
        return module

    import safewebheaders as package

    return package


_PACKAGE = _load_package()
for _name in dir(_PACKAGE):
    if not _name.startswith("_"):
        globals()[_name] = getattr(_PACKAGE, _name)

__all__ = [name for name in globals() if not name.startswith("_")]


if __name__ == "__main__":
    raise SystemExit(_PACKAGE.main())
