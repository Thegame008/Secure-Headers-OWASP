#!/usr/bin/env python3
"""Construye un paquete de entrega limpio y un ZIP determinista."""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOP_LEVEL_FILES = (
    ".gitignore",
    "CONTRIBUTING.md",
    "MANIFEST.in",
    "README.md",
    "SECURITY.md",
    "mejora.py",
    "pyproject.toml",
    "requirements.txt",
    "safewebheaders.py",
    "urls.example.txt",
    "uv.lock",
)
SOURCE_DIRECTORIES = ("safewebheaders", "tests")
FIXED_ZIP_TIME = (2026, 1, 1, 0, 0, 0)


def project_version() -> str:
    source = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', source, re.MULTILINE)
    if match is None:
        raise ValueError("No se encontró project.version en pyproject.toml")
    return match.group(1)


def ignored(path: str, _names: list[str]) -> set[str]:
    directory = Path(path)
    return {
        child.name
        for child in directory.iterdir()
        if child.name == "__pycache__" or child.suffix in {".pyc", ".pyo"}
    }


def digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def write_zip(source: Path, destination: Path) -> None:
    with zipfile.ZipFile(
        destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for path in sorted(item for item in source.rglob("*") if item.is_file()):
            relative = Path(source.name) / path.relative_to(source)
            info = zipfile.ZipInfo(relative.as_posix(), FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            # Conserva únicamente permisos POSIX reproducibles; no propaga
            # owner/group, timestamps ni bits especiales del entorno de build.
            permissions = path.stat().st_mode & 0o777
            info.external_attr = (0o100000 | permissions) << 16
            archive.writestr(info, path.read_bytes())


def build_release(output_root: Path, dist_dir: Path) -> tuple[Path, Path]:
    version = project_version()
    release_dir = output_root / f"SafeWebHeaders-{version}"
    zip_path = output_root / f"SafeWebHeaders-{version}.zip"
    if release_dir.exists() or zip_path.exists():
        raise FileExistsError(
            f"La entrega ya existe: {release_dir} o {zip_path}. Muévela antes de repetir."
        )
    if not dist_dir.is_dir():
        raise FileNotFoundError(
            f"No existe el directorio de distribuciones: {dist_dir}"
        )

    release_dir.mkdir(parents=True)
    version_files = (
        f"CHANGELOG-{version}.md",
        f"VALIDACION-{version}.md",
    )
    for relative in (*TOP_LEVEL_FILES, *version_files):
        shutil.copy2(ROOT / relative, release_dir / relative)
    for directory in SOURCE_DIRECTORIES:
        shutil.copytree(ROOT / directory, release_dir / directory, ignore=ignored)
    (release_dir / "upload").mkdir()
    shutil.copy2(ROOT / "upload" / "mejora.py", release_dir / "upload" / "mejora.py")
    (release_dir / ".github" / "workflows").mkdir(parents=True)
    shutil.copy2(
        ROOT / ".github" / "workflows" / "quality.yml",
        release_dir / ".github" / "workflows" / "quality.yml",
    )
    (release_dir / "tools").mkdir()
    shutil.copy2(__file__, release_dir / "tools" / Path(__file__).name)
    shutil.copytree(dist_dir, release_dir / "dist", ignore=ignored)

    checksums = [
        f"{digest(path)}  {path.relative_to(release_dir).as_posix()}"
        for path in sorted(item for item in release_dir.rglob("*") if item.is_file())
    ]
    (release_dir / "SHA256SUMS.txt").write_text(
        "\n".join(checksums) + "\n", encoding="utf-8"
    )
    write_zip(release_dir, zip_path)
    return release_dir, zip_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=ROOT / "release")
    parser.add_argument("--dist-dir", type=Path, default=ROOT / "dist-v840-final")
    args = parser.parse_args()
    release_dir, zip_path = build_release(
        args.output_root.resolve(), args.dist_dir.resolve()
    )
    print(release_dir)
    print(zip_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
