"""Helpers de sistema de archivos: raíz segura, iteración, lectura y detección de texto."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from nano_repo_guardian.constants import BUILD_NAMES, SKIP_DIRS, TEXT_EXTS


def safe_root(root: str | Path | None = None) -> Path:
    raw = root or os.environ.get("NANO_REPO_ROOT") or os.getcwd()
    p = Path(raw).expanduser().resolve()
    if not p.exists() or not p.is_dir():
        raise ValueError(f"Invalid repository root: {p}")
    return p


def iter_files(root: Path, only: set[str] | None = None) -> Iterable[Path]:
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        rel = str(p.relative_to(root))
        if only is not None and rel not in only:
            continue
        yield p


def read_text(path: Path, max_bytes: int = 3_000_000) -> str:
    try:
        if path.stat().st_size > max_bytes:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def is_text_candidate(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTS or path.name in BUILD_NAMES
