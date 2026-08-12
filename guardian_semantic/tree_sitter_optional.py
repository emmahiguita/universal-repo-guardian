from __future__ import annotations

from pathlib import Path


def available() -> bool:
    try:
        import tree_sitter  # noqa
        return True
    except Exception:
        return False

def analyze(path: Path, language: str):
    """
    Safe optional integration point.
    This package deliberately does not auto-download grammars.
    Return UNVERIFIED until a grammar is explicitly installed/configured.
    """
    if not available():
        return {"status":"UNVERIFIED","reason":"tree_sitter package not installed"}
    return {"status":"UNVERIFIED","reason":f"grammar for {language} must be configured explicitly"}
