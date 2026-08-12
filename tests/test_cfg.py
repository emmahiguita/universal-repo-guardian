import tempfile
import unittest
from pathlib import Path

from nano_repo_guardian.cfg import build_cfg


class Tests(unittest.TestCase):
    def test_cfg(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.py"
            p.write_text("def f(x):\n    if x:\n        return 1\n    return 0\n", encoding="utf-8")
            self.assertGreater(len(build_cfg(p)["nodes"]), 0)


if __name__ == "__main__":
    unittest.main()
