import tempfile
import unittest
from pathlib import Path

from guardian_cfg.ownership import scan
from guardian_cfg.python_cfg import build_cfg


class Tests(unittest.TestCase):
    def test_cfg(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.py"
            p.write_text("def f(x):\n    if x:\n        return 1\n    return 0\n", encoding="utf-8")
            self.assertGreater(len(build_cfg(p)["nodes"]), 0)

    def test_owner(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.c"
            p.write_text("void f(){malloc(1);}", encoding="utf-8")
            self.assertTrue(scan(p))


if __name__ == "__main__":
    unittest.main()
