import tempfile
import unittest
from pathlib import Path

from guardian_semantic.python_ast import analyze
from guardian_semantic.registry import adapter_for


class Tests(unittest.TestCase):
    def test_python_ast(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.py"
            p.write_text("def a():\n    b()\n\ndef b():\n    return 1\n", encoding="utf-8")
            out = analyze(p)
            self.assertEqual(out["status"], "OK")
            self.assertTrue(any(x["name"] == "a" for x in out["symbols"]))

    def test_registry(self):
        self.assertEqual(adapter_for(Path("x.kt")).language, "kotlin")


if __name__ == "__main__":
    unittest.main()
