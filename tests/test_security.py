import tempfile
import unittest
from pathlib import Path

from nano_repo_guardian.scanners import entropy_scan


class Tests(unittest.TestCase):
    def test_entropy(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.py"
            p.write_text('tok = "K7h2Q9xR4tZ8mN3wP6vB1cD5fG0jL2sH"\n', encoding="utf-8")
            self.assertTrue(any(x["category"] == "high_entropy_secret_candidate" for x in entropy_scan(p)))


if __name__ == "__main__":
    unittest.main()
