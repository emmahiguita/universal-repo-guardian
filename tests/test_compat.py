import tempfile
import unittest
from pathlib import Path

from nano_repo_guardian.analysis import build_compatibility_matrix


class Tests(unittest.TestCase):
    def test_gradle(self):
        with tempfile.TemporaryDirectory() as td:
            r = Path(td)
            (r / "gradle-wrapper.properties").write_text("distributionUrl=xgradle-8.7-bin.zip", encoding="utf-8")
            self.assertEqual(build_compatibility_matrix(r)["gradle_wrapper"]["distribution"], "8.7")


if __name__ == "__main__":
    unittest.main()
