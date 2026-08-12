import tempfile
import unittest
from pathlib import Path

from guardian_compat.local_matrix import extract


class Tests(unittest.TestCase):
    def test_gradle(self):
        with tempfile.TemporaryDirectory() as td:
            r = Path(td)
            (r / "gradle-wrapper.properties").write_text("distributionUrl=xgradle-8.7-bin.zip", encoding="utf-8")
            self.assertEqual(extract(r)["gradle"]["version"], "8.7")


if __name__ == "__main__":
    unittest.main()
