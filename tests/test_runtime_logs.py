import unittest

from guardian_runtime.logs import analyze


class Tests(unittest.TestCase):
    def test_cluster(self):
        out = analyze("E linker: dlopen failed x\nE linker: dlopen failed x\n")
        self.assertEqual(out["groups"][0]["count"], 2)


if __name__ == "__main__":
    unittest.main()
